import socket
import threading
import json
import queue
import time

from schema import (
    make_event,
    EVENT_FAILED_LOGIN,
    EVENT_SUCCESSFUL_LOGIN,
    EVENT_SUSPICIOUS_PROCESS,
    EVENT_PRIVILEGE_ESCALATION,
)

from config import (
    HOST_SENSOR_PORT,
    BRUTE_FORCE_THRESHOLD,
    TIME_WINDOW,
    SUSPICIOUS_PROCESSES,
)


class HostSensor:
    def __init__(self, event_queue: queue.Queue, anomaly_detector=None):
        self.event_queue = event_queue
        self.anomaly_detector = anomaly_detector
        self.running = False
        self.failed_login_tracker = {}
        self.successful_login_tracker = {}
        self.disabled = False
        self.server = None

    def start(self):
        if self.running:
            return

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(("127.0.0.1", HOST_SENSOR_PORT))
            server.listen(50)
            server.settimeout(1.0)
        except OSError as exc:
            server.close()
            raise RuntimeError(
                f"Host Sensor failed to bind 127.0.0.1:{HOST_SENSOR_PORT}. "
                f"Address may already be in use. ({exc})"
            ) from exc

        self.server = server
        self.running = True
        threading.Thread(target=self._listen, daemon=True).start()

    def stop(self):
        self.running = False
        if self.server:
            try:
                self.server.close()
            except OSError:
                pass
            self.server = None

    def disable(self):
        self.disabled = True

    def enable(self):
        self.disabled = False

    def _listen(self):
        while self.running and self.server:
            try:
                conn, _ = self.server.accept()
                threading.Thread(target=self._handle, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle(self, conn):
        try:
            data = conn.recv(4096).decode("utf-8")
        except Exception:
            data = None
        finally:
            conn.close()

        if not data or self.disabled:
            return

        try:
            log_entry = json.loads(data)
            self._process_log(log_entry)
        except json.JSONDecodeError:
            pass

    def _process_log(self, log_entry):
        now = time.time()
        log_type = log_entry.get("log_type")

        if log_type == "failed_login":
            if self.anomaly_detector:
                self.anomaly_detector.record_failed_login()
            self._check_brute_force(log_entry, now)
        elif log_type == "process_creation":
            self._check_suspicious_process(log_entry, now)
        elif log_type == "successful_login":
            self._check_privilege_escalation(log_entry, now)

    def _check_brute_force(self, log_entry, now):
        username = log_entry.get("username", "unknown")
        src_ip = log_entry.get("src_ip", "127.0.0.1")

        evt = make_event(
            source="host",
            event_type=EVENT_FAILED_LOGIN,
            description=f"Failed login for {username}",
            username=username,
            src_ip=src_ip,
            extra={"src_ip": src_ip},
        )
        self._emit(evt)

        if username not in self.failed_login_tracker:
            self.failed_login_tracker[username] = []

        self.failed_login_tracker[username].append((now, src_ip))

        self.failed_login_tracker[username] = [
            (t, ip) for (t, ip) in self.failed_login_tracker[username] if now - t <= TIME_WINDOW
        ]

        if len(self.failed_login_tracker[username]) > BRUTE_FORCE_THRESHOLD:
            evt_bf = make_event(
                source="host",
                event_type="brute_force_burst",
                description=f"Brute-force burst detected for {username}",
                username=username,
                src_ip=src_ip,
                extra={"failed_attempts": len(self.failed_login_tracker[username])},
            )
            self._emit(evt_bf)
            self.failed_login_tracker[username] = []

    def _check_suspicious_process(self, log_entry, now):
        process_name = log_entry.get("process_name", "")
        username = log_entry.get("username", "unknown")

        if process_name in SUSPICIOUS_PROCESSES:
            evt = make_event(
                source="host",
                event_type=EVENT_SUSPICIOUS_PROCESS,
                description=f"Suspicious process '{process_name}' executed by {username}",
                username=username,
                process_name=process_name,
            )
            self._emit(evt)

    def _check_privilege_escalation(self, log_entry, now):
        username = log_entry.get("username", "unknown")
        src_ip = log_entry.get("src_ip", "127.0.0.1")

        evt_success = make_event(
            source="host",
            event_type=EVENT_SUCCESSFUL_LOGIN,
            description=f"Successful login for {username}",
            username=username,
            src_ip=src_ip,
        )
        self._emit(evt_success)

        recent_failures = self.failed_login_tracker.get(username, [])
        recent_failures = [(t, ip) for (t, ip) in recent_failures if now - t <= TIME_WINDOW]

        failed_ips = {ip for (t, ip) in recent_failures}

        if src_ip in failed_ips:
            evt_priv = make_event(
                source="host",
                event_type=EVENT_PRIVILEGE_ESCALATION,
                description=f"Privilege escalation/Successful brute-force detected for {username} from {src_ip}",
                username=username,
                src_ip=src_ip,
            )
            self._emit(evt_priv)

    def _emit(self, event):
        self.event_queue.put(event)
        with open("logs/events.json", "a") as f:
            f.write(json.dumps(event) + "\n")
