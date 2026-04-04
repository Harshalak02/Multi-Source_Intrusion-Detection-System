import socket
import threading
import json
import queue
import time
import hashlib

from schema import (
    make_event,
    EVENT_PORT_SCAN,
    EVENT_CONNECTION_ATTEMPT,
    EVENT_HIGH_TRAFFIC,
    EVENT_REPLAY_DETECTED,
)

from config import (
    NETWORK_SENSOR_PORT,
    PORT_SCAN_THRESHOLD,
    CONNECTION_RATE_THRESHOLD,
    TIME_WINDOW,
    REPLAY_WINDOW,
    PORT_SCAN_ALERT_COOLDOWN,
)


class NetworkSensor:
    def __init__(self, event_queue: queue.Queue, anomaly_detector=None):
        self.event_queue = event_queue
        self.anomaly_detector = anomaly_detector
        self.running = False
        self.port_scan_tracker = {}
        self.port_scan_last_alert = {}
        self.connection_rate_tracker = {}
        self.replay_tracker = {}
        self.disabled = False
        self.server = None

    def start(self):
        if self.running:
            return

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(("127.0.0.1", NETWORK_SENSOR_PORT))
            server.listen(50)
            server.settimeout(1.0)
        except OSError as exc:
            server.close()
            raise RuntimeError(
                f"Network Sensor failed to bind 127.0.0.1:{NETWORK_SENSOR_PORT}. "
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
                threading.Thread(target=self._handle_connection, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle_connection(self, conn):
        try:
            data = conn.recv(4096).decode("utf-8")
        except Exception:
            data = None
        finally:
            conn.close()

        if not data or self.disabled:
            return

        try:
            flow = json.loads(data)
            self._process_flow(flow)
        except json.JSONDecodeError:
            pass

    def _process_flow(self, flow):
        now = time.time()
        src_ip = flow.get("src_ip", "127.0.0.1")
        dst_ip = flow.get("dst_ip")
        src_port = flow.get("src_port")
        dst_port = flow.get("dst_port", 0)
        protocol = flow.get("protocol")

        if self.anomaly_detector:
            if dst_port:
                self.anomaly_detector.record_port_access(dst_port)
            self.anomaly_detector.record_connection()

        evt = make_event(
            source="network",
            event_type=EVENT_CONNECTION_ATTEMPT,
            description=f"Connection from {src_ip} to port {dst_port}",
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
        )
        self._emit(evt)

        self._check_port_scan(src_ip, dst_port, now)
        self._check_connection_rate(src_ip, now)
        self._check_replay(flow, now, src_ip, dst_ip, src_port, dst_port, protocol)

    def _check_port_scan(self, src_ip, dst_port, now):
        if src_ip not in self.port_scan_tracker:
            self.port_scan_tracker[src_ip] = []

        self.port_scan_tracker[src_ip].append((now, dst_port))

        self.port_scan_tracker[src_ip] = [
            (t, p) for (t, p) in self.port_scan_tracker[src_ip] if now - t <= TIME_WINDOW
        ]

        unique_ports = {p for (t, p) in self.port_scan_tracker[src_ip]}
        last_alert = self.port_scan_last_alert.get(src_ip, 0)
        cooldown_active = (now - last_alert) < PORT_SCAN_ALERT_COOLDOWN

        if len(unique_ports) > PORT_SCAN_THRESHOLD and not cooldown_active:
            evt = make_event(
                source="network",
                event_type=EVENT_PORT_SCAN,
                description=f"Port scan detected from {src_ip} targeting {len(unique_ports)} distinct ports",
                src_ip=src_ip,
                extra={"unique_ports_count": len(unique_ports), "ports": list(unique_ports)},
            )
            self._emit(evt)
            self.port_scan_last_alert[src_ip] = now

    def _check_connection_rate(self, src_ip, now):
        if src_ip not in self.connection_rate_tracker:
            self.connection_rate_tracker[src_ip] = []

        self.connection_rate_tracker[src_ip].append(now)

        self.connection_rate_tracker[src_ip] = [
            t for t in self.connection_rate_tracker[src_ip] if now - t <= TIME_WINDOW
        ]

        if len(self.connection_rate_tracker[src_ip]) > CONNECTION_RATE_THRESHOLD:
            evt = make_event(
                source="network",
                event_type=EVENT_HIGH_TRAFFIC,
                description=f"High connection rate detected from {src_ip}",
                src_ip=src_ip,
                extra={"connection_count": len(self.connection_rate_tracker[src_ip])},
            )
            self._emit(evt)
            self.connection_rate_tracker[src_ip] = []

    def _check_replay(self, flow, now, src_ip, dst_ip, src_port, dst_port, protocol):
        payload = flow.get("payload", "")
        hash_input = f"{src_ip}:{dst_ip}:{dst_port}:{protocol}:{payload}"
        hash_str = hashlib.md5(hash_input.encode("utf-8")).hexdigest()

        keys_to_delete = [h for h, t in self.replay_tracker.items() if now - t > REPLAY_WINDOW]
        for h in keys_to_delete:
            del self.replay_tracker[h]

        if hash_str in self.replay_tracker:
            if now - self.replay_tracker[hash_str] <= REPLAY_WINDOW:
                evt = make_event(
                    source="network",
                    event_type=EVENT_REPLAY_DETECTED,
                    description=f"Replay attack detected from {src_ip} to {dst_ip}:{dst_port}",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    extra={"flow_hash": hash_str},
                )
                self._emit(evt)
                del self.replay_tracker[hash_str]
        else:
            self.replay_tracker[hash_str] = now

    def _emit(self, event):
        self.event_queue.put(event)
        with open("logs/events.json", "a") as f:
            f.write(json.dumps(event) + "\n")
