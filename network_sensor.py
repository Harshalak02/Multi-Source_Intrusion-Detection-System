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
    EVENT_REPLAY_DETECTED
)

from config import (
    NETWORK_SENSOR_PORT, 
    PORT_SCAN_THRESHOLD, 
    CONNECTION_RATE_THRESHOLD,
    TIME_WINDOW, 
    REPLAY_WINDOW
)

class NetworkSensor:
    def __init__(self, event_queue: queue.Queue, anomaly_detector=None):
        self.event_queue = event_queue        # Shared queue with Correlation Engine
        self.anomaly_detector = anomaly_detector
        self.running = False
        self.port_scan_tracker = {}           # { src_ip: [(timestamp, port), ...] }
        self.connection_rate_tracker = {}     # { src_ip: [timestamp, ...] }
        self.replay_tracker = {}              # { hash_str: timestamp }
        self.disabled = False                 # For sensor failure simulation

    def start(self):
        self.running = True
        t = threading.Thread(target=self._listen, daemon=True)
        t.start()

    def stop(self):
        self.running = False

    def disable(self):
        """Used in sensor failure simulation scenario."""
        self.disabled = True

    def enable(self):
        self.disabled = False

    def _listen(self):
        """Listen for incoming simulated flow data on a TCP socket."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", NETWORK_SENSOR_PORT))
        server.listen(50)
        server.settimeout(1.0)
        while self.running:
            try:
                conn, addr = server.accept()
                threading.Thread(target=self._handle_connection, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
        server.close()

    def _handle_connection(self, conn):
        """Process one incoming simulated flow."""
        try:
            data = conn.recv(4096).decode("utf-8")
        except Exception:
            data = None
        finally:
            conn.close()
            
        if not data or self.disabled:
            return
            
        try:
            flow = json.loads(data)          # flow has: src_ip, dst_ip, src_port, dst_port, protocol
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

        # Record for anomaly detection if instance exists
        if self.anomaly_detector:
            if dst_port:
                self.anomaly_detector.record_port_access(dst_port)
            self.anomaly_detector.record_connection()

        # Always emit a raw connection attempt event
        evt = make_event(
            source="network", 
            event_type=EVENT_CONNECTION_ATTEMPT,
            description=f"Connection from {src_ip} to port {dst_port}",
            src_ip=src_ip, 
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol
        )
        self._emit(evt)

        # Apply rule-based checks
        self._check_port_scan(src_ip, dst_port, now)
        self._check_connection_rate(src_ip, now)
        self._check_replay(flow, now, src_ip, dst_ip, src_port, dst_port, protocol)

    def _check_port_scan(self, src_ip, dst_port, now):
        if src_ip not in self.port_scan_tracker:
            self.port_scan_tracker[src_ip] = []
            
        # Add new entry
        self.port_scan_tracker[src_ip].append((now, dst_port))
        
        # Prune older than TIME_WINDOW
        self.port_scan_tracker[src_ip] = [
            (t, p) for (t, p) in self.port_scan_tracker[src_ip] 
            if now - t <= TIME_WINDOW
        ]
        
        unique_ports = {p for (t, p) in self.port_scan_tracker[src_ip]}
        
        if len(unique_ports) > PORT_SCAN_THRESHOLD:
            evt = make_event(
                source="network",
                event_type=EVENT_PORT_SCAN,
                description=f"Port scan detected from {src_ip} targeting {len(unique_ports)} distinct ports",
                src_ip=src_ip,
                extra={"unique_ports_count": len(unique_ports), "ports": list(unique_ports)}
            )
            self._emit(evt)
            # Clear tracker after emitting to avoid rapid duplicate firing, 
            # or rely on Alert Manager's deduplication. We clear for safety.
            self.port_scan_tracker[src_ip] = []
            
    def _check_connection_rate(self, src_ip, now):
        if src_ip not in self.connection_rate_tracker:
            self.connection_rate_tracker[src_ip] = []
            
        self.connection_rate_tracker[src_ip].append(now)
        
        self.connection_rate_tracker[src_ip] = [
            t for t in self.connection_rate_tracker[src_ip] 
            if now - t <= TIME_WINDOW
        ]
        
        if len(self.connection_rate_tracker[src_ip]) > CONNECTION_RATE_THRESHOLD:
            evt = make_event(
                source="network",
                event_type=EVENT_HIGH_TRAFFIC,
                description=f"High connection rate detected from {src_ip}",
                src_ip=src_ip,
                extra={"connection_count": len(self.connection_rate_tracker[src_ip])}
            )
            self._emit(evt)
            self.connection_rate_tracker[src_ip] = []

    def _check_replay(self, flow, now, src_ip, dst_ip, src_port, dst_port, protocol):
        # Create a simple hash of the required connection parameters.
        # Fallback to empty string for payload if not present.
        payload = flow.get("payload", "")
        hash_input = f"{src_ip}:{dst_ip}:{dst_port}:{protocol}:{payload}"
        hash_str = hashlib.md5(hash_input.encode("utf-8")).hexdigest()
        
        # Prune old hashes
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
                    extra={"flow_hash": hash_str}
                )
                self._emit(evt)
                # Remove so it doesn't trigger again constantly until another duplicate appears
                del self.replay_tracker[hash_str]
        else:
            self.replay_tracker[hash_str] = now

    def _emit(self, event):
        self.event_queue.put(event)
        # Also log to file
        with open("logs/events.json", "a") as f:
            f.write(json.dumps(event) + "\n")
