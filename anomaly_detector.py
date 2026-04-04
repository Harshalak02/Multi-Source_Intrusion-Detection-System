import math
import statistics
import time
import threading
import queue
from schema import make_event
from config import BASELINE_WINDOW_SIZE, ANOMALY_Z_THRESHOLD, ANOMALY_CHECK_INTERVAL

class AnomalyDetector:
    def __init__(self, event_queue: queue.Queue):
        self.event_queue = event_queue
        self.baselines = {
            "failed_login_rate":  [],   # Rolling window of measurements
            "unique_ports_rate":  [],
            "connection_rate":    [],
        }
        self.running = False
        # Counters reset every ANOMALY_CHECK_INTERVAL
        self.current_counts = {
            "failed_login_rate": 0,
            "unique_ports_rate": set(),
            "connection_rate":   0,
        }

    def start(self):
        self.running = True
        threading.Thread(target=self._run, daemon=True).start()

    def stop(self):
        self.running = False

    def record_failed_login(self):
        self.current_counts["failed_login_rate"] += 1

    def record_port_access(self, port):
        self.current_counts["unique_ports_rate"].add(port)

    def record_connection(self):
        self.current_counts["connection_rate"] += 1

    def _run(self):
        while self.running:
            time.sleep(ANOMALY_CHECK_INTERVAL)
            self._check_anomalies()

    def _check_anomalies(self):
        for feature_name, baseline in self.baselines.items():
            raw = self.current_counts[feature_name]
            current_val = len(raw) if isinstance(raw, set) else raw

            if len(baseline) >= 5:    # Need at least 5 data points
                mu = statistics.mean(baseline)
                try:
                    sigma = statistics.stdev(baseline)
                except statistics.StatisticsError:
                    sigma = 0.0
                epsilon = 0.0001
                z = (current_val - mu) / (sigma + epsilon)
                if abs(z) > ANOMALY_Z_THRESHOLD:
                    evt = make_event(
                        source="network" if "port" in feature_name or "connection" in feature_name else "host",
                        event_type="anomaly_detected",
                        description=f"Anomaly in {feature_name}: z={z:.2f}, current={current_val}, mean={mu:.2f}",
                        src_ip="anomaly_network" if "port" in feature_name or "connection" in feature_name else "anomaly_host",
                        extra={"feature": feature_name, "z_score": z, "current": current_val}
                    )
                    self.event_queue.put(evt)

            # Update baseline (sliding window)
            if len(baseline) >= BASELINE_WINDOW_SIZE:
                baseline.pop(0)
            baseline.append(current_val)

            # Reset counters
            if isinstance(self.current_counts[feature_name], set):
                self.current_counts[feature_name] = set()
            else:
                self.current_counts[feature_name] = 0
