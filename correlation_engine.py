import queue
import threading
import time

from config import (
    TIME_WINDOW,
    EVENT_WEIGHTS,
    CRITICAL_THRESHOLD,
    HIGH_THRESHOLD,
    MEDIUM_THRESHOLD,
    LOW_THRESHOLD
)

class CorrelationEngine:
    def __init__(self, event_queue: queue.Queue, alert_manager):
        self.event_queue = event_queue
        self.alert_manager = alert_manager
        self.window_buffer = []
        self.running = False

    def start(self):
        self.running = True
        threading.Thread(target=self._run, daemon=True).start()

    def stop(self):
        self.running = False

    def _add_to_window(self, event):
        self.window_buffer.append(event)

    def _prune_window(self):
        now = time.time()
        # Keep events that occurred within the TIME_WINDOW sliding timeframe
        self.window_buffer = [
            e for e in self.window_buffer 
            if now - e["timestamp"] <= TIME_WINDOW
        ]

    def _evaluate_window(self, window_events):
        network_events = [e for e in window_events if e["source"] == "network"]
        host_events    = [e for e in window_events if e["source"] == "host"]

        network_score = sum(EVENT_WEIGHTS.get(e["event_type"], 0) for e in network_events)
        host_score    = sum(EVENT_WEIGHTS.get(e["event_type"], 0) for e in host_events)
        total_score   = network_score + host_score

        both_sources_active = len(network_events) > 0 and len(host_events) > 0
        multi_step_detected = self._check_multistep_pattern(network_events, host_events)

        if (both_sources_active and total_score >= CRITICAL_THRESHOLD) or multi_step_detected:
            severity = "Critical"
        elif total_score >= HIGH_THRESHOLD:
            severity = "High"
        elif total_score >= MEDIUM_THRESHOLD:
            severity = "Medium"
        elif total_score >= LOW_THRESHOLD:
            severity = "Low"
        else:
            severity = "Info"

        return severity, total_score, network_score, host_score

    def _check_multistep_pattern(self, network_events, host_events):
        """
        Multi-step attack: Port scan followed by brute-force login.
        If we see a port_scan event AND a failed_login/brute_force event
        for an IP that appeared in the port scan, that's a multi-step attack.
        """
        # Determine any IP address that was flagged in a port scan.
        # The Network Sensor adds the IP itself to src_ip.
        scanned_ips = {e["src_ip"] for e in network_events if e["event_type"] == "port_scan"}
        
        # Check against brute force / failed logins which may store src_ip directly 
        # or inside the "extra" dict based on our implementation.
        brute_ips = {
            e.get("extra", {}).get("src_ip", e.get("src_ip")) 
            for e in host_events 
            if e["event_type"] in ("failed_login", "brute_force_burst")
        }
        
        return bool(scanned_ips & brute_ips)   # Non-empty intersection = multi-step

    def _run(self):
        while self.running:
            try:
                # Retrieve next available event from shared Queue, timeout keeps loop active to check `running`
                event = self.event_queue.get(timeout=1.0)
                self._add_to_window(event)
                self._prune_window()
                
                severity, score, net_score, host_score = self._evaluate_window(self.window_buffer)
                
                if severity != "Info":
                    # Generate an alert via Alert Manager
                    print("\n[DEBUG] Current Window Events:")
                    for e in self.window_buffer:
                        print(f"{e['source']} | {e['event_type']} | {e.get('src_ip')} | t={e['timestamp']:.2f}")
                    self.alert_manager.raise_alert(severity, score, self.window_buffer.copy())
            except queue.Empty:
                # It's fine if the queue is empty; continue managing window passively or just loop.
                pass
