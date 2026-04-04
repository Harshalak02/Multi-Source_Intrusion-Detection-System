import queue
import threading
import time
from collections import defaultdict

from config import (
    TIME_WINDOW,
    EVENT_WEIGHTS,
    CRITICAL_THRESHOLD,
    HIGH_THRESHOLD,
    MEDIUM_THRESHOLD,
    LOW_THRESHOLD,
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
        self.window_buffer = [e for e in self.window_buffer if now - e["timestamp"] <= TIME_WINDOW]

    def _entity_key(self, event):
        """
        Correlate by attacker-like identity to avoid global event mixing.
        Priority:
        1) src_ip
        2) username (for host events without IP)
        3) coarse synthetic key by source/event_type
        """
        src_ip = event.get("src_ip")
        if src_ip:
            return f"ip:{src_ip}"

        username = event.get("username")
        if username:
            return f"user:{username}"

        return f"fallback:{event.get('source', 'unknown')}:{event.get('event_type', 'unknown')}"

    def _group_by_entity(self, events):
        grouped = defaultdict(list)
        for e in events:
            grouped[self._entity_key(e)].append(e)
        return grouped

    def _evaluate_window(self, window_events):
        network_events = [e for e in window_events if e["source"] == "network"]
        host_events = [e for e in window_events if e["source"] == "host"]

        network_score = sum(EVENT_WEIGHTS.get(e["event_type"], 0) for e in network_events)
        host_score = sum(EVENT_WEIGHTS.get(e["event_type"], 0) for e in host_events)
        total_score = network_score + host_score

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
        scanned_ips = {e["src_ip"] for e in network_events if e["event_type"] == "port_scan" and e.get("src_ip")}

        brute_ips = {
            e.get("extra", {}).get("src_ip", e.get("src_ip"))
            for e in host_events
            if e["event_type"] in ("failed_login", "brute_force_burst")
        }

        return bool(scanned_ips & brute_ips)

    def _run(self):
        while self.running:
            try:
                event = self.event_queue.get(timeout=1.0)
                self._add_to_window(event)
                self._prune_window()

                groups = self._group_by_entity(self.window_buffer)
                for entity, entity_events in groups.items():
                    severity, score, _, _ = self._evaluate_window(entity_events)

                    if severity != "Info":
                        print(f"\n[DEBUG] Entity Group: {entity}")
                        for e in entity_events:
                            print(f"{e['source']} | {e['event_type']} | {e.get('src_ip')} | t={e['timestamp']:.2f}")
                        self.alert_manager.raise_alert(severity, score, entity_events.copy())
            except queue.Empty:
                pass
