import time
import uuid
import json

from config import ALERT_COOLDOWN, EVENT_WEIGHTS

class AlertManager:
    def __init__(self, metrics=None):
        self.metrics = metrics
        self.last_alert_time = {}   # { severity: last_raised_timestamp }
        self.cooldown = ALERT_COOLDOWN    # from config.py, default: 10 seconds

    def raise_alert(self, severity, total_score, window_events):
        now = time.time()
        last = self.last_alert_time.get(severity, 0)
        
        if now - last < self.cooldown:
            return   # Suppressed — cooldown active for this severity level

        self.last_alert_time[severity] = now
        alert = self._build_alert(severity, total_score, window_events, now)
        self._log_alert(alert)
        self._print_alert(alert)
        return alert

    def _build_alert(self, severity, total_score, window_events, now):
        network_events = [e for e in window_events if e["source"] == "network"]
        host_events    = [e for e in window_events if e["source"] == "host"]
        
        network_score = sum(EVENT_WEIGHTS.get(e["event_type"], 0) for e in network_events)
        host_score    = sum(EVENT_WEIGHTS.get(e["event_type"], 0) for e in host_events)
        
        event_ids = [e["event_id"] for e in window_events]
        
        description = f"Multi-source incident corroborated" if len(network_events) > 0 and len(host_events) > 0 else f"Single-source threshold exceeded"
        
        return {
            "alert_id": str(uuid.uuid4()),
            "timestamp": now,
            "severity": severity,
            "total_score": float(total_score),
            "network_score": float(network_score),
            "host_score": float(host_score),
            "contributing_events": event_ids,
            "description": f"{description} | Net Events: {len(network_events)}, Host Events: {len(host_events)}"
        }

    def _log_alert(self, alert):
        with open("logs/alerts.json", "a") as f:
            f.write(json.dumps(alert) + "\n")

    def _print_alert(self, alert):
        color_map = {
            "Info":     "\033[37m",    # White
            "Low":      "\033[32m",    # Green
            "Medium":   "\033[33m",    # Yellow
            "High":     "\033[91m",    # Light Red
            "Critical": "\033[31m",    # Red
        }
        reset = "\033[0m"
        color = color_map.get(alert["severity"], "")
        print(f"{color}[ALERT][{alert['severity']}] Score={alert['total_score']:.2f} | {alert['description']}{reset}")
