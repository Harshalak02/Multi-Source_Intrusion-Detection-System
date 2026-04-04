"""
Non-interactive validation script for the IDS.

Checks:
1) No false Critical when unrelated network and host attacker IPs are mixed in time.
2) Critical is possible when same attacker IP produces corroborated multi-source evidence.
"""

import json
import os
import queue
import time

from alert_manager import AlertManager
from anomaly_detector import AnomalyDetector
from correlation_engine import CorrelationEngine
from host_sensor import HostSensor
from network_sensor import NetworkSensor
from attack_simulator import send_to_network_sensor, send_to_host_sensor
from metrics import MetricsCollector


def _reset_logs():
    os.makedirs("logs", exist_ok=True)
    open("logs/events.json", "w").close()
    open("logs/alerts.json", "w").close()


def _load_alerts():
    alerts = []
    if not os.path.exists("logs/alerts.json"):
        return alerts
    with open("logs/alerts.json", "r") as f:
        for line in f:
            line = line.strip()
            if line:
                alerts.append(json.loads(line))
    return alerts


def _send_port_scan(src_ip, dst_ip="127.0.0.1", start_port=2000, count=16, delay=0.03):
    for i in range(count):
        flow = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": 50000,
            "dst_port": start_port + i,
            "protocol": "TCP",
        }
        send_to_network_sensor(flow)
        time.sleep(delay)


def _send_bruteforce(src_ip, username="admin", attempts=9, delay=0.08):
    for _ in range(attempts):
        log = {
            "log_type": "failed_login",
            "username": username,
            "src_ip": src_ip,
            "timestamp": time.time(),
        }
        send_to_host_sensor(log)
        time.sleep(delay)


def run_validation():
    _reset_logs()

    event_queue = queue.Queue()
    metrics = MetricsCollector()
    anomaly = AnomalyDetector(event_queue)
    net = NetworkSensor(event_queue, anomaly)
    host = HostSensor(event_queue, anomaly)
    alert_mgr = AlertManager(metrics)
    corr = CorrelationEngine(event_queue, alert_mgr)

    anomaly.start()
    net.start()
    host.start()
    corr.start()
    time.sleep(0.8)

    # Test 1: different IPs should not create false Critical by cross-source mixing
    _send_port_scan("192.168.1.101")
    _send_bruteforce("192.168.1.100", username="victim")
    time.sleep(2.0)

    alerts_after_test1 = _load_alerts()
    t1_critical = [a for a in alerts_after_test1 if a.get("severity") == "Critical"]
    print(f"[TEST1] Alerts={len(alerts_after_test1)}, Critical={len(t1_critical)}")

    # Test 2: same IP multi-source behavior can produce Critical
    _send_port_scan("192.168.50.50")
    _send_bruteforce("192.168.50.50", username="root")
    time.sleep(2.0)

    alerts_after_test2 = _load_alerts()
    t2_critical = [a for a in alerts_after_test2 if a.get("severity") == "Critical"]
    print(f"[TEST2] Alerts={len(alerts_after_test2)}, Critical={len(t2_critical)}")

    corr.stop()
    net.stop()
    host.stop()
    anomaly.stop()

    # Pass criteria
    if len(t1_critical) > 0:
        raise SystemExit("FAIL: False Critical detected for unrelated IP activity")
    if len(t2_critical) == 0:
        raise SystemExit("FAIL: No Critical detected for same-IP multi-source attack")

    print("PASS: Validation checks succeeded.")


if __name__ == "__main__":
    run_validation()
