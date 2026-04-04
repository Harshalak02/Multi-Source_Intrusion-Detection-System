"""Integration-style tests for manual debugging of IDS behavior.

Unlike the original placeholder script, this file now boots IDS components so scenario
functions generate real events/alerts.
"""

import json
import os
import queue
import socket
import time

import attack_simulator
import host_sensor as host_sensor_module
import network_sensor as network_sensor_module
from alert_manager import AlertManager
from anomaly_detector import AnomalyDetector
from attack_simulator import (
    scenario_brute_force,
    scenario_noise_injection,
    scenario_port_scan,
    scenario_replay_attack,
)
from correlation_engine import CorrelationEngine
from host_sensor import HostSensor
from metrics import MetricsCollector
from network_sensor import NetworkSensor


def _pick_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _configure_test_ports():
    net_port = _pick_free_port()
    host_port = _pick_free_port()
    network_sensor_module.NETWORK_SENSOR_PORT = net_port
    host_sensor_module.HOST_SENSOR_PORT = host_port
    attack_simulator.NETWORK_SENSOR_PORT = net_port
    attack_simulator.HOST_SENSOR_PORT = host_port


def _reset_logs():
    os.makedirs("logs", exist_ok=True)
    open("logs/events.json", "w").close()
    open("logs/alerts.json", "w").close()


def _read_alerts():
    out = []
    if not os.path.exists("logs/alerts.json"):
        return out
    with open("logs/alerts.json", "r") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


class TestHarness:
    def __init__(self):
        self.event_queue = queue.Queue()
        self.metrics = MetricsCollector()
        self.anomaly = AnomalyDetector(self.event_queue)
        self.net = NetworkSensor(self.event_queue, self.anomaly)
        self.host = HostSensor(self.event_queue, self.anomaly)
        self.alert_mgr = AlertManager(self.metrics)
        self.corr = CorrelationEngine(self.event_queue, self.alert_mgr)

    def start(self):
        _configure_test_ports()
        _reset_logs()
        self.anomaly.start()
        self.net.start()
        self.host.start()
        self.corr.start()
        time.sleep(0.8)

    def stop(self):
        self.corr.stop()
        self.net.stop()
        self.host.stop()
        self.anomaly.stop()


def test_cooldown_issue():
    print("\n==============================")
    print("TEST 1: Cooldown / dedup sanity")
    print("==============================")
    _reset_logs()

    scenario_port_scan()
    time.sleep(1)
    scenario_brute_force()
    time.sleep(2)

    alerts = _read_alerts()
    print(f"[RESULT] Total alerts: {len(alerts)}")
    if len(alerts) >= 2:
        print("✅ PASS: Multiple alerts observed (dedup did not suppress unrelated incidents).")
    else:
        print("❌ FAIL: Too few alerts; dedup may be over-suppressing.")


def test_wrong_correlation():
    print("\n==============================")
    print("TEST 2: Wrong Correlation (different IPs)")
    print("==============================")
    _reset_logs()

    scenario_port_scan()
    time.sleep(1)
    scenario_brute_force()
    time.sleep(2)

    alerts = _read_alerts()
    critical = [a for a in alerts if a.get("severity") == "Critical"]
    if not critical:
        print("✅ PASS: No false Critical for unrelated attacker IPs.")
    else:
        print(f"❌ FAIL: Found {len(critical)} unexpected Critical alert(s).")


def test_anomaly_issue():
    print("\n==============================")
    print("TEST 3: Anomaly / noise behavior")
    print("==============================")
    _reset_logs()

    scenario_noise_injection()
    time.sleep(3)

    alerts = _read_alerts()
    low_or_medium = [a for a in alerts if a.get("severity") in ("Low", "Medium")]
    if low_or_medium:
        print("✅ PASS: Noise produced low/medium-level alerting as expected.")
    else:
        print("⚠️ WARN: No low/medium alerts observed; check anomaly baseline warm-up.")


def test_threshold_issue():
    print("\n==============================")
    print("TEST 4: Threshold Check (single-source brute force)")
    print("==============================")
    _reset_logs()

    scenario_brute_force()
    time.sleep(2)

    alerts = _read_alerts()
    critical = [a for a in alerts if a.get("severity") == "Critical"]
    high = [a for a in alerts if a.get("severity") == "High"]

    if critical:
        print("❌ FAIL: Critical raised from single-source activity.")
    elif high:
        print("✅ PASS: High observed without Critical for single-source brute force.")
    else:
        print("⚠️ WARN: No High alert observed; thresholds may be too strict.")


def run_all_tests():
    print("\n🚀 Running All IDS Tests with live components...\n")
    harness = TestHarness()
    harness.start()
    try:
        test_cooldown_issue()
        test_wrong_correlation()
        test_anomaly_issue()
        test_threshold_issue()
        print("\n✅ Testing complete.")
    finally:
        harness.stop()


if __name__ == "__main__":
    run_all_tests()
