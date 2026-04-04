import queue
import time
import threading
import os

from network_sensor import NetworkSensor
from host_sensor import HostSensor
from correlation_engine import CorrelationEngine
from alert_manager import AlertManager
from anomaly_detector import AnomalyDetector
from attack_simulator import (
    scenario_brute_force, 
    scenario_port_scan,
    scenario_noise_injection, 
    scenario_replay_attack,
    scenario_sensor_failure,
    run_all_scenarios
)
from metrics import MetricsCollector

def main():
    # Ensure logs directory exists
    os.makedirs("logs", exist_ok=True)
    # Clear old log files
    open("logs/events.json", "w").close()
    open("logs/alerts.json", "w").close()

    print("[MAIN] Starting IDS components...")

    # Shared queue: all sensors push events here, correlation engine reads from it
    event_queue = queue.Queue()

    # Metrics collector (observes alerts, used for reporting)
    metrics = MetricsCollector()

    # Start anomaly detector
    anomaly_detector = AnomalyDetector(event_queue)
    anomaly_detector.start()
    print("[MAIN] Anomaly Detector started.")

    # Start network sensor
    net_sensor = NetworkSensor(event_queue, anomaly_detector)
    net_sensor.start()
    print("[MAIN] Network Sensor started on port 9001.")

    # Start host sensor
    host_sensor = HostSensor(event_queue, anomaly_detector)
    host_sensor.start()
    print("[MAIN] Host Sensor started on port 9002.")

    # Alert Manager
    alert_mgr = AlertManager(metrics)
    print("[MAIN] Alert Manager initialized.")

    # Start Correlation Engine
    corr_engine = CorrelationEngine(event_queue, alert_mgr)
    corr_engine.start()
    print("[MAIN] Correlation Engine started.")

    time.sleep(0.5)   # Allow sockets to bind and threads to start
    print("[MAIN] All components running. Starting Attack Simulator...\n")

    # ── Attack Simulator Menu ──────────────────────────────────────
    while True:
        print("\n" + "="*53)
        print("  Multi-Source IDS — Attack Simulator")
        print("="*53)
        print("  1. Brute-Force Login Attack")
        print("  2. Port Scan Attack")
        print("  3. Noise Injection")
        print("  4. Replay Attack")
        print("  5. Sensor Failure Simulation")
        print("  6. Run All Scenarios (for metrics)")
        print("  7. Generate Metrics Report")
        print("  0. Exit")
        print("="*53)

        choice = input("Enter your choice: ").strip()

        if choice == "1":
            scenario_brute_force()
        elif choice == "2":
            scenario_port_scan()
        elif choice == "3":
            scenario_noise_injection()
        elif choice == "4":
            scenario_replay_attack()
        elif choice == "5":
            scenario_sensor_failure(net_sensor, host_sensor)
        elif choice == "6":
            run_all_scenarios(net_sensor, host_sensor, metrics)
        elif choice == "7":
            metrics.print_report()
        elif choice == "0":
            print("[MAIN] Shutting down IDS...")
            corr_engine.stop()
            net_sensor.stop()
            host_sensor.stop()
            anomaly_detector.stop()
            metrics.print_report()
            break
        else:
            print("[ERROR] Invalid choice.")

if __name__ == "__main__":
    main()
