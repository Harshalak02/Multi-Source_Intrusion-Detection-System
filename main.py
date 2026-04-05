import queue
import time
import os

from network_sensor import NetworkSensor
from host_sensor import HostSensor
from correlation_engine import CorrelationEngine
from alert_manager import AlertManager
from anomaly_detector import AnomalyDetector
from attack_simulator import (
    scenario_benign_baseline,
    scenario_brute_force,
    scenario_port_scan,
    scenario_noise_injection,
    scenario_replay_attack,
    scenario_sensor_failure,
    scenario_multi_source_same_ip,
    run_all_scenarios,
)
from metrics import MetricsCollector


def main():
    os.makedirs("logs", exist_ok=True)
    open("logs/events.json", "w").close()
    open("logs/alerts.json", "w").close()

    print("[MAIN] Starting IDS components...")

    event_queue = queue.Queue()
    metrics = MetricsCollector()

    anomaly_detector = AnomalyDetector(event_queue)
    anomaly_detector.start()
    print("[MAIN] Anomaly Detector started.")

    net_sensor = NetworkSensor(event_queue, anomaly_detector)
    host_sensor = HostSensor(event_queue, anomaly_detector)

    try:
        net_sensor.start()
        print("[MAIN] Network Sensor started on port 9001.")

        host_sensor.start()
        print("[MAIN] Host Sensor started on port 9002.")
    except RuntimeError as exc:
        print(f"[FATAL] {exc}")
        print("[FATAL] Stop any old IDS process using these ports, then retry.")
        anomaly_detector.stop()
        return

    alert_mgr = AlertManager(metrics)
    print("[MAIN] Alert Manager initialized.")

    corr_engine = CorrelationEngine(event_queue, alert_mgr)
    corr_engine.start()
    print("[MAIN] Correlation Engine started.")

    time.sleep(0.5)
    print("[MAIN] All components running. Starting Attack Simulator...\n")

    while True:
        print("\n" + "=" * 53)
        print("  Multi-Source IDS — Attack Simulator")
        print("=" * 53)
        print("  1. Benign Baseline")
        print("  2. Brute-Force Login Attack")
        print("  3. Port Scan Attack")
        print("  4. Noise Injection")
        print("  5. Replay Attack")
        print("  6. Sensor Failure Simulation")
        print("  7. Correlated Multi-Source (Same IP)")
        print("  8. Run All Scenarios (for metrics)")
        print("  9. Generate Metrics Report")
        print("  0. Exit")
        print("=" * 53)

        choice = input("Enter your choice: ").strip()

        if choice == "1":
            metrics.start_scenario("benign_baseline_manual", "benign")
            scenario_benign_baseline()
        elif choice == "2":
            metrics.start_scenario("brute_force_manual", "attack")
            scenario_brute_force()
        elif choice == "3":
            metrics.start_scenario("port_scan_manual", "attack")
            scenario_port_scan()
        elif choice == "4":
            metrics.start_scenario("noise_injection_manual", "benign")
            scenario_noise_injection()
        elif choice == "5":
            metrics.start_scenario("replay_attack_manual", "attack")
            scenario_replay_attack()
        elif choice == "6":
            metrics.start_scenario("sensor_failure_manual", "attack")
            scenario_sensor_failure(net_sensor, host_sensor)
        elif choice == "7":
            metrics.start_scenario("correlated_same_ip_manual", "attack")
            scenario_multi_source_same_ip()
        elif choice == "8":
            run_all_scenarios(net_sensor, host_sensor, metrics)
        elif choice == "9":
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
