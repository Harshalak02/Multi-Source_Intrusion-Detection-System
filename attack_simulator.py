import socket
import json
import time
import random
from config import NETWORK_SENSOR_PORT, HOST_SENSOR_PORT

def send_to_network_sensor(data: dict):
    """Send a simulated network flow to the Network Sensor."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect(("127.0.0.1", NETWORK_SENSOR_PORT))
        s.sendall(json.dumps(data).encode("utf-8"))
    except ConnectionRefusedError:
        print(f"[ERROR] Network Sensor is not running on port {NETWORK_SENSOR_PORT}.")
    finally:
        s.close()

def send_to_host_sensor(data: dict):
    """Send a simulated host log event to the Host Sensor."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect(("127.0.0.1", HOST_SENSOR_PORT))
        s.sendall(json.dumps(data).encode("utf-8"))
    except ConnectionRefusedError:
        print(f"[ERROR] Host Sensor is not running on port {HOST_SENSOR_PORT}.")
    finally:
        s.close()



def scenario_benign_baseline():
    print("\n[SIMULATOR] Starting Benign Baseline Activity...")
    client_ip = "10.10.10.10"
    target_ip = "127.0.0.1"

    # Benign low-rate network activity
    for port in [80, 443, 8080, 22] * 2:
        flow = {
            "src_ip": client_ip,
            "dst_ip": target_ip,
            "src_port": random.randint(20000, 50000),
            "dst_port": port,
            "protocol": "TCP"
        }
        send_to_network_sensor(flow)
        time.sleep(0.2)

    # Benign host activity: successful logins and normal process creation
    for user in ["alice", "bob", "charlie"]:
        send_to_host_sensor({
            "log_type": "successful_login",
            "username": user,
            "src_ip": client_ip,
            "timestamp": time.time(),
        })
        send_to_host_sensor({
            "log_type": "process_creation",
            "username": user,
            "process_name": "python",
            "timestamp": time.time(),
        })
        time.sleep(0.2)

    print("[SIMULATOR] Benign baseline complete.")
    print("[SIMULATOR] Expected: Mostly Info/Low, ideally no High/Critical.")


def scenario_brute_force():
    print("\n[SIMULATOR] Starting Brute-Force Login Attack...")
    attacker_ip = "192.168.1.100"
    target_user = "admin"
    num_attempts = 20    # Enough to trigger Rule 4

    for i in range(num_attempts):
        log_entry = {
            "log_type":  "failed_login",
            "username":  target_user,
            "src_ip":    attacker_ip,
            "timestamp": time.time()
        }
        send_to_host_sensor(log_entry)
        time.sleep(0.2)   # 0.2 second between attempts (fast but not instant)

    print(f"[SIMULATOR] Sent {num_attempts} failed login attempts for user '{target_user}'")
    print("[SIMULATOR] Expected: High or Critical alert depending on network corroboration")

def scenario_port_scan():
    print("\n[SIMULATOR] Starting Port Scan Attack...")
    attacker_ip = "192.168.1.101"
    target_ip   = "127.0.0.1"
    ports_to_scan = list(range(20, 100))   # 80 ports

    for port in ports_to_scan:
        flow = {
            "src_ip":   attacker_ip,
            "dst_ip":   target_ip,
            "src_port": 54321,
            "dst_port": port,
            "protocol": "TCP"
        }
        send_to_network_sensor(flow)
        time.sleep(0.05)    # 50ms between probes (fast scan)

    print(f"[SIMULATOR] Sent probes to {len(ports_to_scan)} ports from {attacker_ip}")
    print("[SIMULATOR] Expected: Rule 1 (Port Scan) fires → High alert if only network sensor")

def scenario_noise_injection():
    print("\n[SIMULATOR] Starting Noise Injection...")
    attacker_ip = "10.0.0.50"
    # Mix of low-weight noise events from both sensors
    for i in range(50):
        # Random low-level network probes (single port, not a scan)
        flow = {
            "src_ip":   attacker_ip,
            "dst_ip":   "127.0.0.1",
            "src_port": random.randint(10000, 60000),
            "dst_port": random.choice([80, 443, 22, 8080]),
            "protocol": "TCP"
        }
        send_to_network_sensor(flow)

        # Random benign-looking host events
        log_entry = {
            "log_type":  "failed_login",
            "username":  f"user_{random.randint(1, 100)}",
            "src_ip":    f"10.0.0.{random.randint(1, 254)}",
            "timestamp": time.time()
        }
        send_to_host_sensor(log_entry)
        time.sleep(0.1)

    print("[SIMULATOR] Noise injection complete.")
    print("[SIMULATOR] Expected: Only Low/Medium alerts. NO Critical alerts from noise alone.")

def scenario_replay_attack():
    print("\n[SIMULATOR] Starting Replay Attack...")
    attacker_ip = "192.168.1.200"
    target_ip   = "127.0.0.1"

    # Step 1: Send an original "benign" connection
    original_flow = {
        "src_ip":   attacker_ip,
        "dst_ip":   target_ip,
        "src_port": 45678,
        "dst_port": 80,
        "protocol": "TCP",
        "payload": "benign_http_get_request_v1"   # Used in replay hash inside Network Sensor
    }
    print("[SIMULATOR] Sending original connection...")
    send_to_network_sensor(original_flow)
    time.sleep(2)

    # Step 2: Replay the same connection (same hash)
    print("[SIMULATOR] Replaying the same connection (simulated replay)...")
    for _ in range(5):
        send_to_network_sensor(original_flow)
        time.sleep(1)

    print("[SIMULATOR] Replay attack sent.")
    print("[SIMULATOR] Expected: Rule 3 fires on repeated hash → EVENT_REPLAY_DETECTED")



def scenario_multi_source_same_ip():
    print("\n[SIMULATOR] Starting Correlated Multi-Source Attack (Same IP)...")
    attacker_ip = "192.168.1.150"
    target_ip = "127.0.0.1"

    # Stage 1: network reconnaissance
    for port in range(30, 55):
        flow = {
            "src_ip": attacker_ip,
            "dst_ip": target_ip,
            "src_port": 40000,
            "dst_port": port,
            "protocol": "TCP"
        }
        send_to_network_sensor(flow)
        time.sleep(0.04)

    # Stage 2: host brute-force from same IP
    for _ in range(10):
        log_entry = {
            "log_type": "failed_login",
            "username": "admin",
            "src_ip": attacker_ip,
            "timestamp": time.time()
        }
        send_to_host_sensor(log_entry)
        time.sleep(0.12)

    print("[SIMULATOR] Expected: correlated High/Critical because same source IP appears in both sensors.")


def scenario_sensor_failure(network_sensor, host_sensor):
    print("\n[SIMULATOR] Starting Sensor Failure Simulation...")

    # Step 1: Disable the Network Sensor
    print("[SIMULATOR] Disabling Network Sensor...")
    network_sensor.disable()
    time.sleep(1)

    # Step 2: Run a brute force attack (only host sensor sees it)
    print("[SIMULATOR] Running brute force while Network Sensor is down...")
    for i in range(15):
        log_entry = {
            "log_type":  "failed_login",
            "username":  "root",
            "src_ip":    "192.168.1.50",
            "timestamp": time.time()
        }
        send_to_host_sensor(log_entry)
        time.sleep(0.2)

    print("[SIMULATOR] Expected: HIGH alert at most (only one sensor active).")
    print("[SIMULATOR] Expected: NO Critical alert despite brute force (no network corroboration).")

    # Step 3: Re-enable
    time.sleep(2)
    network_sensor.enable()
    print("[SIMULATOR] Network Sensor re-enabled.")

def run_all_scenarios(net_sensor=None, host_sensor=None, metrics=None):
    if metrics: metrics.start_scenario("benign_baseline", "benign")
    scenario_benign_baseline()
    time.sleep(3)

    if metrics: metrics.start_scenario("brute_force", "attack")
    scenario_brute_force()
    time.sleep(3)

    if metrics: metrics.start_scenario("port_scan", "attack")
    scenario_port_scan()
    time.sleep(3)

    if metrics: metrics.start_scenario("noise_injection", "benign")
    scenario_noise_injection()
    time.sleep(3)

    if metrics: metrics.start_scenario("replay_attack", "attack")
    scenario_replay_attack()
    time.sleep(3)

    if metrics: metrics.start_scenario("correlated_same_ip", "attack")
    scenario_multi_source_same_ip()
    time.sleep(3)

    if net_sensor and host_sensor:
        if metrics: metrics.start_scenario("sensor_failure", "attack")
        scenario_sensor_failure(net_sensor, host_sensor)
        time.sleep(3)

def main():
    print("\n" + "="*53)
    print("  Multi-Source IDS — Attack Simulator")
    print("="*53)

    while True:
        print("\n  1. Benign Baseline")
        print("  2. Brute-Force Login Attack")
        print("  3. Port Scan Attack")
        print("  4. Noise Injection")
        print("  5. Replay Attack")
        print("  6. Sensor Failure Simulation")
        print("  7. Correlated Multi-Source (Same IP)")
        print("  8. Run All Scenarios Sequentially (for metrics)")
        print("  0. Exit")
        print("="*53)

        choice = input("Enter your choice: ").strip()

        if choice == "1":
            scenario_benign_baseline()
        elif choice == "2":
            scenario_brute_force()
        elif choice == "3":
            scenario_port_scan()
        elif choice == "4":
            scenario_noise_injection()
        elif choice == "5":
            scenario_replay_attack()
        elif choice == "6":
            print("[INFO] Sensor failure simulation must be run from main.py (option 6).")
        elif choice == "7":
            scenario_multi_source_same_ip()
        elif choice == "8":
            run_all_scenarios()
        elif choice == "0":
            print("Exiting simulator.")
            break
        else:
            print("[ERROR] Invalid choice. Please enter 0-8.")


if __name__ == "__main__":
    main()
