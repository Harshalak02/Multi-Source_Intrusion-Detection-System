import time
from attack_simulator import (
    scenario_brute_force,
    scenario_port_scan,
    scenario_noise_injection,
    scenario_replay_attack
)

# -----------------------------
# TEST 1: Cooldown Bug
# -----------------------------
def test_cooldown_issue():
    print("\n==============================")
    print("TEST 1: Cooldown Issue")
    print("==============================")

    print("\n[STEP] Running Port Scan (IP1)...")
    scenario_port_scan()

    time.sleep(1)  # small gap

    print("\n[STEP] Running Brute Force (IP2)...")
    scenario_brute_force()

    print("\n[EXPECTED]")
    print("→ You should see TWO alerts")
    print("→ If second alert missing → BUG CONFIRMED")


# -----------------------------
# TEST 2: Wrong Correlation (DIFFERENT IPs)
# -----------------------------
def test_wrong_correlation():
    print("\n==============================")
    print("TEST 2: Wrong Correlation")
    print("==============================")

    print("\n[STEP] Port Scan from IP1")
    scenario_port_scan()

    time.sleep(2)

    print("\n[STEP] Brute Force from IP2")
    scenario_brute_force()

    print("\n[EXPECTED]")
    print("→ Should NOT produce CRITICAL")
    print("→ If CRITICAL appears → BUG CONFIRMED")


# -----------------------------
# TEST 3: Anomaly Weight Issue
# -----------------------------
def test_anomaly_issue():
    print("\n==============================")
    print("TEST 3: Anomaly Detection")
    print("==============================")

    print("\n[STEP] Running noise to trigger anomaly...")
    scenario_noise_injection()

    print("\n[EXPECTED]")
    print("→ Should produce at least LOW/MEDIUM alert")
    print("→ If NO alert → anomaly weight = 0 (BUG)")


# -----------------------------
# TEST 4: Threshold Check
# -----------------------------
def test_threshold_issue():
    print("\n==============================")
    print("TEST 4: Threshold Check")
    print("==============================")

    print("\n[STEP] Running ONLY brute force...")
    scenario_brute_force()

    print("\n[EXPECTED]")
    print("→ Should be HIGH (not Critical)")
    print("→ If Critical → threshold too low")


# -----------------------------
# RUN ALL TESTS
# -----------------------------
def run_all_tests():
    print("\n🚀 Running All IDS Tests...\n")

    test_cooldown_issue()
    time.sleep(5)

    test_wrong_correlation()
    time.sleep(5)

    test_anomaly_issue()
    time.sleep(5)

    test_threshold_issue()

    print("\n✅ Testing complete.")


if __name__ == "__main__":
    run_all_tests()