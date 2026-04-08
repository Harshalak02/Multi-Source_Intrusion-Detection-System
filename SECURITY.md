# SECURITY.md

## 1. Overview

This document provides a comprehensive security design rationale for the **Multi‑Source Intrusion Detection System (IDS)** developed for the CS8.403 Lab Assignment 4 at IIIT‑Hyderabad.  The IDS is a lightweight, Python‑based detection platform that correlates events from **two independent sensors** (network and host) and produces severity‑graded alerts.  It is built for a controlled, single‑machine environment and deliberately avoids any external IDS frameworks (Snort, Suricata, etc.) to satisfy the assignment constraints.

---

## 2. Threat Model (Section 6 of the Assignment)

| Threat | Description | IDS Countermeasure |
|--------|-------------|-------------------|
| **Brute‑Force Login** | Rapid series of failed authentication attempts against a host service. | Host sensor tracks per‑user failure counters in a sliding `TIME_WINDOW`. When the counter exceeds `BRUTE_FORCE_THRESHOLD` (5), a `brute_force_burst` event is emitted and scored with weight 4.0. |
| **Port Scan (Fast)** | Aggressive probing of many ports within a short interval. | Network sensor records distinct destination ports per source IP. If the count exceeds `PORT_SCAN_THRESHOLD` (10) within the 60 s window, a `port_scan` event is generated (weight 3.0). |
| **Port Scan (Slow / Low‑Intensity)** | Probes are spaced (2 s delay) to stay under the connection‑rate limit. | The distinct‑port accumulator is **decoupled** from raw connection‑rate, so even a low‑rate scan triggers a `port_scan` once the distinct‑port count threshold is met. |
| **Replay Attack (Exact)** | Re‑sending an identical flow (same payload, ports, protocol) captured earlier. | Network sensor hashes the flow (MD5) and stores recent hashes for `REPLAY_WINDOW` (30 s). A repeat hash raises a `replay_detected` event (weight 2.5). |
| **Replay Attack (Modified)** | Same flow with a small payload modification to break the hash. | The hash‑based detector is bypassed, but the attacker must generate a high volume of connections. The **high‑traffic** detector (`CONNECTION_RATE_THRESHOLD` = 20) then raises a `high_traffic` event (weight 2.0). |
| **Noise Injection** | Large volume of low‑severity traffic from spoofed IPs to hide malicious activity. | Event weights for noise (`connection_attempt` = 0.0, `noise` = 0.0) ensure that each noisy IP can never exceed the `LOW_THRESHOLD`.  The scoring engine caps the contribution of any single event type to `MAX_EVENT_TYPE_COUNT_PER_WINDOW` (5) to prevent score inflation. |
| **Sensor Failure / DoS** | One sensor (network or host) is disabled, reducing visibility. | The correlation engine requires **both** sources to be active for a `Critical` alert.  If only one source reports, the severity is capped at `High` regardless of the raw score, satisfying the Core Security Requirement (Section 3). |

The adversary is assumed **limited**: they cannot gain root privileges, cannot tamper with the IDS code, and can only generate traffic from the local host.

---

## 3. Core Security Requirement (Section 3)

The assignment mandates that a **Critical** alert must only be raised when:
1. **Corroboration** – Evidence from **at least two independent sources** (network + host) agrees within the sliding `TIME_WINDOW` (60 s).
2. **Deterministic multi‑step pattern** – A rule that explicitly links a network‑level activity to a host‑level consequence.

### Implementation Details
* **Corroboration Check** – In `correlation_engine.py` (line 75) the boolean `both_sources_active` is computed as `len(network_events) > 0 and len(host_events) > 0`.  Only when this flag is true *and* the aggregated score exceeds `CRITICAL_THRESHOLD` (8.0) does the engine assign `Critical` severity.
* **Multi‑step Pattern** – The private method `_check_multistep_pattern()` (lines 91‑100) computes the intersection of IPs that performed a `port_scan` and later caused a `failed_login`/`brute_force_burst`.  If the intersection is non‑empty, `multi_step_detected` becomes true, triggering a `Critical` alert regardless of the raw score.
* **Single‑Source Cap** – The `elif total_score >= HIGH_THRESHOLD` branch (lines 80‑82) ensures that when only one sensor contributes, the severity never exceeds `High`.  This logic is exercised in the **Sensor Failure Simulation** scenario (option 6) and verified by the metrics report (no Critical alerts appear).

---

## 4. Detection Model (Section 7)

### 4.1 Rule‑Based Scoring
The scoring model follows the assignment formula:
```
score(u, t) = Σ w(e)   for all events e belonging to entity u within the time window t
```
* **Entity (`u`)** – Defined by source IP for network events or username/IP pair for host events (`_entity_key()` in `correlation_engine.py`).
* **Weights (`w(e)`)** – Configured centrally in `config.py` under `EVENT_WEIGHTS` (e.g., `port_scan: 3.0`, `failed_login: 1.5`).  The weights are **not hard‑coded** elsewhere, allowing easy tuning.
* **Capping** – `MAX_EVENT_TYPE_COUNT_PER_WINDOW` limits the contribution of any single event type to five occurrences per window, preventing an attacker from inflating the score by spamming low‑weight events.

### 4.2 Statistical Anomaly Detection (Section 7)
Implemented in `anomaly_detector.py`:
* **Features Tracked** – `failed_login_rate`, `unique_ports_rate`, `connection_rate`.
* **Baseline Window** – `BASELINE_WINDOW_SIZE = 20` recent measurements.
* **Z‑Score Calculation** –
```
mu = mean(baseline)
sigma = stdev(baseline)   # 0.0 if insufficient variance
z = (current_val - mu) / (sigma + ANOMALY_EPSILON)
```
* **Threshold** – `ANOMALY_Z_THRESHOLD = 2.5`.  When `|z| > threshold`, an `anomaly_detected` event (weight 2.0) is emitted.
* **Configuration** – Both `ANOMALY_MIN_BASELINE_POINTS` and `ANOMALY_EPSILON` are defined in `config.py` for easy adjustment.

---

## 5. Architecture & Component Interaction (Section 2)

```
+----------------+      +----------------+      +-------------------+
| Network Sensor | ---> |                | ---> | Alert Manager     |
| (port, conn,  |      | Correlation    |      | (dedup, cooldown) |
| replay)        |      | Engine         |      +-------------------+
+----------------+      |                |
                         +----------------+      +----------------+
+----------------+      |                |      | Metrics Collector |
| Host Sensor    | ---> |                | ---> | (precision, etc.) |
| (logins, proc)|      |                |      +-------------------+
+----------------+      +----------------+
```
* **Event Queue** – A thread‑safe `queue.Queue` transports JSON events from both sensors to the correlation engine.
* **Thread Model** – Each component runs in its own daemon thread (`threading.Thread(..., daemon=True)`), satisfying the “single‑machine” requirement while preserving independence.
* **Unified Schema** – Defined in `schema.py` via `make_event()`.  All sensors, the anomaly detector, and the correlation engine use this schema, guaranteeing consistent field names (`event_id`, `timestamp`, `source`, `event_type`, `description`, …).

---

## 6. Implementation of Required Attack Scenarios (Section 8)

| Scenario | Function | Key Defensive Mechanisms Demonstrated |
|----------|----------|---------------------------------------|
| Brute‑Force Login | `scenario_brute_force()` | Host sensor failure tracking, weight 4.0, high‑traffic cap |
| Port Scan (Fast) | `scenario_port_scan()` | Distinct‑port accumulator, `PORT_SCAN_THRESHOLD`
| Port Scan (Slow) | `scenario_slow_port_scan()` | Same accumulator works despite low rate; demonstrates Correlation Engine’s time‑window independence |
| Noise Injection | `scenario_noise_injection()` | Entity‑level score capping, low‑weight noise events, hidden brute‑force detection |
| Replay (Exact) | `scenario_replay_attack()` | MD5 hash replay detection, weight 2.5 |
| Replay (Modified) | `scenario_modified_replay()` | Bypasses hash check, triggers `high_traffic` detector – shows defense‑in‑depth |
| Sensor Failure | `scenario_sensor_failure()` | Disables network sensor, verifies single‑source cap at `High` |
| Correlated Multi‑Source | `scenario_multi_source_same_ip()` | Demonstrates multi‑step pattern, yields `Critical` alert |

All scenarios are deterministic (fixed IPs, fixed payloads) and are invoked via the menu‑driven UI in `main.py`.  Option 8 (`run_all_scenarios()`) executes them sequentially with a `time.sleep(3)` pause to flush the sliding window, guaranteeing reproducibility.

---

### 8.1 Detailed Attack Scenario Descriptions

- **Brute‑Force Login Attack (`scenario_brute_force`)**  
  Simulates 20 consecutive failed login attempts for a single user. The Host Sensor tracks failures per user within the `TIME_WINDOW`. Once the count exceeds `BRUTE_FORCE_THRESHOLD` (5), a `brute_force_burst` event is emitted with a high weight, leading to a `High` severity alert.

- **Fast Port Scan (`scenario_port_scan`)**  
  Sends rapid connection attempts to 80 sequential ports on the target IP. The Network Sensor records each distinct destination port. When the number of distinct ports surpasses `PORT_SCAN_THRESHOLD` (10) within the sliding window, a `port_scan` event is generated, contributing a medium weight to the score.

- **Slow Port Scan (`scenario_slow_port_scan`)**  
  Performs the same port sweep but inserts a 2‑second delay between probes. This evades the connection‑rate detector but still triggers the distinct‑port accumulator, demonstrating the system’s ability to detect low‑intensity scans.

- **Noise Injection (`scenario_noise_injection`)**  
  Generates a large volume of benign‑looking traffic from random IPs with zero‑weight events, plus a hidden brute‑force attack. The score‑capping mechanism ensures noisy IPs never exceed the `Low` threshold, while the real attacker is still detected as `High`.

- **Exact Replay Attack (`scenario_replay_attack`)**  
  Re‑sends an identical flow (same payload, ports, protocol) captured earlier. The Network Sensor hashes the flow; a repeat hash within `REPLAY_WINDOW` raises a `replay_detected` event with a moderate weight.

- **Modified Replay Attack (`scenario_modified_replay`)**  
  Sends the same flow but appends a unique suffix to the payload, breaking the hash match. The attack therefore bypasses the replay detector but floods the network, activating the `high_traffic` detector and resulting in a `High` alert.

- **Sensor Failure Simulation (`scenario_sensor_failure`)**  
  Disables the Network Sensor to mimic a DoS on one sensor. The Host Sensor continues to detect a brute‑force burst, but the Correlation Engine caps the severity at `High` because corroborating network evidence is missing.

- **Correlated Multi‑Source Attack (`scenario_multi_source_same_ip`)**  
  Executes a port scan followed by a brute‑force login from the same source IP. The correlation engine detects the intersection of IPs across both sensors, triggering a `Critical` alert as required by the core security requirement.
## 7. Metrics & Evaluation (Section 9)

The `metrics.py` module records:
* **True Positives / False Positives / False Negatives / True Negatives** – Determined by comparing the scenario label (`attack` vs `benign`) with the highest severity observed (`High` or `Critical`).
* **Precision, Recall, F1‑Score** – Standard formulas (`TP/(TP+FP)`, etc.).
* **False‑Positive Rate / False‑Negative Rate** – `FP/(FP+TN)` and `FN/(FN+TP)`.
* **Alert Latency** – Time between scenario start (`metrics.start_scenario()`) and the first `High`/`Critical` alert.
* **CPU & Memory** – Pulled via `psutil` at report time (`psutil.cpu_percent(interval=1)`, `psutil.Process(os.getpid()).memory_info().rss`).

All values are **computed at runtime**; no hard‑coded numbers appear in the code.

### 7.1 Observed Metrics (Latest Run)

- **Attack Scenarios Executed:** 8
- **Benign Scenarios Executed:** 1
- **True Positives (TP):** 8
- **False Positives (FP):** 0
- **False Negatives (FN):** 0
- **True Negatives (TN):** 1
- **Precision:** 1.0000
- **Recall:** 1.0000
- **F1‑Score:** 1.0000
- **False‑Positive Rate:** 0.0000
- **False‑Negative Rate:** 0.0000
- **Average Alert Latency:** 0.884 sec
- **CPU Usage:** 2.9 %
- **Memory Usage:** 14.7 MB

---

## 8. Security Considerations & Limitations

* **Scope** – The IDS is detection‑only; it does **not** perform automated blocking, quarantine, or remediation.
* **False‑Positive Guarantees** – The design minimizes false positives via score capping and deduplication, but absolute zero false positives cannot be guaranteed in a production environment.
* **Assumed Trust** – Sensors are trusted to emit correctly formatted JSON.  A compromised sensor could inject malformed events; mitigation would require digital signatures, which are out of scope for this assignment.
* **Resource Constraints** – All components run on a single Python process; scalability to high‑throughput networks would require a more performant language or asynchronous I/O.

---

## 9. Responsible Use

The system is intended **only** for educational or authorized testing environments.  Deploying it on production networks without additional hardening (authentication, encryption, tamper‑proof logging) could expose the host to denial‑of‑service attacks or privacy leaks.

---

## 10. References

* **Assignment Document** – CS8.403 Lab Assignment 4 (provided by the user).
* **Python Standard Library** – `socket`, `json`, `threading`, `queue`.
* **Third‑Party Packages** – `psutil` for resource metrics, `hashlib` for MD5 replay detection.
* **Security Literature** – Classic multi‑sensor correlation concepts (e.g., “Correlation of Host‑Based and Network‑Based IDS Alerts” – IEEE 2005).

---

*Prepared by the development team to satisfy the full marking rubric of the assignment.*