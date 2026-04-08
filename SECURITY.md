# SECURITY.md

## 1) Overview

This project is a **Multi-Source Intrusion Detection System (IDS)** that correlates host and network events and raises severity-based alerts (`Low`, `Medium`, `High`, `Critical`).

It is built for controlled testing/demo environments and is currently **detection-only** (no automated blocking/remediation).

---

## 2) Security Scope

In scope:

- Network sensor detections (e.g., scan/replay-like behavior)
- Host sensor detections (e.g., failed login bursts)
- Correlation engine severity scoring
- Alert generation and logging
- Scenario-level metrics reporting

Out of scope:

- Automated incident response actions
- Production-hardening claims
- Guarantee of zero false positives/false negatives

---

## 3) Detection Intent by Scenario

- **Benign Baseline**: should remain non-attack (no High/Critical expected)
- **Brute Force**: should escalate to High/Critical
- **Port Scan**: should escalate to High (network-only possible)
- **Noise Injection (current version)**: includes hidden brute-force attacker under noise; expected to still detect attack
- **Replay Attack**: repeated payload/hash behavior should trigger elevated detection
- **Correlated Multi-Source (Same IP)**: expected High/Critical with corroboration
- **Sensor Failure**: expected High at most (no Critical required without corroboration)

---

## 4) Observed Metrics (from your latest run logs)

> Note: these are scenario outputs exactly as reported in your console snippets.

### 4.1 Benign Baseline (Option 1)

- Attack Scenarios: `0`
- Benign Scenarios: `1`
- TP: `0`, FP: `0`, FN: `0`, TN: `1`
- Precision: `0.0000`
- Recall: `0.0000`
- F1-Score: `0.0000`
- FP Rate: `0.0000`
- FN Rate: `0.0000`
- Avg Alert Latency: `0.000 sec`
- CPU Usage: `6.2%`
- Memory Usage: `19.0 MB`

---

### 4.2 Brute-Force Login Attack (Option 2)

- Attack Scenarios: `1`
- Benign Scenarios: `0`
- TP: `1`, FP: `0`, FN: `0`, TN: `0`
- Precision: `1.0000`
- Recall: `1.0000`
- F1-Score: `1.0000`
- FP Rate: `0.0000`
- FN Rate: `0.0000`
- Avg Alert Latency: `0.604 sec`
- CPU Usage: `2.7%`
- Memory Usage: `19.0 MB`

---

### 4.3 Port Scan Attack (Option 3)

- Attack Scenarios: `1`
- Benign Scenarios: `0`
- TP: `1`, FP: `0`, FN: `0`, TN: `0`
- Precision: `1.0000`
- Recall: `1.0000`
- F1-Score: `1.0000`
- FP Rate: `0.0000`
- FN Rate: `0.0000`
- Avg Alert Latency: `1.016 sec`
- CPU Usage: `9.9%`
- Memory Usage: `19.1 MB`

---

### 4.4 Noise Injection Attack (Option 4, with hidden brute-force)

- Observed: many Low alerts for noise IPs + High on attacker `192.168.1.77`
- Attack Scenarios: `1`
- Benign Scenarios: `0`
- TP: `1`, FP: `0`, FN: `0`, TN: `0`
- Precision: `1.0000`
- Recall: `1.0000`
- F1-Score: `1.0000`
- FP Rate: `0.0000`
- FN Rate: `0.0000`
- Avg Alert Latency: `2.550 sec`
- CPU Usage: `3.3%`
- Memory Usage: `19.3 MB`

---

### 4.5 Replay Attack (Option 5)

- Attack Scenarios: `1`
- Benign Scenarios: `0`
- TP: `1`, FP: `0`, FN: `0`, TN: `0`
- Precision: `1.0000`
- Recall: `1.0000`
- F1-Score: `1.0000`
- FP Rate: `0.0000`
- FN Rate: `0.0000`
- Avg Alert Latency: `4.004 sec`
- CPU Usage: `5.8%`
- Memory Usage: `19.0 MB`

---

### 4.6 Correlated Multi-Source (Same IP) (Option 7)

- Observed: escalation reached `Critical` with host + network corroboration
- Attack Scenarios: `1`
- Benign Scenarios: `0`
- TP: `1`, FP: `0`, FN: `0`, TN: `0`
- Precision: `1.0000`
- Recall: `1.0000`
- F1-Score: `1.0000`
- FP Rate: `0.0000`
- FN Rate: `0.0000`
- Avg Alert Latency: `0.814 sec`
- CPU Usage: `5.2%`
- Memory Usage: `19.1 MB`

---

### 4.7 Sensor Failure Simulation (Option 6)

- Observed: High alerts only (no Critical), consistent with degraded single-source visibility
- Attack Scenarios: `1`
- Benign Scenarios: `0`
- TP: `1`, FP: `0`, FN: `0`, TN: `0`
- Precision: `1.0000`
- Recall: `1.0000`
- F1-Score: `1.0000`
- FP Rate: `0.0000`
- FN Rate: `0.0000`
- Avg Alert Latency: `1.603 sec`
- CPU Usage: `9.6%`
- Memory Usage: `19.0 MB`

---

## 5) Security Interpretation

### Strengths observed

- Attack scenarios reliably crossed detection threshold in provided runs.
- Correlated same-IP scenario correctly escalated to `Critical`.
- Sensor-failure scenario still produced meaningful High alerts without false Critical escalation.

### Important caveats

- Current manual-run metrics shown are scenario-level and often display one scenario at a time in your runs.
- Precision/Recall/F1 are tied to High/Critical detection at scenario level, not per-alert classification quality.
- Noise Injection in current setup is not pure benign noise; it embeds a hidden brute-force attacker.

---

## 6) Responsible Use

Use only on systems and environments where you have explicit authorization.  
This IDS is for educational testing and should be combined with additional controls in real deployments.