# 🚨 Multi-Source Intrusion Detection System (IDS)

A lightweight **multi-source Intrusion Detection System (IDS)** developed for the **IIIT Hyderabad SNS Lab assignment**.  
This system correlates **network and host telemetry**, detects suspicious activities, and generates **severity-based alerts**.

---

## 📌 Overview

This IDS combines:

- Network-level monitoring  
- Host-level monitoring  
- Correlation engine  
- Anomaly detection  
- Alert management  
- Performance evaluation  

It is designed to simulate real-world detection scenarios and evaluate detection quality using multiple metrics.

---

## ⚙️ Features

- Multi-source correlation (Host + Network)  
- Rule-based + anomaly-based detection  
- Sliding window event correlation  
- Severity-based alerting:
  - Info
  - Low
  - Medium
  - High
  - Critical  
- Alert deduplication & cooldown handling  
- Built-in attack simulator  
- Detailed performance metrics:
  - Precision, Recall, F1 Score  
  - False Positive Rate (FPR)  
  - False Negative Rate (FNR)  
  - Alert latency  
  - CPU & Memory usage  

---

## 🧠 System Architecture

```
Sensors → Correlation Engine → Anomaly Detector → Alert Manager → Metrics
```

### Components

**Sensors**
- `network_sensor.py` → Captures network events  
- `host_sensor.py` → Captures host/system events  

**Core Engine**
- `correlation_engine.py` → Correlates events across sources  
- `anomaly_detector.py` → Detects deviations from baseline  

**Alerting**
- `alert_manager.py` → Generates & deduplicates alerts  

**Evaluation**
- `metrics.py` → Computes performance metrics  

**Simulation**
- `attack_simulator.py` → Runs predefined attack scenarios  

---

## 📁 Project Structure

```
.
├── main.py
├── network_sensor.py
├── host_sensor.py
├── correlation_engine.py
├── anomaly_detector.py
├── alert_manager.py
├── attack_simulator.py
├── metrics.py
├── doctor_ports.py
├── test_validation.py
├── test_cases.py
├── run_all_checks.sh
└── logs/
    ├── events.json
    ├── alerts.json
    └── metrics_report.txt
```

---

## 🚀 Getting Started

### 1. Create Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install Dependencies

```bash
pip install psutil
```

---

## ▶️ Running the IDS

```bash
python3 main.py
```

This launches the interactive simulator menu.

---

## 🧪 Attack Simulation Menu

```
1  Benign Baseline
2  Brute-Force Login Attack
3  Port Scan Attack
4  Noise Injection
5  Replay Attack
6  Sensor Failure Simulation
7  Correlated Multi-Source Attack (Same IP)
8  Run All Scenarios
9  Generate Metrics Report
0  Exit
```

---

## 📊 Output Files

- `logs/events.json` → All normalized events  
- `logs/alerts.json` → Generated alerts  
- `logs/metrics_report.txt` → Performance summary  

---

## ✅ Validation & Testing

### Quick Validation

```bash
python3 test_validation.py
```

### Full System Checks

```bash
./run_all_checks.sh
```

---

## 🛠️ Troubleshooting

### Port Already in Use

Error:
```
OSError: [Errno 98] Address already in use
```

Fix:

```bash
lsof -i :9001 -i :9002
kill -9 <PID>
python3 main.py
```

---

### Port Diagnostics

```bash
python3 doctor_ports.py
```

---

## 📈 Metrics Collected

- True Positives (TP)  
- False Positives (FP)  
- False Negatives (FN)  
- True Negatives (TN)  
- Precision  
- Recall  
- F1 Score  
- False Positive Rate (FPR)  
- False Negative Rate (FNR)  
- Average Alert Latency  
- CPU Usage Snapshot  
- Memory Usage Snapshot  

---

## 🎯 Use Cases

- Cybersecurity research & education  
- IDS/IPS prototyping  
- Attack simulation & benchmarking  
- Multi-source telemetry correlation experiments  

