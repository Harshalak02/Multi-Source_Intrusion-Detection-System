# Multi-Source Intrusion Detection System (IDS)

This project implements a lightweight **multi-source IDS** for the IIIT Hyderabad SNS Lab assignment.
It correlates host and network telemetry, applies rule-based and statistical detection, and raises robust alerts with severity scoring.

## Features

- Unified JSON event schema across modules (`schema.py`)
- Independent sensors:
  - `network_sensor.py` (flows, port scan, replay, traffic rate)
  - `host_sensor.py` (failed logins, suspicious processes, login escalation pattern)
- Sliding-window correlation and score aggregation (`correlation_engine.py`)
- Statistical anomaly detector with rolling baseline and z-score (`anomaly_detector.py`)
- Alert manager with deduplication/cooldown (`alert_manager.py`)
- Attack simulator for reproducible scenarios (`attack_simulator.py`)
- Metrics: Precision, Recall, F1, FPR, FNR, alert latency, CPU and memory (`metrics.py`)

## Architecture

1. Sensors generate normalized events and push to a shared queue.
2. Correlation engine consumes events in a sliding time window.
3. Scores are computed via `EVENT_WEIGHTS` in `config.py`.
4. Severity is mapped to `Info/Low/Medium/High/Critical`.
5. Alert manager logs and deduplicates alerts.
6. Metrics collector tracks quality and runtime resource usage.

## Security Requirement Enforcement

- `Critical` is raised only when:
  - both host and network evidence exist in the active window and score crosses critical threshold, or
  - a deterministic multi-step pattern is detected (port scan + brute-force linkage).
- Single-source evidence is capped at `High`.

## Implemented Detectors

Rule-based detectors:
1. Port scan (distinct ports per source IP in time window)
2. High connection rate
3. Replay attack (flow hash repetition)
4. Brute-force burst (failed login threshold)
5. Suspicious process execution
6. Privilege escalation pattern (failed logins followed by successful login from same IP)

Statistical detector:
- Anomaly detector using z-score over rolling baselines for:
  - failed login rate
  - unique ports rate
  - connection rate

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install psutil
```

## Run

```bash
python3 main.py
```

Use the menu to launch individual attack scenarios or run all scenarios for evaluation.

## Output Files

- `logs/events.json` – normalized events
- `logs/alerts.json` – raised alerts
- `logs/metrics_report.txt` – latest metrics snapshot

## Reproducible Experiment Workflow

1. Start system (`python3 main.py`)
2. Run benign/noise baseline
3. Run one attack scenario
4. Observe alerts and scores
5. Generate metrics report from menu

## Notes

- No external IDS frameworks (Snort/Suricata) are used.
- The implementation is socket/thread-based and runs on a single machine.

## Quick Validation (Non-interactive)

Run an automated smoke validation to verify correlation behavior:

```bash
python3 test_validation.py
```

This performs two checks:
1. Different attacker IPs across sensors should **not** produce false `Critical` alerts.
2. Same attacker IP across sensors should produce at least one `Critical` alert for correlated multi-source behavior.

## Troubleshooting

### `OSError: [Errno 98] Address already in use`

This means another process is already bound to IDS ports `9001` or `9002` (often a previous `main.py` run still alive).

Use:

```bash
lsof -i :9001 -i :9002
kill -9 <PID>
```

Then run:

```bash
python3 main.py
```

The current startup path now fails fast with a clear message if bind fails, instead of continuing with broken sensors.

If the traceback still points to old lines like `_listen -> server.bind(...)`, run:

```bash
python3 doctor_ports.py
```

This prints the actual module file paths being imported, your current working directory, and whether ports 9001/9002 are free.


### Scoring saturation

To prevent score explosion from repeated identical events, scoring now caps per-event-type contributions within a window using `MAX_EVENT_TYPE_COUNT_PER_WINDOW` in `config.py`.
