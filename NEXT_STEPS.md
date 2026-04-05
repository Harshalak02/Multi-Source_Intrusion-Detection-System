# What to do now (Submission Runbook)

## 1) Quick correctness check (mandatory)

```bash
python3 test_validation.py
```

Expected at end:
- `TEST1 ... Critical=0`
- `TEST2 ... Critical>=1`
- `PASS: Validation checks succeeded.`

## 2) Demo run (for viva)

```bash
python3 main.py
```

In menu run in this order:
1. `1` Benign Baseline
2. `7` Correlated Multi-Source (Same IP)
3. `4` Noise Injection
4. `9` Generate Metrics Report
5. `0` Exit

## 3) If startup fails due ports

```bash
python3 doctor_ports.py
```

Then stop any old process shown by your OS tools and re-run step 1.

## 4) Collect artifacts for submission/report

- `logs/events.json`
- `logs/alerts.json`
- `logs/metrics_report.txt`

## 5) Final submission checklist

- Include source files
- Include `README.md`
- Include `SECURITY.md`


## Optional deeper integration test

```bash
python3 test_cases.py
```

This now boots IDS components automatically and reports pass/fail style outputs for cooldown, correlation, anomaly/noise, and threshold checks.


## One-command run (optional)

```bash
./run_all_checks.sh
```

This runs syntax check, port diagnostics, core validation, and integration harness in order.


Note: Individual menu attacks now start their own metric scenario labels, so per-attack metrics are captured even without using "Run All".


Note: `main.py` now auto-prints a metrics report after each individual scenario run (options 1-7).
