#!/usr/bin/env bash
set -euo pipefail

printf "\n[1/5] Syntax check...\n"
python3 -m py_compile *.py

printf "\n[2/5] Port diagnostics (non-fatal)...\n"
python3 doctor_ports.py || true

printf "\n[3/5] Core validation (required)...\n"
python3 test_validation.py

printf "\n[4/5] Integration harness (optional/deeper)...\n"
python3 test_cases.py

printf "\n[5/5] Done. Artifacts:\n"
printf "- logs/events.json\n- logs/alerts.json\n- logs/metrics_report.txt (generated when metrics printed in main flow)\n"
