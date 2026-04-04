# Assignment Checklist (Required vs Optional)

## Required for assignment (high priority)

- [x] Multi-source architecture present: network sensor, host sensor, correlation engine, alert manager, simulator.
- [x] Unified JSON schema and validation.
- [x] Sliding time-window correlation.
- [x] At least six rule-based detectors.
- [x] Statistical anomaly detector present.
- [x] Severity scoring pipeline (Info/Low/Medium/High/Critical).
- [x] Critical gating logic based on corroboration/multi-step rule.
- [x] Alert flood control (dedup/cooldown).
- [x] Reproducible evaluation flow and metrics output.
- [x] README and SECURITY.md present.

## Not fully as expected / should be improved before submission

- [ ] Simulator scenario alignment for clear same-entity multi-source demonstration in viva/report.
- [ ] Port-scan campaign consolidation (currently can produce repeated scan alerts across long scans).
- [ ] Cleaner debug verbosity for long runs (logs are noisy under heavy traffic).

## Optional polish (not strict blockers unless explicitly demanded)

- [ ] Smarter anomaly attribution to real entity/IP instead of synthetic placeholders.
- [ ] Additional performance tuning for very high event rates.
- [ ] More granular alert suppression by attacker entity and attack stage.
