# SECURITY.md

## Security Design Overview

This IDS is designed to improve robustness and reduce false positives by correlating independent evidence channels.

### Components and Trust Boundaries

- **Network Sensor**: receives synthetic flow metadata over localhost TCP.
- **Host Sensor**: receives synthetic host log events over localhost TCP.
- **Correlation Engine**: central policy decision point for severity computation.
- **Alert Manager**: deduplicates and records alert outputs.
- **Anomaly Detector**: statistical monitor that emits anomaly events.

All modules run on a single host and communicate via in-process queue or localhost sockets.

## Event Integrity and Schema Control

- A unified schema is enforced through `schema.py`.
- Required fields are validated before event publication.
- Event IDs use UUIDv4; timestamps use Unix epoch seconds.

## Detection and Correlation Strategy

### Rule-Based Detection
- Network: port scan, high traffic, replay.
- Host: brute-force burst, suspicious process, privilege escalation pattern.

### Statistical Detection
- Rolling baseline z-score model for three activity features.
- Anomaly events are integrated into the same scoring pipeline.

### Severity and False Positive Control
- Score is computed from weighted event evidence.
- **Critical gating rule**:
  - requires both host and network evidence in active window, or
  - deterministic multi-step pattern check.
- Single-source activity cannot exceed `High` severity.

## Alert Flood Protection

- Cooldown-based deduplication suppresses repeated equivalent alerts for a configurable interval.
- Deduplication key combines severity, source mix, and event-type mix to avoid over-suppressing unrelated incidents.

## Adversary Model Coverage

The implementation includes scenarios for:
- brute-force login attempts,
- fast scanning,
- replay attacks,
- noise injection,
- temporary sensor disablement.

## Known Limitations

- Transport security and message authentication are not implemented (localhost lab scope).
- Flow analysis is metadata-level only (no deep payload inspection by design).
- Current implementation assumes trusted local execution context.
