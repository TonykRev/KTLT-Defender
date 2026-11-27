# Evidence 09 — G5 Discovery re-run on cloud-vm (scoring fix validated)

**Date:** 2026-11-27
**Environment:** cloud-vm (Azure Win11 Pro Insider b26300), RTP ON, TamperProtection ON, cloud_protection OFF
**Code:** HEAD = 9855a79 (`fix(scoring): pass the runner's technique_ran signal into the scorer`)
**run_id:** 5
**Unit tests:** 45 / 45 OK

## Why this re-run
The first G5 run scored all three discovery techniques `inconclusive`. Root cause: the scorer
re-inferred "did the technique run?" from evidence (Sysmon events OR static==clean). On the behavior
axis with Sysmon unavailable on this VM, that inference collapsed to False, so every *non-detected*
technique — the exact gap cases this study exists to surface — was wrongly buried as `inconclusive`.

Fix (9855a79): the measurement station now passes the atomic runner's authoritative
`technique_ran` signal straight into `scorer.score(...)`. A technique that demonstrably ran and
produced no Defender detection now scores `not_detected`.

## Results (G5 — Discovery / LOLBin, all non-invasive)

| Technique  | Name                         | State          | Fidelity | fid_valid | Evidence  |
|------------|------------------------------|----------------|----------|-----------|-----------|
| T1082      | System Information Discovery | not_detected   | 1.0      | True      | defender  |
| T1057      | Process Discovery            | not_detected   | 1.0      | True      | defender  |
| T1218.010  | Regsvr32 (LOLBin)            | not_detected   | 1.0      | True      | defender  |

All three → **not_detected**, exactly as expected.

## Notes
- The single `defender_events=1` per technique is **event_id 5013** (Tamper Protection blocked a
  `DisableRealtimeMonitoring` attempt originating from `reset.ps1`). 5013 is **not** a detection
  event (not in `DETECTION_EVENT_IDS`), so the scorer correctly ignored it and scored not_detected.
  This confirms the scorer distinguishes config/tamper telemetry from actual detections.
- **Finding:** T1082, T1057, T1218.010 are a confirmed Defender coverage gap on this build →
  prime candidates for the supplementary YARA/Sigma rule set (Phase 4, M11).
- Minor cleanup (non-blocking): `reset.ps1` generates benign 5013 noise; could be silenced so the
  evidence rows carry no distracting Tamper-Protection events.
