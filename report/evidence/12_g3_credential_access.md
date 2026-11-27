# Evidence 12 — G3 Credential Access on cloud-vm (LSASS missed — cloud-off signal)

**Date:** 2026-11-27
**Environment:** cloud-vm (Azure Win11 Pro Insider b26300), RTP ON, TamperProtection ON, **cloud_protection OFF**
**Code:** HEAD = 8b91325 (block-is-detection fix in place)
**run_id:** 8
**Unit tests:** 53/53 OK
**Invasive group:** yes (most sensitive — LSASS access)

## Results (G3 — Credential Access, both invasive, both ran)

| Technique  | Name                         | Expectation      | State          | Fidelity | Defender events | Trigger |
|------------|------------------------------|------------------|----------------|----------|-----------------|---------|
| T1003.001  | OS Cred Dumping — LSASS      | likely_detected  | **not_detected** | 1.0    | 5013 (noise)    | ran 3.3s |
| T1555      | Credentials from Pwd Stores  | likely_missed    | **not_detected** | 1.0    | (none)          | ran 3.4s |

- **T1003.001 (LSASS) → not_detected (UNEXPECTED, and significant).** The atomic ran to completion
  in 3.3 s; Defender neither blocked nor passively detected it. The only Defender event is 5013
  (reset.ps1 Tamper-Protection noise), correctly ignored. **Defender did not fire at all.**
- **T1555 → not_detected (expected).** Zero Defender events.

## Block-is-detection fix — diagnostic
The fix shipped in 8b91325 was built for the case where Defender BLOCKS the LSASS atomic (trigger
fails) yet emits detection events. **That path did NOT trigger here:** the atomic ran cleanly
(ran=True, exit_ok=True, no stderr), so there was no trigger failure to reconcile and no detection
event to promote. The fix was not exercised by real data this run, but remains correct and
regression-tested (53 tests) for any invasive technique Defender does block. No mis-scoring occurred.

## ⚠ This is now a validity signal, not just a caveat
Default Windows Defender detects LSASS memory dumping reliably — it is one of the most heavily
covered techniques (behavioral ML + ASR rule "Block credential stealing from lsass.exe"). The miss
here is almost certainly because **cloud-delivered protection is OFF**: Defender's LSASS behavioral
protection leans heavily on cloud ML / reputation lookups, and the ASR credential-theft rule is not
enabled on this box. With cloud off, the on-device signature/behavior engine has no coverage for raw
LSASS reads.

Running tally makes the pattern clear — **8 of 9 measurements missed; the only detection is local
AMSI (PowerShell):**

| Group | Technique  | State          | Layer         |
|-------|------------|----------------|---------------|
| G5    | T1082      | not_detected   | —             |
| G5    | T1057      | not_detected   | —             |
| G5    | T1218.010  | not_detected   | —             |
| G1    | T1059.001  | **detected**   | runtime/AMSI  |
| G1    | T1059.003  | not_detected   | —             |
| G4    | T1547.001  | not_detected   | —             |
| G4    | T1053.005  | not_detected   | —             |
| G3    | T1003.001  | not_detected   | —             |
| G3    | T1555      | not_detected   | —             |

AMSI is a local layer, so it fires regardless of cloud state — which is exactly why it is the lone
detection. **Interpretation:** these results characterise Defender's *on-box / offline* engine, not
a default consumer Defender. Reporting "Defender misses LSASS dumping" without this context would be
invalid and would not survive review.

## Decision needed before the report (see conversation)
Either (1) keep cloud-OFF and reframe the study explicitly as an **offline-engine** evaluation, or
(2) run a **cloud-ON comparison pass** to quantify what cloud adds and report the delta
(scientifically strongest), or (3) switch cloud-ON as the primary config and re-measure. Cloud-ON
submits samples to Microsoft and is non-reproducible (cloud verdicts drift), so if used it must pin
the exact Defender build + signature version per measurement.

## Box stability (post-LSASS)
lsass.exe healthy (PID 836, responding, ~33 MB, normal CPU); no critical/error events in System or
Application logs in the last 15 min; no atomic artifacts; cleanup verified. Box stable, snapshot
intact.
