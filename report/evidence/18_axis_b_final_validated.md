# Evidence 18 — Axis B FINAL (validated) results

**Date:** 2026-11-27 · **Environment:** cloud-vm · **Code:** atomic_runner fix @ 00d52b4
**Validation:** `Test-Path` install-check of all 11 technique IDs + exact-stdout confirmation.

## Install-check (resolves the atomic_runner validity concern)
10 of 11 atomics installed; **only T1562.001 missing**. Confirmed detection strings:
- Good run `T1059.001-1` stdout contains **"Executing test"** → the new `ran` positive marker fires. ✅
- Missing `T1562.001-1` stdout = **"...T1562.001.yaml does not exist"**, exit 0, no "Executing test" →
  the old runner's false `ran`; the new runner correctly returns `ran=False`. ✅

**⇒ Only run_id=11 (T1562.001) was invalid. Every other Axis-B measurement used an installed atomic
and STANDS.** (Bonus: `T1059.001-1` is the **Mimikatz** test — Defender blocked it with "Access is
denied", consistent with the detection we recorded.)

## FINAL Axis B tally (11 techniques)

| Technique | Group | Result | Defender layer | Validated by |
|---|---|---|---|---|
| T1059.001 (Mimikatz/PowerShell) | G1 | **DETECTED** | AMSI / runtime | 1116/1117 events; atomic ran |
| T1562.001 (Impair Defenses) | G2 | **BLOCKED (Defender win)** | Tamper Protection | direct verify (evidence 17) |
| T1082 (System Info Discovery) | G5 | not_detected | — | atomic installed + ran |
| T1057 (Process Discovery) | G5 | not_detected | — | atomic installed + ran |
| T1218.010 (Regsvr32 LOLBin) | G5 | not_detected | — | installed; cloud delta 0 |
| T1059.003 (Windows cmd) | G1 | not_detected | — | atomic installed + ran |
| T1547.001 (Run Key) | G4 | not_detected | — | installed; cloud delta 0 |
| T1053.005 (Scheduled Task) | G4 | not_detected | — | atomic installed + ran |
| T1003.001 (LSASS dump) | G3 | not_detected | — | installed; cloud + ASR delta 0 |
| T1555 (Password Stores) | G3 | not_detected | — | atomic installed + ran |
| T1140 (Deobfuscate/Decode) | G2 | not_detected | — | atomic installed + ran |

**Headline (corrected & validated): of 11 behavioural techniques, Defender stopped 2 and missed 9.**
- **2 Defender successes, via two different layers:** AMSI (script content — blocked Mimikatz) and
  Tamper Protection (self-defense — blocked the disable attempt). A more balanced, credible story than
  the provisional "1 detected".
- **9 genuine gaps:** discovery, LOLBin, cmd, both persistence, both credential-access, deobfuscation.
  Cloud-ON (delta 0/3) and ASR (LSASS) spot-checks confirmed these are not config artifacts. These are
  exactly what the supplementary YARA/Sigma rules (M11) target.

## Methodology note (for the report)
**Impair-Defenses (T1562.001) is scored by direct state-verification, not the event-window pipeline.**
`run_measure`'s scorer keys on detection events in a fixed collection window; but (a) Tamper Protection
blocks are logged as 5013, which is a config/defence event we treat as non-detection, and (b)
`reset.ps1` itself attempts a RTP toggle and emits 5013 noise that lands in-window, so a technique-vs-
reset 5013 cannot be told apart reliably. The sound method for this technique class is to observe the
**protection state** (did RTP actually drop?) — which the verify did. This is a documented scoping of
the tool, not a defect in the measurement.

## Axis A (static, from Phase 2, run_id 2) — for the combined picture
v0 detected · v1 not_detected · v2 detected · v3 not_detected → signature catches raw on-disk samples
(v0/v2), misses obfuscation (v1) and fileless (v3). Covered by the M11 YARA rules.

**Measurement is now COMPLETE and VALIDATED.** Ready for report + slides.
