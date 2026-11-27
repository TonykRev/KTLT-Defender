# Evidence 16 — G2 Defense Evasion (final Axis-B group) + Axis-B complete

**Date:** 2026-11-27
**Environment:** cloud-vm, cloud OFF, RTP + Tamper Protection ON. **Code:** HEAD = 5771678 · **run_id:** 11
**Invasive group:** yes. Run was **user-driven** (the on-prem session is blocked by its safety
classifier from relaying a disable-Defender instruction).

## Results (G2)

| Technique  | Name                       | Expectation      | State          | Defender events |
|------------|----------------------------|------------------|----------------|-----------------|
| T1562.001  | Impair Defenses (disable)  | likely_detected  | not_detected*  | **none** (no 5013) |
| T1140      | Deobfuscate/Decode         | likely_missed    | not_detected   | 5013 (reset noise) |

- **T1140 → not_detected (expected).** Only the usual reset.ps1 5013 noise; a clean behavioural gap.

## *T1562.001 — AMBIGUOUS, do NOT read as a clean "Defender miss"
The tool scored not_detected because **no detection event landed in the collection window** — and
unusually, not even a 5013. But Tamper Protection is demonstrably **ON** (every other run's reset step
reliably emits a 5013). So the most likely truth is that the disable-Defender attempt was **blocked by
Tamper Protection**, i.e. **Defender defended successfully**, but the block either:
  (a) occurred at a kernel/Tamper layer that did not emit an in-window Operational 5013, or
  (b) emitted a 5013 just outside the `[trigger_started, collect_until]` window.

Either way, "not_detected per logs" here **under-credits Defender** and must not be reported as
"Defender failed to detect an attempt to disable it." **Verification needed** (user-driven, since the
on-prem session is classifier-blocked for this technique): re-run T1562.001 and capture
`Get-MpComputerStatus.RealTimeProtectionEnabled` *immediately after* the trigger —
  - RTP still **True** → Tamper Protection blocked it → this is a **Defender WIN** (credit as a block),
  - RTP flipped **False** → a real evasion success → not_detected stands and is a serious gap.
This is a tool limitation worth noting: for T1562.001 the right evidence is the **post-technique
protection state**, which run_measure does not currently capture (candidate enhancement).

## AXIS B — COMPLETE (all 5 groups + 2 spot-checks)

| Group / run | Technique | State |
|---|---|---|
| G5 (5) | T1082 / T1057 / T1218.010 | not_detected ×3 |
| G1 (6) | T1059.001 | **detected** (AMSI, runtime) |
| G1 (6) | T1059.003 | not_detected |
| G4 (7) | T1547.001 / T1053.005 | not_detected ×2 |
| G3 (8) | T1003.001 / T1555 | not_detected ×2 |
| G2 (11) | T1562.001* / T1140 | not_detected ×2 (*ambiguous — see above) |
| Cloud-ON spot-check (9) | T1003.001 / T1547.001 / T1218.010 | not_detected (control T1059.001 detected ✅) |
| ASR spot-check (10) | T1003.001 | not_detected |

**Headline (Axis B): 1 detected / 9 not_detected across 10 behavioural techniques.** The single
detection is PowerShell via **AMSI** (local/runtime). Cloud (delta 0/3) and ASR (LSASS) were verified
not to close the gaps. All runs fidelity=1.0, boxes reverted and stable.

### Framing guard for the report (so the finding survives review)
- Scoped to **Atomic test #1** of each technique; other test numbers may differ.
- The config is a **default-ish consumer posture** (RTP on; cloud/ASR measured separately, off by
  default); spot-checks show cloud/ASR do not help for the tested variants.
- **T1562.001 is ambiguous** and most likely a Defender win (Tamper Protection) — exclude it from any
  "miss" headline until RTP-state-verified.
- Fidelity confirms each atomic **ran**, not that the malicious **effect** occurred (general caveat).

## Measurement status
**Phase 3 measurement is COMPLETE.** Remaining Phase 4: optional T1562.001 RTP-state verification,
Sigma true/false-positive validation (limited — Sysmon is unavailable on this VM, image-level bug),
ASR/mitigation mapping table, then report + slides.
