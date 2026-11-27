# Evidence 11 — G4 Persistence group on cloud-vm (both missed)

**Date:** 2026-11-27
**Environment:** cloud-vm (Azure Win11 Pro Insider b26300), RTP ON, TamperProtection ON, **cloud_protection OFF**
**Code:** HEAD = e705ea0
**run_id:** 7
**Unit tests:** 47/47 OK
**Invasive group:** yes (allowed only because machine_label=cloud-vm)

## Results (G4 — Persistence, both invasive, both ran)

| Technique  | Name                      | Expectation      | State          | Fidelity | Layer | Defender events |
|------------|---------------------------|------------------|----------------|----------|-------|-----------------|
| T1547.001  | Registry Run Key          | likely_detected  | **not_detected** | 1.0    | —     | 5013 (noise)    |
| T1053.005  | Scheduled Task            | likely_missed    | **not_detected** | 1.0    | —     | 5013 (noise)    |

- **T1547.001 → not_detected (UNEXPECTED).** The scenario guessed "often caught", but Defender did
  not alert on the HKCU `...\Run` key write. No 1116/1117/1015/1119 in the window. The only Defender
  event is 5013 (Tamper-Protection reset.ps1 noise), correctly ignored. **Real gap** — a benign Run
  key write is not flagged on its own → strong candidate for a Sigma rule watching HKCU Run-key
  creation/modification.
- **T1053.005 → not_detected (expected).** Benign scheduled task created without an alert. Second
  persistence gap.
- Error-vs-detection edge case: **not triggered** (no detection events existed to mis-score).

## Cleanup verification (reversibility of invasive run)
Atomic `-Cleanup` confirmed clean afterwards:
- HKCU `...\Run`: only OneDrive + Edge entries; no atomic artifacts.
- Non-Microsoft scheduled tasks: only OneDrive + Edge update tasks; no atomic artifacts.
Box returned to a clean state before the next group. (Snapshot remains the hard revert point.)

## ⚠ Methodology caveat — cloud-delivered protection is OFF
`config.yaml` has `cloud_protection=false` on this VM, so MAPS / cloud lookups are disabled and these
are **on-box (local-engine) detection results**: signatures + AMSI + behavior monitoring, without
cloud-delivered protection or sample submission. This is a deliberate, defensible scoping choice —
it makes results **reproducible** (cloud verdicts drift over time and would make grading
non-repeatable) and avoids submitting samples to Microsoft. But it may **understate** Defender:
some techniques that miss here (e.g. the Run-key write) could be caught by cloud heuristics on a
default consumer machine. The report must state this explicitly as a limitation, and framing the
study as an evaluation of **Defender's on-box engine** keeps every "not_detected" result honest.
Optional future work: a cloud-ON spot-check of the gap techniques to quantify the delta.

## Running tally (Axis B)
| Group | Technique  | State          | Note                         |
|-------|------------|----------------|------------------------------|
| G5    | T1082      | not_detected   | discovery gap                |
| G5    | T1057      | not_detected   | discovery gap                |
| G5    | T1218.010  | not_detected   | LOLBin gap                   |
| G1    | T1059.001  | **detected**   | PowerShell/AMSI, 3.8 s       |
| G1    | T1059.003  | not_detected   | cmd gap                      |
| G4    | T1547.001  | not_detected   | Run key gap (unexpected)     |
| G4    | T1053.005  | not_detected   | scheduled-task gap           |

7 measurements: 1 detected, 6 not_detected. All local-engine (cloud off).
