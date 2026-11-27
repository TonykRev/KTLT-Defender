# Evidence 10 — G1 Execution group on cloud-vm (detection baseline + gap)

**Date:** 2026-11-27
**Environment:** cloud-vm (Azure Win11 Pro Insider b26300), RTP ON, TamperProtection ON, cloud_protection OFF
**Code:** HEAD = 9855a79 at run time (layer heuristic refined afterwards — see note)
**run_id:** 6
**Unit tests:** 45/45 at run time (47/47 after the layer refinement below)

## Results (G1 — Execution, both non-invasive, both actually ran)

| Technique  | Name                  | Expectation      | State          | Fidelity | Layer    | Latency  | Defender events        |
|------------|-----------------------|------------------|----------------|----------|----------|----------|------------------------|
| T1059.001  | PowerShell            | likely_detected  | **detected**   | 1.0      | runtime* | 3804 ms  | 5013, **1116, 1117**   |
| T1059.003  | Windows Command Shell | likely_missed    | **not_detected** | 1.0    | —        | —        | (none)                 |

- **T1059.001 → detected** in 3.8 s. Events: 1116 (malware detected, realtime) @ 05:14:36.693Z,
  1117 (countermeasure action taken) @ 05:14:51.663Z. The 5013 @ 05:14:32.771Z is the usual
  Tamper-Protection reset.ps1 noise, correctly ignored by the scorer. **Defender baseline confirmed.**
- **T1059.003 → not_detected**, zero Defender events. Clean gap case — a second candidate for the
  supplementary rule set.

## Edge case checked (and NOT triggered)
Pre-run concern: if AMSI *blocks* the PowerShell atomic, the runner could report it as not-run
(exit_ok=False) → had_error=True → scorer returns "error" on step 1 before it ever inspects the
detection events, mis-scoring a genuine catch. **This did not fire.** The atomic ran far enough to
trigger Defender; the scorer reached step 3b (detection events present) and returned `detected`
before the had_error gate. No workaround needed; noted as still-latent and worth a defensive guard
if ever observed on an invasive group.

## *Layer attribution refinement (post-run, committed next)
The scorer initially labelled T1059.001 `detection_layer="static"` because 1116/1117 are
signature-class event IDs. That is wrong here: 1116/1117 are generic "malware detected / action
taken" records emitted for file scans AND live (RTP/AMSI) catches alike, and **on the behaviour axis
no on-demand file scan is run**, so the catch is necessarily a runtime one. `_infer_layer` now falls
back on the measurement axis: a signature-class detection on the behaviour axis is reported as
`behavior` (runtime), reserving `static` for the Axis-A file-scan path and for events whose text
names an on-demand scan. The *state* (detected) and *latency* (3.8 s) were already correct; only the
layer label changes. The PowerShell catch is specifically AMSI; distinguishing AMSI from generic
behaviour-monitoring needs the event's Detection Source field, noted as a report caveat.

## Running tally (Axis B)
| Group | Technique  | State          |
|-------|------------|----------------|
| G5    | T1082      | not_detected   |
| G5    | T1057      | not_detected   |
| G5    | T1218.010  | not_detected   |
| G1    | T1059.001  | **detected**   |
| G1    | T1059.003  | not_detected   |

First confirmed Defender detection of the study (T1059.001, runtime/AMSI, 3.8 s).
