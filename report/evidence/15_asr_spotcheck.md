# Evidence 15 — ASR spot-check (LSASS layer test) — completes the layer picture

**Date:** 2026-11-27
**Environment:** cloud-vm; **only** the lsass ASR rule enabled (Block), cloud left OFF to isolate ASR;
RTP + Tamper Protection ON (unchanged). **Code:** HEAD = 5771678 · **run_id:** 10 · Tests 57 OK (3 skipped).
Procedure: `docs/PHASE3_ASR_SPOTCHECK.md`.

## Config applied (confirmed)
- Baseline ASR: **empty** (no rules configured) — the consumer default.
- Enabled: ASR rule `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` ("Block credential stealing from lsass.exe"),
  Action = **1 (Block)**. Cloud OFF (MAPSReporting=0), unchanged.

## Result — T1003.001 (LSASS)

| Config tested | State | ASR event (1121/1122) | run_id |
|---|---|---|---|
| RTP, cloud OFF | not_detected | — | 8 |
| RTP, cloud ON | not_detected | — | 9 |
| **RTP + ASR (Block)** | **not_detected** | **none (1121 absent)** | 10 |

The ASR rule did **not** fire (no 1121 block, no 1122 audit); only the usual 5013 reset noise. The
atomic ran 4.1 s clean. **All three Defender layers miss this atomic variant of T1003.001.**

## Interpretation (Chapter 4)
The LSASS gap is not closed by signatures, cloud, *or* the dedicated ASR rule for this specific
Atomic test. → The supplementary **Sigma rule (Sysmon EID 10, ProcessAccess on lsass.exe)** is the
**primary** gap-filler for this case; ASR/cloud are not sufficient alone here. This is exactly the
kind of coverage gap the project's supplementary rule set is meant to address.

## Honest caveats (threats to validity — for the report)
1. **Atomic-variant specific.** This is Invoke-AtomicTest **T1003.001 test #1 only** (likely a
   comsvcs/procdump-style dump with signed binaries). Other T1003.001 tests may be caught; the claim
   is scoped to this variant. Testing more test numbers is clear future work.
2. **Execution vs. effect.** Our fidelity signal confirms the atomic *ran* (exit ok + output), not
   that the malicious *effect* (an actual LSASS memory read/dump) occurred. For full rigor the LSASS
   runs should also confirm the dump artifact was produced; this is a general limitation of all
   behaviour-axis measurements, noted once here. If the prerequisite tool was missing, "not detected"
   would be weaker — worth a re-run with GetPrereqs confirmed.
3. **ASR rule not firing is itself notable.** The lsass ASR rule is usually effective against common
   dump methods; its silence here supports caveat 1 (the atomic's method/path is outside the rule's
   scope, or the effect did not occur).

## Layer picture — now complete
| Technique | Signature/RTP | Cloud | ASR | Covered? |
|---|---|---|---|---|
| T1059.001 (PowerShell) | — | — | — | **yes** via AMSI (local, runtime) |
| T1003.001 (LSASS, test#1) | miss | miss | miss | **no** → supplementary Sigma (Sysmon EID10) |

Box stable post-run, ASR reverted to empty (exact baseline match). G2 (defense evasion) remains the
last Axis-B group — user-driven.
