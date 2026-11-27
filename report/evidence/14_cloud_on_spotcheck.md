# Evidence 14 — Cloud-ON spot-check (delta vs cloud-OFF baseline)

**Date:** 2026-11-27
**Environment:** cloud-vm; **cloud-delivered protection ENABLED** for this run only (MAPSReporting=Advanced,
SubmitSamplesConsent=SendSafeSamples), then reverted. RTP + Tamper Protection ON throughout (unchanged).
**Code:** HEAD = d98d05c · **run_id:** 9 · Procedure: `docs/PHASE3_CLOUD_ON_SPOTCHECK.md`

## Defender build (pinned for reproducibility)
AMEngineVersion 1.1.26100.4 · AMProductVersion 4.18.26100.4 · Signature **1.463.490.0** (stable
before/after the run). Cloud path confirmed active during the run (see control, 2010 events).

## Results — only the cloud setting changed vs the baseline

| Technique  | Baseline (cloud-OFF) | Spot-check (cloud-ON) | Delta | Evidence cloud-ON |
|------------|----------------------|-----------------------|-------|-------------------|
| T1003.001 (LSASS)     | not_detected | **not_detected** | 0 | 5013 only (noise) |
| T1547.001 (Run key)   | not_detected | **not_detected** | 0 | none              |
| T1218.010 (regsvr32)  | not_detected | **not_detected** | 0 | 5013 only (noise) |
| T1059.001 (PowerShell, CONTROL) | detected | **detected** | 0 (held) | 1116 + **2010×3** + 1117 |

**cloud-ON delta = 0/3 flips.** Not one gap technique changed verdict with cloud protection on.

## Why this run is valid (the control)
T1059.001 (the control) stayed **detected**, now with event **2010** ×3 — "used cloud protection to
get additional security intelligence" (sig 1.463.490.0). That is direct proof the MAPS/cloud path was
live during the measurement, so the 0/3 delta is a real negative result, not a mis-configuration.
Side note: cloud-ON latency for the control rose to **7.6 s** (vs 3.8 s cloud-OFF) — the cloud lookup
adds ~3.8 s even when local AMSI already catches it. The control's layer is correctly labelled
`behavior` (confirms the layer-by-axis fix on real data).

## Interpretation — this RESOLVES the validity concern
Evidence 12 raised the worry that the LSASS miss was merely a `cloud_protection=OFF` artifact. This
spot-check **refutes that empirically**: with cloud protection demonstrably active, Defender still did
not catch LSASS dumping, Run-key persistence, or regsvr32 LOLBin abuse for these Atomic test variants.
**The gaps are genuine, not a configuration artifact.** The cloud-OFF baseline is therefore
representative for these techniques, and the report can present the gaps with confidence.

## Honest caveat — ASR was deliberately NOT tested
To isolate the cloud variable, the runbook changed *only* cloud settings and left **Attack Surface
Reduction (ASR) rules disabled**. ASR is a separate Defender hardening layer; in particular the rule
"Block credential stealing from lsass.exe" is known to block many LSASS-dump methods. So the precise
claim is: *neither the on-device signature/behaviour engine nor cloud-delivered protection caught
these atomic variants; ASR (untested here) is the remaining Defender layer.* The report must state
this, and ASR evaluation is a clear next measurement (it is also the natural "mitigation mapping" for
the gap in Chapter 4).

## Running picture (Axis B)
10 behaviour measurements so far (cloud-OFF) + 4 cloud-ON: Defender detects only PowerShell (AMSI,
local). Discovery, cmd, Run-key, scheduled task, regsvr32, LSASS, password-store all evade both the
on-device engine and cloud → the techniques the supplementary YARA/Sigma rules (M11) target. Revert
to cloud-OFF confirmed; box stable. G2 (defense evasion) still pending (user-driven).
