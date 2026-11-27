# Phase 3 — ASR spot-check runbook (LSASS layer test)

**Purpose.** The LSASS gap (T1003.001) persisted at both cloud-OFF (run_id 8) and cloud-ON (run_id 9).
The remaining untested Defender layer is **Attack Surface Reduction (ASR)**. This run enables **only**
the ASR rule *"Block credential stealing from the Windows local security authority subsystem
(lsass.exe)"* and re-runs T1003.001, to see whether ASR closes the gap — completing the
"which layer catches what" picture for Chapter 4.

**Experimental control.** Change *only* the one ASR rule. Leave cloud protection OFF (its delta was
already measured as 0) so any change is attributable to ASR alone. ASR is an enterprise-oriented
hardening layer, not on by default on consumer Windows — the report frames it as a mitigation
recommendation, not the default posture.

**ASR rule GUID:** `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2`

**Scorer readiness:** an ASR block emits Defender Operational event **1121**, which is already in the
scorer's `BEHAVIOR_EVENT_IDS`; `_infer_layer` maps "attack surface reduction" text to layer **asr**.
So a block will score `detected` / layer `asr` with no code change. (Audit mode emits **1122**, which
is NOT a block and NOT in the detection set — use Block mode for a real detection.)

**Environment:** cloud-vm only; snapshot current; RTP + Tamper Protection ON (unchanged).

---

## Steps (run on the cloud-vm)

1. `git pull origin main`, then `python -m unittest -v` (expect all tests OK).

2. Record the baseline ASR state (to restore exactly):
   ```powershell
   Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
   Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions
   ```
   Save the output.

3. Enable ONLY the lsass ASR rule in **Block** mode (strengthening Defender; nothing else changed):
   ```powershell
   Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 `
                    -AttackSurfaceReductionRules_Actions Enabled
   ```
   Confirm the rule shows Id `9e6c4e1f...` with Action `1` (Enabled/Block) via the Get-MpPreference
   lines above. Leave cloud OFF and leave every other ASR rule as-is.

4. Run the ASR plan:
   ```powershell
   python run_measure.py --plan scenarios/spotcheck/asr_lsass.yaml --yes
   ```
   Capture: state, fidelity, detection_layer, detect_latency_ms, defender_event_ids (look for **1121**),
   trigger outcome, new run_id.

5. Verify box stability + `-Cleanup`, same as the other invasive runs.

6. **REVERT** — remove the ASR rule so the baseline config is restored:
   ```powershell
   Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 `
                    -AttackSurfaceReductionRules_Actions Disabled
   # or, if the rule was absent at baseline, remove the entry entirely:
   # Remove-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2
   ```
   Confirm the ASR Ids/Actions match the step-2 baseline. (If anything looks off, revert to snapshot.)

---

## Expected outcome (hypothesis)

| Technique  | Baseline | cloud-ON | ASR-ON hypothesis |
|------------|----------|----------|-------------------|
| T1003.001  | not_detected | not_detected | **detected (layer=asr, event 1121)** if ASR covers this method |

- If **detected** → ASR is the layer that closes the LSASS gap; Chapter 4 recommends enabling this ASR
  rule, and the LSASS supplementary Sigma rule becomes a defence-in-depth backup.
- If **still not_detected** → even ASR misses this atomic variant; the supplementary Sigma rule
  (Sysmon EID 10 on lsass access) is the primary gap-filler. Either result is a clean finding.
