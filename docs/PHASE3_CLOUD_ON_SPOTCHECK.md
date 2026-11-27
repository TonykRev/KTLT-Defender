# Phase 3 — Cloud-ON spot-check runbook (delta measurement)

**Purpose.** The cloud-OFF Axis-B baseline (run_ids 5–8) returned 8/9 *not_detected*, including
LSASS dumping (T1003.001) — a technique default Defender catches reliably. That strongly indicates
`cloud_protection=OFF` (MAPS/cloud lookups disabled) is understating Defender below a representative
default install. This spot-check re-runs a focused subset with **cloud-delivered protection enabled**
to quantify what cloud adds, so the report can present both numbers honestly.

**Experimental control.** Change *only* the cloud setting between baseline and this pass
(`MAPSReporting` + `SubmitSamplesConsent`). Leave ASR rules and every other setting untouched, so any
state change is attributable to cloud protection alone. ASR is a separate layer, noted in the report
as future work, not enabled here.

**Environment:** cloud-vm only (invasive techniques in the set). Snapshot must be current before
starting. Samples are standard Atomic Red Team (benign); enabling sample submission sends them to
Microsoft — acceptable on this isolated test VM.

---

## Steps (run on the cloud-vm)

1. **Record the baseline Defender build** (cloud verdicts drift over time, so pin versions):
   ```powershell
   Get-MpComputerStatus | Select-Object AMEngineVersion, AMProductVersion,
       AntivirusSignatureVersion, AntispywareSignatureVersion, IsTamperProtected,
       RealTimeProtectionEnabled, MAPSReporting, SubmitSamplesConsent
   ```
   Save the output to `report/evidence/` (it is part of the measurement's traceability).

2. **Enable cloud-delivered protection** (the only variable changed):
   ```powershell
   Set-MpPreference -MAPSReporting Advanced
   Set-MpPreference -SubmitSamplesConsent SendSafeSamples
   ```
   Confirm with `Get-MpComputerStatus` that `MAPSReporting` is `Advanced` (2) and
   `SubmitSamplesConsent` is `SendSafeSamples` (1). Leave RTP and Tamper Protection ON (unchanged).

3. **Flip the project config flag** so measurement rows are labelled correctly:
   set `environment.cloud_protection: true` in `config.yaml` (revert in step 6).

4. **Run the spot-check plan:**
   ```powershell
   python run_measure.py --plan scenarios/spotcheck/cloud_on_delta.yaml --yes
   ```
   Collect for each technique: state, fidelity, fid_valid, evidence_source, error_message,
   detection_layer, detect_latency_ms, defender_event_ids, trigger outcome. Note the new run_id.

5. **Capture the post-run Defender build again** (signature version may have updated via cloud) and
   verify box stability + `-Cleanup` left no artifacts, same checks as the baseline groups.

6. **REVERT to the reproducible baseline** (restore cloud-OFF so the repo's default config is intact):
   ```powershell
   Set-MpPreference -MAPSReporting Disabled
   Set-MpPreference -SubmitSamplesConsent NeverSend
   ```
   Set `environment.cloud_protection: false` back in `config.yaml`. Confirm with
   `Get-MpComputerStatus`. (If anything about Defender's protection state looks wrong at any point,
   STOP and revert to the VM snapshot.)

---

## Expected delta (hypotheses to confirm)

| Technique  | cloud-OFF baseline | cloud-ON hypothesis | What a change proves |
|------------|--------------------|--------------------|-----------------------|
| T1003.001  | not_detected       | detected (cloud ML) | cloud accounts for LSASS coverage |
| T1547.001  | not_detected       | detected?           | cloud reputation on Run-key persistence |
| T1218.010  | not_detected       | detected?           | cloud-side LOLBin coverage |
| T1059.001  | **detected** (AMSI) | detected (control)  | AMSI is local → unaffected by cloud |

The control (T1059.001) must stay detected; if it flips, something other than cloud changed and the
run is invalid. The delta = (count detected cloud-ON) − (count detected cloud-OFF) over this subset,
which the report expresses as "cloud-delivered protection accounts for N of M techniques in the
spot-check."
