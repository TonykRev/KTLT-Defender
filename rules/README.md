# Supplementary detection rules (M11)

Rules that cover the techniques/samples **Windows Defender missed** in the KTLT-Defender
measurements. Each rule cites the measurement (run_id) that justifies it. Rules are `experimental`
until false-positive–tested against goodware (next step) and validated against the measured samples.

> Scope note: the Axis-B baseline (run_ids 5–8) ran with `cloud_protection=OFF`. A **cloud-ON
> spot-check (run_id 9, evidence 14) confirmed the gaps are real, not a config artifact**: with cloud
> protection demonstrably active (the control technique emitted cloud `2010` events), T1003.001 /
> T1547.001 / T1218.010 still scored not_detected — **delta = 0/3**. ASR rules were deliberately not
> evaluated and are the remaining Defender layer (noted per rule); these rules also stand for
> offline/air-gapped deployments.

## YARA — file/memory samples (Axis A)

| Rule file | Target | Technique | Gap it closes |
|---|---|---|---|
| `yara/ktld_encoded_sample.yar` | `sample_v1.bin` (XOR+Base64-encoded blob on disk) | T1027 | **v1** encoded sample → not_detected by MpCmdRun |
| `yara/ktld_payload_loader.yar` | v0–v3 loader `.exe` (embedded blob + decode routine) | T1027, T1620 | **v3** fileless loader → not_detected (catches it by its dropper) |

Defender **did** catch v0 and v2 (raw sample on disk), so no supplementary YARA rule is needed for
those. The rule files embed only the already-obfuscated blob and ordinary .NET strings, so they do not
themselves trip an AV scan (keeps the repo clean).

## Sigma — behaviour (Axis B)

| Rule file | Technique | Group | Gap it closes |
|---|---|---|---|
| `sigma/ktld_t1082_system_information_discovery.yml` | T1082 | G5 | Discovery → not_detected |
| `sigma/ktld_t1057_process_discovery.yml` | T1057 | G5 | Discovery → not_detected |
| `sigma/ktld_t1218_010_regsvr32_lolbin.yml` | T1218.010 | G5 | LOLBin proxy-exec → not_detected (**cloud delta=0, confirmed**) |
| `sigma/ktld_t1059_003_windows_command_shell.yml` | T1059.003 | G1 | cmd.exe execution → not_detected |
| `sigma/ktld_t1547_001_registry_run_key.yml` | T1547.001 | G4 | Run-key persistence → not_detected (**cloud delta=0, confirmed**) |
| `sigma/ktld_t1053_005_scheduled_task.yml` | T1053.005 | G4 | Scheduled-task persistence → not_detected |
| `sigma/ktld_t1003_001_lsass_memory_access.yml` | T1003.001 | G3 | LSASS dump → not_detected (**misses RTP + cloud + ASR, all confirmed**; primary gap-filler; needs Sysmon EID 10) |

### Not yet covered
- **T1555** (Credentials from Password Stores, G3) — too application-specific for a single generic
  rule; candidate for a targeted rule once the exact store/atomic is fixed.
- **T1562.001** (Impair Defenses, G2) — **Defender WIN**: Tamper Protection blocks the disable attempt
  (verified directly, evidence 17 — RTP never dropped, 5013 at trigger). No supplementary rule needed.
- **T1059.001** (PowerShell, G1) — Defender **detected** it (AMSI), so no rule needed.

## Detection baseline vs. gap (what Defender caught on its own)

| Measured | State | Covered by Defender? |
|---|---|---|
| Axis A v0 / v2 (raw sample on disk) | detected (static) | yes |
| Axis B T1059.001 (PowerShell) | detected (runtime/AMSI) | yes |
| Everything else measured so far | not_detected | **supplementary rules above** |

## Next steps
1. False-positive test: run the YARA set over a goodware corpus and the Sigma set over benign
   process/registry telemetry; record FP counts (report M12).
2. Validate each rule fires on the corresponding measured sample/trace (true-positive check).
3. Fold in G2 and the cloud-ON spot-check results, then finalize the rule set and lift `experimental`.
