# Mitigation mapping (Chapter 4 / recommendations)

For each measured technique: the Defender layer that stopped it (if any), the relevant Attack Surface
Reduction (ASR) rule and MITRE ATT&CK mitigation, and the supplementary KTLT rule that fills the gap.
Grounded in the validated measurements (evidence 09-18); see `rules/README.md` for the rules.

## Legend
- **Layer** = the Defender component that produced (or could produce) the detection.
- **ASR** = a Microsoft Defender Attack Surface Reduction rule covering the technique (enterprise
  hardening, off by default on consumer Windows).
- **Supplementary** = the KTLT YARA/Sigma rule that closes the measured gap.

## Behavioural techniques (Axis B)

| Technique | Measured | Defender layer | ASR rule (GUID) | MITRE mitigation | Supplementary rule | Recommendation |
|---|---|---|---|---|---|---|
| T1059.001 PowerShell (Mimikatz) | **detected** | AMSI (runtime) | - | M1049 Antivirus/AMSI | - (covered) | Keep AMSI + script logging on |
| T1562.001 Impair Defenses | **blocked** | Tamper Protection | - | M1024 Restrict Registry / Tamper Protection | - (covered) | Keep Tamper Protection ON |
| T1003.001 LSASS dump | not_detected | (none; ASR tested, missed) | **9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2** (Block credential stealing from lsass.exe) | M1043 Credential Access Protection | `ktld_t1003_001_lsass_memory_access` (Sysmon EID 10) | Enable the lsass ASR rule **and** deploy the Sigma rule (ASR missed this variant) |
| T1547.001 Registry Run Key | not_detected | - | - (no dedicated ASR) | M1028 OS Config / detect | `ktld_t1547_001_registry_run_key` | Deploy Sigma; monitor Run/RunOnce writes |
| T1053.005 Scheduled Task | not_detected | - | - | M1028 OS Config / detect | `ktld_t1053_005_scheduled_task` | Deploy Sigma; audit task creation (EID 4698) |
| T1218.010 Regsvr32 LOLBin | not_detected | - | - (WDAC/AppLocker instead) | M1042 Disable/Remove Feature | `ktld_t1218_010_regsvr32_lolbin` | Deploy Sigma; consider WDAC to block scrobj |
| T1059.003 Windows cmd | not_detected | - | - | M1038 Exec Prevention | `ktld_t1059_003_windows_command_shell` | Deploy Sigma; command-line auditing |
| T1082 System Info Discovery | not_detected | - | - (no effective prevention) | detect-only | `ktld_t1082_system_information_discovery` | Detection only; benign LOLBins can't be blocked |
| T1057 Process Discovery | not_detected | - | - | detect-only | `ktld_t1057_process_discovery` | Detection only |
| T1555 Credentials from Password Stores | not_detected | - | - | M1027 Password Policies | (candidate; app-specific) | Detect store access; harden app vaults |
| T1140 Deobfuscate/Decode | not_detected | - | - | detect-only | (candidate) | Detection via content/behaviour correlation |

## Static/memory variants (Axis A)

| Variant | Measured | Defender layer | Supplementary rule | Recommendation |
|---|---|---|---|---|
| v0 raw sample on disk | detected | signature (static) | - (covered) | - |
| v1 encoded sample on disk | not_detected | - | `KTLD_Encoded_Sample_On_Disk` (YARA) | Deploy YARA on the file store |
| v2 decoded-to-disk | detected | signature/RTP (on-write) | - (covered) | - |
| v3 in-memory / fileless | not_detected | - | `KTLD_Payload_Loader_Binary` (YARA) | Deploy YARA on the loader/dropper |

## Summary of Defender's working layers vs. gaps
- **Working:** AMSI (script content - caught Mimikatz), Tamper Protection (self-defence - blocked the
  disable attempt), and the signature engine on **raw** on-disk samples (v0/v2).
- **Gaps:** behavioural techniques with no AMSI/signature/Tamper hook (discovery, LOLBins, persistence,
  LSASS dump, deobfuscation) and obfuscated/fileless payloads (v1/v3). Cloud-delivered protection
  (delta 0/3) and the lsass ASR rule (for T1003.001 test#1) did **not** close these in our tests.
- **Fill:** the KTLT supplementary rule set (2 YARA + 7 Sigma), FP-validated on YARA (0 / 12,450
  goodware files), plus the enterprise hardening (ASR, WDAC, command-line/task auditing) noted above.
