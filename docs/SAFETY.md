# Safety Boundary & Scope (READ BEFORE RUNNING)

This project triggers standardized attack techniques (Invoke-AtomicRedTeam) **only for measurement**, to see whether Defender
detects them. Self-written payloads are **harmless** (benign) — they carry only strings/behavior that "look like malware"
so the scanning layer can be measured, and they do not cause real harm.

## Two environments — strictly separated

### 🟢 DEV machine (this personal Windows 11) — ONLY:
- Write code, compile the 4 C# payloads, write YARA/Sigma rules.
- **Smoke test**: code runs, real logs can be parsed, DB writes work, scoring is correct.
- **Static measurement axis**: scan payload files with MpCmdRun (harmless — it only scans files on disk).
- (Optional) 1–2 harmless Atomic discovery tests (T1082, T1057) to test the log collection pipeline.

### 🔴 NOT to run on the DEV machine — reserved for the CLOUD VM:
- Real invasive techniques: LSASS dump (T1003), disabling Defender/tools (T1562), AMSI bypass,
  persistence (Run key / scheduled task — T1547, T1053), credential access (T1555).
- Reasons: (a) Defender blocking/quarantining disrupts development; (b) **real modifications** to the registry/services of the main machine; (c) they contaminate the measurement data.

## Golden rule
**All OFFICIAL NUMBERS for Chapter 4 are taken on the CLOUD VM** — a network-isolated environment with
a pinned Defender version and a clean snapshot to restore. The dev machine is only for *building carefully*.

## When running on the cloud VM
- Network-isolate the VM (do not let it spread outward).
- `machine_label: cloud-vm` in config; record the Defender signature version in the `runs` table.
- Clean snapshot before measuring; soft-reset between runs; full snapshot restore when the environment breaks.
- Clean up samples + quarantine after each measurement.
