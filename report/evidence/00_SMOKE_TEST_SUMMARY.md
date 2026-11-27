# Smoke Test — End-to-End Validation (Phase 2)

**Date:** 2026-11-27 (local, Asia/Ho_Chi_Minh)
**Machine:** dev-win11 (`machine_label=dev-win11`), Windows 11 Home SL 10.0.26200
**Defender:** RTP enabled, AntivirusSignatureVersion `1.463.485.0`, Engine `1.1.26100.4`
**Tool commit:** `641db24`
**Command:** `python run_measure.py --static --variants v0,v2 --yes`

## Goal
Validate that the full `run_measure.py` (M10) orchestration loop runs end-to-end on the
dev machine: **reset → build → detonate → static scan → collect logs → fidelity → score → write DB.**
Axis A static variants v0 and v2 drop a *benign EICAR* sample to disk; Defender's reaction
is the measurement.

## Result — PASS ✅

| # | Variant | State | Detection layer | Threat name | Fidelity | Evidence source |
|---|---------|-------|-----------------|-------------|----------|-----------------|
| 1 | v0 | **detected** | static | `Virus:DOS/EICAR_Test_File` | 1.0 (valid) | MpCmdRun scan (rc=2) |
| 2 | v2 | **detected** | static | `Virus:DOS/EICAR_Test_File` | 1.0 (valid) | MpCmdRun scan (rc=2) |

- `run_id=1`, summary `{'detected': 2}`.
- The orchestration loop executed cleanly with no errors; both measurements scored `detected`
  with full fidelity (1.0). SQLite DB written to `db/results.sqlite`.

## Key finding (important for Phase 3 methodology)

Detection on this dev machine came **entirely from the on-demand signature scan**
(`MpCmdRun -Scan -ScanType 3 -DisableRemediation`, exit code 2 = threat found,
threat `Virus:DOS/EICAR_Test_File`). However:

- **No Windows Defender Operational-log detection events** (1006/1116/1117/1118) were produced
  during the runs → `defender_events_json = 0`, `evidence_source = none`. The last Operational
  events were only routine health reports (1150/1151).
- **RTP did not auto-quarantine** the dropped benign EICAR: `sample_v2.bin` (68 B, raw EICAR)
  remained on disk after the run, even though `DisableRealtimeMonitoring = False`.
- Defender exclusion lists could not be read (requires an elevated/admin shell), so a path
  exclusion on the user/project folder cannot be ruled out on this dev box.

**Why:** `-DisableRemediation` makes the scan *detect-only* (no "action taken" → no 1116/1117
telemetry), and RTP evidently did not scan-on-write the dropped sample within the 20 s collect
window. The scorer correctly fell back to the static scan result → `detected`.

**Implication for the real Chapter 4 measurement (cloud-vm):**
1. Run on the clean, **admin**, network-isolated VM snapshot (no inherited exclusions).
2. For the RTP layer, also measure **without** `-DisableRemediation` so Defender quarantines
   and emits 1116/1117 → richer `evidence_source` than the static scan alone.
3. Verify `Get-MpPreference` exclusions are empty before the official run.

## Conclusion
Phase 2 integration is **validated**: `run_measure.py` (M10) correctly drives the entire
measurement pipeline, scores one of the four states, and persists traceable results. The dev
run confirms the signature layer catches EICAR; the cloud-vm run will additionally exercise the
RTP/behavior layers.

## Evidence files (this folder)
- `01_environment.txt` — host + Defender + toolchain snapshot
- `02_payload_build.txt` — payload SHA-256 + sizes (clean compile)
- `03_dryrun.txt` — safe dry-run matrix
- `04_live_run.txt` — live run console output
- `05_db_measurements.txt` — DB runs + measurements dump
- `06_defender_evidence.txt` — Operational-log + RTP/exclusion check
