# Smoke Test — End-to-End Validation (Phase 2)

**Date:** 2026-11-27 (local, Asia/Ho_Chi_Minh)
**Machine:** dev-win11 (`machine_label=dev-win11`), Windows 11 Home SL 10.0.26200
**Defender:** RTP enabled, AntivirusSignatureVersion `1.463.485.0`, Engine `1.1.26100.4`
**Tool commit:** `b3c4423` (+ follow-up finishing Phase 2)
**Commands:**
- `python run_measure.py --static --variants v0,v2 --yes`  (run_id=1, initial smoke test)
- `python run_measure.py --static --yes`                    (run_id=2, full Axis A, all 4 variants)
- `python run_measure.py --all-behavior --dry-run`          (Axis B matrix validation)

## Goal
Validate that the full `run_measure.py` (M10) orchestration loop runs end-to-end on the
dev machine: **reset → build → detonate → static scan → collect logs → fidelity → score → write DB.**
Axis A static variants drop a *benign EICAR* sample; Defender's reaction is the measurement.

## Result — PASS ✅

### Axis A — static, all 4 variants (run_id=2)

| # | Variant | Behaviour | State | Detection layer | Threat name | Fidelity |
|---|---------|-----------|-------|-----------------|-------------|----------|
| 1 | v0 | bare EICAR written to disk        | **detected** | static | `Virus:DOS/EICAR_Test_File` | 1.0 |
| 2 | v1 | *encoded* EICAR written (never decoded) | **not_detected** | — | — | 1.0 |
| 3 | v2 | decode → disk → execute           | **detected** | static | `Virus:DOS/EICAR_Test_File` | 1.0 |
| 4 | v3 | memory-only (nothing touches disk) | **not_detected** | — | — | 1.0 |

Summary `{'detected': 2, 'not_detected': 2}`. This is the core thesis in one table: the
**signature layer catches on-disk plaintext (v0, v2) but misses obfuscation (v1) and
fileless/in-memory execution (v3)** — exactly the gap the supplementary YARA/Sigma rules
(Phase 4) are meant to close.

### Axis B — behavior, dry-run matrix (11 techniques, G1–G5)
All 5 invasive techniques (`T1562.001`, `T1003.001`, `T1555`, `T1547.001`, `T1053.005`)
were correctly tagged `[WILL BE BLOCKED on dev machine]`; the 6 non-invasive techniques
were listed as runnable. The safety gate (`atomic_runner`) behaves as designed. Live
behavior runs are deferred to the cloud-vm by design (Phase 3).

### Tests
`python -m unittest discover -s tests` → **38 tests pass** (27 module tests + 11 new in
`tests/test_run_measure.py` covering `build_matrix`, `load_plan`, `_split_evidence`,
`_ps_quote`, and `measure_one` for the static-detected / static-clean / invasive-blocked paths).

The orchestration loop executed cleanly with no errors; every measurement scored with full
fidelity (1.0). SQLite DB written to `db/results.sqlite`.

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
- `05_db_measurements.txt` — DB runs + measurements dump (both runs, 6 measurements)
- `06_defender_evidence.txt` — Operational-log + RTP/exclusion check
- `07_full_static_live.txt` — full Axis A live run (all 4 variants, run_id=2)
- `08_behavior_dryrun.txt` — Axis B dry-run matrix (G1–G5, invasive-blocked tags)
