# 4-Day Implementation Plan (approved)

Model: **Opus = lead/orchestrator** (architecture, contracts, core scientific parts, review, integration).
**Sonnet/Haiku subagents = workers** that code modules per spec. (No opencode/DeepSeek.)

- **Opus [O]** does itself: architecture, interfaces, schema, `scorer`, `fidelity`, `run_measure`, `reset`, integration, report.
- **Sonnet [S]**: `log_collector`, `atomic_runner`, payload v2/v3, YARA/Sigma rules.
- **Haiku [H]**: payload v0/v1, `build.ps1`, scenario YAML, `db_writer` boilerplate, goodware script, README.

## Environment
- **This Windows 11 machine = DEV station + command post.** Build + smoke test + static measurement axis (safe). Verified: csc.exe, MpCmdRun, and Defender log reading all work.
- **Windows 11 cloud VM = OFFICIAL measurement station.** All invasive techniques + all Chapter 4 numbers. You operate it; Opus provides the instructions.

## Phases
- **Phase 0 (Day 1 morning) — Foundation:** repo + schema + config + docs + module specs + git. *(in progress)*
- **Phase 1 (Day 1 afternoon → Day 2) — Parallel build:** spawn workers to code M1–M11; Opus reviews + integrates; validate the safe part on this machine.
- **Phase 2 (Day 2 end → Day 3 morning) — Integration + trial run:** end-to-end safe part; fix all integration errors; DB records full traceability.
- **Phase 3 (Day 3) — Real measurement on cloud VM:** Opus writes the runbook; you set up the VM; run a reduced matrix of ~10–15 techniques × 4 variants.
- **Phase 4 (Day 4) — Rules + results + packaging:** YARA/Sigma for missed samples; FP measurement on goodware; ASR mapping; generate Chapter 4 tables/charts; write limitations; package. Half-day buffer.

## Modules (tracking progress)
| # | Module | File | Owner |
|---|---|---|---|
| M1 | Payload v0–v3 (C#) | `payloads/src/` | H+S |
| M2 | Build script | `payloads/build.ps1` | H |
| M3 | Atomic runner | `engine/atomic_runner.py` | S |
| M4 | 5 scenario groups | `scenarios/*.yaml` | H |
| M5 | Log collector | `collect/log_collector.py` | S |
| M6 | Fidelity | `score/fidelity.py` | O |
| M7 | Scorer (4 states) | `score/scorer.py` | O |
| M8 | DB writer + schema | `db/` | H+O |
| M9 | Reset (soft) | `vm/reset.ps1` | O |
| M10 | Orchestration loop | `run_measure.py` | O |
| M11 | YARA/Sigma rules | `rules/` | S |
| M12 | FP + ASR + report | `report/` | O |

## 5 scenario groups (G1–G5)
- G1 Execution (TA0002): T1059.001 PowerShell, T1059.003 cmd, T1204
- G2 Defense Evasion (TA0005): T1562.001, T1027, T1140, AMSI bypass
- G3 Credential Access (TA0006): T1003.001 LSASS, T1555
- G4 Persistence (TA0003): T1547.001 Run key, T1053.005 scheduled task
- G5 Discovery/LOLBin (TA0007): T1082, T1057, certutil/mshta/regsvr32
