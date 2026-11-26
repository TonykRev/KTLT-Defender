# Automated Evaluation Tool for Windows Defender Detection (Win11) + Supplementary Rule Set

KTLT course project — Academy of Cryptography Techniques (Học viện Kỹ thuật Mật mã).
Team: Trần Quang Huy, Nguyễn Văn Thành, Nguyễn Viết Nhật Long, Nguyễn Việt Hiếu. Supervisor: Nguyễn Mạnh Thắng.

## Goal
Quantify: how **many** attack techniques Defender on Windows 11 detects, **at which layer**, **how long** it takes, and for which techniques **rules are missing** — then propose supplementary YARA/Sigma rule sets with measured false-positive (FP) rates and ASR mapping.

Every measurement row is traceable: **sample hash + timestamp + Defender version**.

## Architecture (3 blocks — matches Chapter 3 of the outline)
- **Block 1 — Test sample generation:** 4 C# payload variants (`payloads/`), measuring the STATIC/AMSI/memory axes.
  - v0 bare sample · v1 +string encoding · v2 +disk execution · v3 +in-memory execution.
- **Block 2 — Behavior engine:** Invoke-AtomicRedTeam (`engine/`, `scenarios/`), 5 scenario groups G1–G5, measuring the BEHAVIOR/ASR axis.
- **Block 3 — Automated measurement station:** loop per measurement (`run_measure.py`):
  clean reset → load sample → static scan (MpCmdRun) → trigger technique →
  collect logs (Defender + Sysmon) → compute fidelity → score 1 of 4 states → write to SQLite.

## Directory tree
```
payloads/   M1,M2  4 C# variants + build.ps1
engine/     M3     Invoke-AtomicRedTeam wrapper
scenarios/  M4     5 scenario groups G1–G5 (*.yaml)
collect/    M5     reads Defender + Sysmon Event Logs
score/      M6,M7  fidelity + scorer (4 states)
db/         M8     schema.sql + db_writer + results.sqlite
vm/         M9     reset.ps1 (soft-reset)
rules/      M11    supplementary YARA + Sigma rules
report/     M12    generates Chapter 4 tables/charts + FP + ASR
run_measure.py M10 main orchestration loop
docs/       PLAN, SAFETY, module specs (specs/)
tests/             unit tests
```

## ⚠️ Safety — READ BEFORE RUNNING
See [docs/SAFETY.md](docs/SAFETY.md). Summary: the **dev machine (personal Windows PC) is only for building + safe measurement**;
all invasive techniques (LSASS dump, disabling Defender, persistence...) and **all official measurements** run only on an **isolated cloud VM with a snapshot**. Payloads are harmless and exist only to measure the detection layers.

## Status
Currently in Phase 0 (foundation). See [docs/PLAN.md](docs/PLAN.md).
