# CLAUDE.md — Project Memory (read at the start of every session)

> **ALWAYS read `docs/PLAN.md` + `docs/SAFETY.md` BEFORE doing anything.**
> This file is kept brief and is updated whenever an important decision is locked in or progress is frozen.

## 🎯 Project goal
Build an **automated tool to evaluate the attack-detection capability of Windows Defender on Windows 11**,
and **build a supplementary detection rule set** (YARA/Sigma) for the samples Defender misses.
KTLT course — Academy of Cryptography Techniques (Học viện Kỹ thuật Mật mã). Team of 4 (Trần Quang Huy + 3 others). Supervisor: Nguyễn Mạnh Thắng.
Public repo: https://github.com/TonykRev/KTLT-Defender

## 🧭 Working method (locked in)
- **Opus = lead/orchestrator**: architecture, contracts, core parts (scorer, fidelity, run_measure, reset), review, integration, report.
- **Sonnet/Haiku subagents = workers** that code modules per spec. **DO NOT use opencode/DeepSeek.**
- ⑤ When dispatching subagents: subagents **cannot read the conversation**, they only read the files they are pointed to → always state clearly
  *"follow the spec in `docs/specs/Mx-….md`"* and name the specific input/output files.

## 🔬 Measurement design (locked in)
- **2 axes:** Axis A = 4 C# payload variants (v0 bare, v1 string-encoded, v2 disk-exec, v3 memory-exec);
  Axis B = Invoke-AtomicRedTeam across 5 groups **G1–G5** mapped to MITRE ATT&CK.
- **4 scoring states:** `error` / `inconclusive` / `detected` / `not_detected`.
- **Evidence:** `Microsoft-Windows-Windows Defender/Operational` log (event IDs 1006/1015/1116/1117/1118/1119…) + Sysmon.
- **Traceability:** each measurement = sample SHA-256 + timestamp + Defender signature version → `runs`/`measurements` tables.

## 🧱 Code conventions
- **Python 3.12**, standard library + `pyyaml` only. **Tests with `unittest`** (not pytest): `python -m unittest`.
- Windows interactions (Get-WinEvent, csc, MpCmdRun) are invoked via `common.run_powershell()`; **all SQL must be parameterized**.
- **state** must be ∈ `{error, inconclusive, detected, not_detected}` (db_writer asserts this).
- **EICAR is encoded as XOR(0x5A)+Base64 in source** → repo & binaries stay clean (Defender raises no flag on the source/clone).
  Only when *running* v0/v2 is plain EICAR dropped to disk → Defender's reaction is the measurement itself.
- Compile with **csc.exe .NET Framework v4.0.30319** (no Visual Studio / .NET SDK needed).
- Local git identity: `KTLT Defender Dev <dev@localhost>`. Commit per phase/wave, with English commit descriptions.

## 🛡️ Safety boundary (full details in `docs/SAFETY.md`)
`config.yaml → environment.machine_label` controls the safety lock:
- **🟢 `dev-win11` (this machine, default):** ONLY build, smoke test, static scan (MpCmdRun), and at most 1–2 harmless Atomic
  discovery tests (T1082/T1057). `atomic_runner` **BLOCKS** all invasive techniques; `reset.ps1` **does NOT** touch Defender/logs.
- **🔴 `cloud-vm`:** where real invasive techniques run (LSASS T1003, disabling Defender T1562, persistence T1547/T1053, cred T1555)
  and **all official Chapter 4 measurements**. Network-isolated VM with a clean snapshot.

## 📌 STATUS (updated at the end of each phase)
_Updated: 2026-11-27_
- ✅ **Phase 0** — Foundation: schema + config + docs + specs + git. Pushed to GitHub.
- ✅ **Phase 1** — Parallel build (safe part): `log_collector`(M5), `db_writer`(M8), `scorer`(M7),
  `fidelity`(M6) + **21 unit tests pass**; payloads v0–v3 + `build.ps1` (clean compile, 4608 B); `atomic_runner`(M3)
  with a guard that blocks invasive techniques; scenarios G1–G5 + `reset.ps1` with dev/cloud locks.
- ✅ **Phase 2 — FULLY DONE** (2026-11-27). Integration: `run_measure.py`(M10) orchestration loop implemented
  (reset → build/arm → trigger → collect → score → write DB) with a safe **dry-run default** (`--yes` required for live).
  **Validated end-to-end on dev-win11:**
  - Axis A static, **all 4 variants** (run_id=2): v0 **detected**, v1 **not_detected**, v2 **detected**, v3 **not_detected**
    (fidelity 1.0 each) → signature catches on-disk plaintext (v0/v2), misses obfuscation (v1) & fileless (v3). Core thesis proven.
  - Axis B behavior **dry-run** (G1–G5, 11 techniques): all 5 invasive techniques correctly `[WILL BE BLOCKED on dev]`.
    Live invasive behavior is deferred to cloud-vm by design (Phase 3).
  - `tests/test_run_measure.py` added → **38 unit tests pass** (was 27; orchestrator now covered).
  - Evidence in `report/evidence/` (`00_SMOKE_TEST_SUMMARY.md` + 01–08).
  - **Finding for Phase 3:** detection came only from the on-demand MpCmdRun scan; `-DisableRemediation` (detect-only) +
    RTP not scanning-on-write in-window ⇒ **no 1116/1117 Operational-log events**, and the dropped EICAR persisted. On the
    clean admin cloud-vm (no exclusions), run some measurements **without** `-DisableRemediation` to exercise the RTP layer
    and emit 1116/1117 telemetry.
- ✅ **Phase 3 — MEASUREMENT COMPLETE** on cloud-vm (driven from on-prem via cross-session messaging
  to the "setup VM" Claude; two-way comms working). Evidence `report/evidence/09–16`.
  - **Axis B: 1 detected / 9 not_detected** across 10 behavioural techniques (G1/G3/G4/G5 run_ids 5–8,
    G2 run_id 11). The lone detection is **T1059.001 PowerShell via AMSI** (local/runtime).
  - **Scorer hardened** on real data: (a) detection **layer attributed by axis** (behaviour catches
    are runtime, not "static"); (b) **a Defender block = detection**, not a measurement error
    (positive detections outrank the error/fidelity gates). **57 tests**.
  - **Cloud-ON spot-check (run_id 9): delta = 0/3** — with cloud demonstrably active (control fired
    `2010` events), LSASS/Run-key/regsvr32 STILL not_detected → **the gaps are real, not a cloud-OFF
    artifact** (resolves the validity worry). **ASR spot-check (run_id 10):** LSASS still not_detected
    with the lsass ASR rule in Block (no 1121) → misses RTP+cloud+ASR; Sigma is the gap-filler.
  - **CAVEATS for the report:** scoped to Atomic **test#1**; config is default-ish consumer (cloud/ASR
    off by default, measured separately); **T1562.001 (G2) is AMBIGUOUS** — zero events incl. no 5013
    while Tamper Protection is ON ⇒ most likely a Defender WIN (block) under-credited, needs
    post-technique RTP-state verification before any "miss" claim; fidelity proves each atomic *ran*,
    not that the malicious *effect* occurred. All runs fidelity=1.0, boxes reverted/stable.
- 🟨 **Phase 4 — IN PROGRESS.** **M11 rule set DONE** (`rules/`): 2 YARA (v1 encoded sample, v3
  fileless loader) + 7 Sigma, each tied to a run_id gap; `rules/README.md` maps them. **Validated
  live:** YARA fires 5/5 on real samples/loaders, **goodware FP = 0 / 12,450 files** (`rules/fp_scan.py`,
  evidence 13) → precision/recall = 1.0. `tests/test_rules.py`. **TODO:** Sigma TP/FP vs real telemetry
  (LIMITED — Sysmon unavailable on the VM, image-level bug), ASR/mitigation-mapping table,
  `report/generate.py` (M12 stub), **report & slides** (deferred by user until all data is in).

**Next task:** Phase 4 finalize — Sigma validation where possible, mitigation-mapping, then build the
report + slides from `report/evidence/09–16`. Optional: user-driven T1562.001 RTP-state re-check.

## 🔁 Habit for updating this file
- Lock in an important decision → record it in the matching section right away.
- End of session/phase → update the **STATUS** section (done / in progress / next task / notes).
- **When a phase is finished → commit + push to GitHub right away.**
