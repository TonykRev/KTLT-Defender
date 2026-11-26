# Work Packet M3 — Atomic Runner Wrapper

**Worker:** Sonnet. **Review:** Opus. **File:** `engine/atomic_runner.py` (stub + dataclass already exist).

## Goal
Wrap Invoke-AtomicRedTeam so it can trigger one technique by MITRE ID, returning start/end time and execution status.

## Approach
- Via `common.run_powershell`:
  `Import-Module Invoke-AtomicRedTeam; Invoke-AtomicTest <id> -TestNumbers <n> [-GetPrereqs] [-Cleanup]`.
- Record `started_iso = utcnow` right before, and `ended_iso` right after (so the scorer can compute the log collection window).
- `ran`: inferred from whether the command ran (exit 0 / has output) — a signal for fidelity.
- Keep `invoke` (run) and `cleanup` separate so the orchestrator controls them.

## SAFETY CONSTRAINTS (mandatory)
- The module MUST check `cfg['environment']['machine_label']`: if it is `dev-win11` and the technique is in the
  INVASIVE LIST (T1003, T1562, T1547, T1053, T1555, AMSI bypass...) → **refuse to run**, returning
  `AtomicResult(ran=False, exit_ok=False, stderr="blocked on dev machine — see SAFETY.md")`.
- Full execution is allowed only when `machine_label == cloud-vm`.
- A constant `INVASIVE_TECHNIQUES = {...}` is declared explicitly in the module.

## Acceptance
- `invoke_atomic("T1082", cfg=dev_cfg)` (harmless discovery) runs on the dev machine (if Invoke-Atomic is installed),
  or returns a clear error if it is not installed — it must NOT crash.
- `invoke_atomic("T1003.001", cfg=dev_cfg)` → blocked with a safety message.
- `tests/test_atomic_runner.py` mocks subprocess and covers the invasive-block branch.
