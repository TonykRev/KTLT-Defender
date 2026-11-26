"""
M3 — Atomic runner. Specification: docs/specs/M3-atomic_runner.md

Wraps Invoke-AtomicRedTeam: loads the module, runs Invoke-AtomicTest <id>, and returns the start/end times
and exit status for use by the scorer/fidelity.
SAFETY NOTE: invasive techniques may only be run on cloud-vm (see docs/SAFETY.md).
"""
from __future__ import annotations
import re
from dataclasses import dataclass

import common

# Invasive techniques: only run when machine_label == "cloud-vm".
INVASIVE_TECHNIQUES = {
    "T1003", "T1003.001",
    "T1562", "T1562.001",
    "T1547", "T1547.001",
    "T1053", "T1053.005",
    "T1555",
}

CLOUD_LABEL = "cloud-vm"


@dataclass
class AtomicResult:
    technique_id: str
    test_number: int | None
    started_iso: str
    ended_iso: str
    ran: bool            # whether the technique executed (for fidelity)
    exit_ok: bool
    stdout: str = ""
    stderr: str = ""


def is_invasive(technique_id: str) -> bool:
    """True if the id is in INVASIVE_TECHNIQUES or starts with one of the ids in it."""
    tid = (technique_id or "").strip().upper()
    return any(tid == t or tid.startswith(t) for t in INVASIVE_TECHNIQUES)


def build_command(technique_id: str, test_number=None, get_prereqs=False,
                  cleanup=True) -> str:
    # Only allow safe characters in the id to prevent command injection.
    if not re.fullmatch(r"T\d{4}(\.\d{3})?", technique_id):
        raise ValueError(f"invalid technique id: {technique_id!r}")
    cmd = f"Import-Module Invoke-AtomicRedTeam; Invoke-AtomicTest {technique_id}"
    if test_number is not None:
        cmd += f" -TestNumbers {int(test_number)}"
    if get_prereqs:
        cmd += " -GetPrereqs"
    if cleanup:
        cmd += " -Cleanup"
    return cmd


def invoke_atomic(technique_id: str, *, test_number=None, get_prereqs=False,
                  cleanup=True, cfg=None) -> AtomicResult:
    """Run one Atomic test by technique id (with invasive-technique blocking)."""
    if cfg is None:
        cfg = common.load_config()
    label = (cfg.get("environment") or {}).get("machine_label")

    if label != CLOUD_LABEL and is_invasive(technique_id):
        now = common.utcnow_iso()
        return AtomicResult(
            technique_id=technique_id, test_number=test_number,
            started_iso=now, ended_iso=now, ran=False, exit_ok=False,
            stderr=(f"blocked on non-cloud-vm machine (machine_label={label}); "
                    "see docs/SAFETY.md"),
        )

    try:
        cmd = build_command(technique_id, test_number, get_prereqs, cleanup)
    except ValueError as e:
        now = common.utcnow_iso()
        return AtomicResult(technique_id, test_number, now, now,
                            ran=False, exit_ok=False, stderr=str(e))

    started = common.utcnow_iso()
    try:
        cp = common.run_powershell(cmd)
    except Exception as e:  # do not crash: PowerShell missing, timeout...
        ended = common.utcnow_iso()
        return AtomicResult(technique_id, test_number, started, ended,
                            ran=False, exit_ok=False, stderr=f"{type(e).__name__}: {e}")
    ended = common.utcnow_iso()

    out = cp.stdout or ""
    err = cp.stderr or ""
    exit_ok = cp.returncode == 0
    ran = exit_ok and bool(out.strip())
    return AtomicResult(technique_id, test_number, started, ended,
                        ran=ran, exit_ok=exit_ok, stdout=out, stderr=err)
