"""
common.py — Shared helpers for the whole tool (Owner: Opus, already implemented).
Keeps dependencies minimal: only pyyaml. Reads the Event Log via PowerShell through subprocess.
"""
from __future__ import annotations
import hashlib
import json
import glob
import subprocess
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:  # clear message if the dependency is missing
    yaml = None


def load_config(path: str = "config.yaml") -> dict:
    """Read config.yaml -> dict."""
    if yaml is None:
        raise RuntimeError("Missing pyyaml. Run: pip install pyyaml")
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def utcnow_iso() -> str:
    """ISO8601 UTC timestamp (used uniformly for all records)."""
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: str | Path) -> str:
    """SHA-256 hash of a file (for sample traceability)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def run_powershell(script: str, timeout: int = 120) -> subprocess.CompletedProcess:
    """
    Run a PowerShell snippet and return a CompletedProcess (stdout/stderr/returncode).
    Used for: Get-MpComputerStatus, Get-WinEvent, MpCmdRun, reset.ps1 ...
    """
    return subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, timeout=timeout,
    )


def ps_json(script: str, timeout: int = 120):
    """Run PowerShell that ends with `ConvertTo-Json` and parse the output into a Python object."""
    cp = run_powershell(script, timeout=timeout)
    out = (cp.stdout or "").strip()
    if not out:
        return None
    return json.loads(out)


def get_defender_status() -> dict:
    """Get Defender engine/signature version and realtime status (written to the runs table)."""
    data = ps_json(
        "Get-MpComputerStatus | "
        "Select-Object AMEngineVersion,AntivirusSignatureVersion,"
        "AMProductVersion,RealTimeProtectionEnabled,AntivirusEnabled | "
        "ConvertTo-Json -Compress"
    )
    return data or {}


def find_mpcmdrun(pattern: str) -> str | None:
    """Locate MpCmdRun.exe (the Platform folder has a changing version)."""
    hits = sorted(glob.glob(pattern))
    return hits[-1] if hits else None
