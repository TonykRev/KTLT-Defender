"""
common.py — Helper dùng chung cho toàn công cụ (Chủ: Opus, đã implement).
Giữ phụ thuộc tối thiểu: chỉ pyyaml. Đọc Event Log dùng PowerShell qua subprocess.
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
except ImportError:  # thông báo rõ nếu thiếu dep
    yaml = None


def load_config(path: str = "config.yaml") -> dict:
    """Đọc config.yaml -> dict."""
    if yaml is None:
        raise RuntimeError("Thiếu pyyaml. Chạy: pip install pyyaml")
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def utcnow_iso() -> str:
    """Mốc thời gian ISO8601 UTC (dùng thống nhất cho mọi bản ghi)."""
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: str | Path) -> str:
    """Băm SHA-256 của một file (để truy vết mẫu)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def run_powershell(script: str, timeout: int = 120) -> subprocess.CompletedProcess:
    """
    Chạy một đoạn PowerShell, trả CompletedProcess (stdout/stderr/returncode).
    Dùng cho: Get-MpComputerStatus, Get-WinEvent, MpCmdRun, reset.ps1 ...
    """
    return subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, timeout=timeout,
    )


def ps_json(script: str, timeout: int = 120):
    """Chạy PowerShell có `ConvertTo-Json` ở cuối và parse về object Python."""
    cp = run_powershell(script, timeout=timeout)
    out = (cp.stdout or "").strip()
    if not out:
        return None
    return json.loads(out)


def get_defender_status() -> dict:
    """Lấy phiên bản engine/chữ ký + trạng thái realtime của Defender (ghi vào bảng runs)."""
    data = ps_json(
        "Get-MpComputerStatus | "
        "Select-Object AMEngineVersion,AntivirusSignatureVersion,"
        "AMProductVersion,RealTimeProtectionEnabled,AntivirusEnabled | "
        "ConvertTo-Json -Compress"
    )
    return data or {}


def find_mpcmdrun(pattern: str) -> str | None:
    """Dò MpCmdRun.exe (thư mục Platform có version thay đổi)."""
    hits = sorted(glob.glob(pattern))
    return hits[-1] if hits else None
