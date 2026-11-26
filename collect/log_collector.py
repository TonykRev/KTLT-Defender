"""
M5 — Log collector. Đặc tả: docs/specs/M5-log_collector.md

Với một CỬA SỔ THỜI GIAN [start, end] (ISO8601, UTC) trả về các sự kiện bằng chứng từ
  (a) Microsoft-Windows-Windows Defender/Operational
  (b) Microsoft-Windows-Sysmon/Operational (nếu có)
Dùng PowerShell Get-WinEvent (FilterHashtable StartTime/EndTime) qua common.run_powershell.
KHÔNG tự chấm điểm — chỉ trả bằng chứng thô cho scorer. Không bao giờ raise khi thu log.
"""
from __future__ import annotations
import json
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone

import common


@dataclass
class EvidenceEvent:
    source: str          # 'defender' | 'sysmon'
    event_id: int
    time_created: str    # ISO8601
    message: str
    raw: dict = field(default_factory=dict)


def _norm_iso(iso: str) -> str:
    """Chuẩn hoá ISO8601 về UTC ('Z'); chuỗi không có múi giờ coi là UTC."""
    s = str(iso).strip()
    if s.endswith(("Z", "z")):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _build_script(log_name: str, start_iso: str, end_iso: str) -> str:
    """PowerShell: lọc theo cửa sổ (đổi UTC -> giờ local cho FilterHashtable), xuất JSON ASCII-an-toàn."""
    log = log_name.replace("'", "''")
    s = _norm_iso(start_iso)
    e = _norm_iso(end_iso)
    return (
        "$ErrorActionPreference='SilentlyContinue'; "
        f"$s=[DateTimeOffset]::Parse('{s}').LocalDateTime; "
        f"$e=[DateTimeOffset]::Parse('{e}').LocalDateTime; "
        f"$ev=@(Get-WinEvent -FilterHashtable @{{LogName='{log}'; StartTime=$s; EndTime=$e}} "
        "-ErrorAction SilentlyContinue | "
        "Select-Object Id,"
        "@{n='TimeCreated';e={$_.TimeCreated.ToUniversalTime().ToString('o')}},Message); "
        "if ($ev.Count -eq 0) { '[]' } else { "
        "$j=ConvertTo-Json -InputObject $ev -Compress -Depth 4; "
        # Escape ký tự non-ASCII để không phụ thuộc code page của stdout.
        r"[regex]::Replace($j,'[^\x00-\x7F]',{param($m) '\u{0:x4}' -f [int][char]$m.Value}) }"
    )


def _parse(stdout: str, source: str) -> list[EvidenceEvent]:
    out = (stdout or "").strip()
    if not out:
        return []
    try:
        data = json.loads(out)
    except (ValueError, TypeError):
        return []
    if data is None:
        return []
    if isinstance(data, dict):  # 1 event -> object thay vì list
        data = [data]
    if not isinstance(data, list):
        return []
    events: list[EvidenceEvent] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        try:
            eid = int(item.get("Id"))
        except (TypeError, ValueError):
            continue
        events.append(EvidenceEvent(
            source=source,
            event_id=eid,
            time_created=str(item.get("TimeCreated") or ""),
            message=str(item.get("Message") or ""),
            raw=item,
        ))
    return events


def _collect(log_name, source: str, start_iso: str, end_iso: str) -> list[EvidenceEvent]:
    if not log_name:
        return []
    try:
        script = _build_script(log_name, start_iso, end_iso)
        cp = common.run_powershell(script, timeout=60)
        return _parse(getattr(cp, "stdout", ""), source)
    except (subprocess.TimeoutExpired, OSError, ValueError):
        return []
    except Exception:  # bằng chứng không được làm sập pipeline đo
        return []


def collect_defender_events(start_iso: str, end_iso: str, cfg: dict) -> list[EvidenceEvent]:
    """Trả về sự kiện Defender trong [start, end]."""
    log = (cfg.get("evidence") or {}).get("defender_log")
    return _collect(log, "defender", start_iso, end_iso)


def collect_sysmon_events(start_iso: str, end_iso: str, cfg: dict) -> list[EvidenceEvent]:
    """Trả về sự kiện Sysmon trong [start, end] (rỗng nếu chưa cài)."""
    log = (cfg.get("evidence") or {}).get("sysmon_log")
    return _collect(log, "sysmon", start_iso, end_iso)


def collect_all(start_iso: str, end_iso: str, cfg: dict) -> list[EvidenceEvent]:
    """Gộp Defender + Sysmon, sắp theo thời gian."""
    evs = collect_defender_events(start_iso, end_iso, cfg) + collect_sysmon_events(start_iso, end_iso, cfg)
    return sorted(evs, key=lambda x: x.time_created)
