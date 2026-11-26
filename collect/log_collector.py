"""
M5 — Log collector (Chủ: Sonnet worker). STUB — đặc tả ở docs/specs/M5-log_collector.md

Nhiệm vụ: với một CỬA SỔ THỜI GIAN [start, end], trả về các sự kiện bằng chứng từ
  (a) Microsoft-Windows-Windows Defender/Operational
  (b) Microsoft-Windows-Sysmon/Operational (nếu có)
Dùng PowerShell Get-WinEvent (FilterHashtable StartTime/EndTime) qua common.run_powershell.
KHÔNG tự chấm điểm — chỉ trả bằng chứng thô cho scorer.
"""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class EvidenceEvent:
    source: str          # 'defender' | 'sysmon'
    event_id: int
    time_created: str    # ISO8601
    message: str
    raw: dict = field(default_factory=dict)


def collect_defender_events(start_iso: str, end_iso: str, cfg: dict) -> list[EvidenceEvent]:
    """Trả về sự kiện Defender trong [start, end]. TODO(worker)."""
    raise NotImplementedError


def collect_sysmon_events(start_iso: str, end_iso: str, cfg: dict) -> list[EvidenceEvent]:
    """Trả về sự kiện Sysmon trong [start, end] (rỗng nếu chưa cài). TODO(worker)."""
    raise NotImplementedError


def collect_all(start_iso: str, end_iso: str, cfg: dict) -> list[EvidenceEvent]:
    """Gộp Defender + Sysmon. TODO(worker)."""
    raise NotImplementedError
