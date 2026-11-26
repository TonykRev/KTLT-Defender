"""
M3 — Atomic runner (Chủ: Sonnet worker). STUB. Đặc tả: docs/specs/M3-atomic_runner.md

Bọc Invoke-AtomicRedTeam: nạp module, chạy prereqs (nếu cần), Invoke-AtomicTest <id>,
rồi cleanup. Trả về thời điểm bắt đầu/kết thúc + exit status để scorer/fidelity dùng.
LƯU Ý AN TOÀN: chỉ chạy trên cloud-vm với kỹ thuật xâm lấn (xem docs/SAFETY.md).
"""
from __future__ import annotations
from dataclasses import dataclass


@dataclass
class AtomicResult:
    technique_id: str
    test_number: int | None
    started_iso: str
    ended_iso: str
    ran: bool            # kỹ thuật có thực thi không (cho fidelity)
    exit_ok: bool
    stdout: str = ""
    stderr: str = ""


def invoke_atomic(technique_id: str, *, test_number=None, get_prereqs=False,
                  cleanup=True, cfg=None) -> AtomicResult:
    """Chạy một Atomic test theo technique id. TODO(worker)."""
    raise NotImplementedError
