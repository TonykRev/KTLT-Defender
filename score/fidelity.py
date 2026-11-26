"""
M6 — Fidelity: đo ĐỘ TRUNG THỰC của phép đo (Chủ: Opus). STUB.

Ý tưởng: một phép đo chỉ "hợp lệ" nếu kỹ thuật thực sự đã chạy và môi trường sạch trước đó.
Chấm 0..1 dựa trên các tín hiệu:
  - reset thành công trước khi đo?            (+)
  - kỹ thuật có dấu vết thực thi (Sysmon/exit code hợp lệ)?   (+)
  - cửa sổ thu log đủ dài, không bị cắt?      (+)
  - không có nhiễu từ lần đo trước (quarantine cũ)?   (+)
fidelity_valid = fidelity_score >= cfg['scoring']['fidelity_min_valid']
"""
from __future__ import annotations
from dataclasses import dataclass


@dataclass
class FidelityResult:
    score: float
    valid: bool
    signals: dict


def compute_fidelity(*, reset_ok, technique_ran, collect_window_complete,
                     clean_before, cfg) -> FidelityResult:
    """Tính fidelity 0..1 + cờ valid. TODO(Opus, Phase 1)."""
    raise NotImplementedError
