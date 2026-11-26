"""
M6 — Fidelity: đo ĐỘ TRUNG THỰC của phép đo (Chủ: Opus).

Một phép đo chỉ "hợp lệ" nếu kỹ thuật thực sự đã chạy và môi trường sạch trước đó.
Chấm 0..1 từ 4 tín hiệu (có trọng số); technique_ran là điều kiện cần (nếu kỹ thuật
không chạy thì phép đo gần như vô nghĩa nên điểm bị chặn trần).
"""
from __future__ import annotations
from dataclasses import dataclass, field

WEIGHTS = {
    "reset_ok": 0.20,                 # môi trường được reset sạch trước khi đo
    "technique_ran": 0.45,            # kỹ thuật có thực sự thực thi (quan trọng nhất)
    "collect_window_complete": 0.20,  # cửa sổ thu log đủ dài, không bị cắt
    "clean_before": 0.15,             # không nhiễu từ lần đo trước (quarantine cũ...)
}


@dataclass
class FidelityResult:
    score: float
    valid: bool
    signals: dict = field(default_factory=dict)


def compute_fidelity(*, reset_ok, technique_ran, collect_window_complete,
                     clean_before, cfg=None) -> FidelityResult:
    signals = {
        "reset_ok": bool(reset_ok),
        "technique_ran": bool(technique_ran),
        "collect_window_complete": bool(collect_window_complete),
        "clean_before": bool(clean_before),
    }
    s = sum(w for k, w in WEIGHTS.items() if signals[k])
    # technique_ran là điều kiện cần: không chạy -> chặn trần điểm
    if not signals["technique_ran"]:
        s = min(s, 0.30)
    min_valid = 0.5
    if cfg:
        min_valid = cfg.get("scoring", {}).get("fidelity_min_valid", 0.5)
    return FidelityResult(score=round(s, 3), valid=s >= min_valid, signals=signals)
