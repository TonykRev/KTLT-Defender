"""
M7 — Scorer: map BẰNG CHỨNG -> 1 trong 4 TRẠNG THÁI (Chủ: Opus — phần lõi khoa học).
STUB có sẵn CÂY QUYẾT ĐỊNH; sẽ implement chi tiết ở Phase 1.

4 trạng thái (Chương 2):
  - error         : phép đo lỗi (reset/trigger/thu log thất bại) -> không tính
  - inconclusive  : phép đo không đủ tin cậy (fidelity < ngưỡng, hoặc bằng chứng mâu thuẫn)
  - detected      : có bằng chứng Defender phát hiện/chặn
  - not_detected  : kỹ thuật chạy (có dấu vết Sysmon) nhưng Defender KHÔNG phát hiện

Quy tắc (rút gọn):
  1) Nếu lỗi kỹ thuật/thu log -> error
  2) Nếu fidelity_valid == False -> inconclusive
  3) Nếu có event Defender phát hiện (1006/1015/1116/1117...) -> detected (+ suy ra detection_layer)
  4) Nếu kỹ thuật có chạy (Sysmon ProcessCreate...) mà không có event phát hiện -> not_detected
  5) Không đủ bằng chứng hai phía -> inconclusive
"""
from __future__ import annotations
from dataclasses import dataclass


@dataclass
class ScoreResult:
    state: str                 # 'error'|'inconclusive'|'detected'|'not_detected'
    detection_layer: str | None = None   # 'static'|'amsi'|'behavior'|'asr'|None
    detect_latency_ms: int | None = None
    evidence_source: str = "none"        # 'defender'|'sysmon'|'both'|'none'
    reason: str = ""


def score(evidence, *, trigger_started_iso, fidelity_valid, had_error, static_result,
          cfg) -> ScoreResult:
    """Map bằng chứng -> ScoreResult theo cây quyết định trên. TODO(Opus, Phase 1)."""
    raise NotImplementedError
