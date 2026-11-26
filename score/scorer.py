"""
M7 — Scorer: map BẰNG CHỨNG -> 1 trong 4 TRẠNG THÁI (Chủ: Opus — phần lõi khoa học).

4 trạng thái (Chương 2):
  error         : phép đo lỗi (reset/trigger/thu log thất bại) -> không tính
  inconclusive  : phép đo không đủ tin cậy (fidelity thấp, hoặc thiếu bằng chứng)
  detected      : có bằng chứng Defender phát hiện/chặn
  not_detected  : kỹ thuật chạy (có dấu vết) nhưng Defender KHÔNG phát hiện

`evidence` là list các object có thuộc tính: .source ('defender'|'sysmon'),
.event_id (int), .time_created (ISO8601), .message (str). (Duck-typing — không
ràng buộc vào log_collector để test độc lập được.)
"""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime

# --- Phân loại Event ID của Microsoft Defender Operational ---
# Phát hiện theo chữ ký / quét (tầng tĩnh):
SIGNATURE_EVENT_IDS = {1006, 1007, 1008, 1116, 1117, 1118}
# Phát hiện theo giám sát hành vi:
BEHAVIOR_EVENT_IDS = {1015, 1119, 1120, 1121}
DETECTION_EVENT_IDS = SIGNATURE_EVENT_IDS | BEHAVIOR_EVENT_IDS

VALID_STATES = ("error", "inconclusive", "detected", "not_detected")


@dataclass
class ScoreResult:
    state: str
    detection_layer: str | None = None   # 'static'|'amsi'|'behavior'|'asr'|None
    detect_latency_ms: int | None = None
    evidence_source: str = "none"        # 'defender'|'sysmon'|'both'|'none'
    reason: str = ""


def _parse_iso(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except Exception:
        return None


def _evidence_source(evidence) -> str:
    srcs = {getattr(e, "source", None) for e in evidence}
    has_def, has_sys = "defender" in srcs, "sysmon" in srcs
    if has_def and has_sys:
        return "both"
    if has_def:
        return "defender"
    if has_sys:
        return "sysmon"
    return "none"


def _infer_layer(det_events, axis) -> str:
    """Suy tầng phát hiện từ loại event + nội dung (heuristic, có ghi chú ở báo cáo)."""
    msg = " ".join((getattr(e, "message", "") or "") for e in det_events).lower()
    if "amsi" in msg:
        return "amsi"
    ids = {e.event_id for e in det_events}
    if ids & BEHAVIOR_EVENT_IDS and not (ids & SIGNATURE_EVENT_IDS):
        return "behavior"
    return "static"


def score(evidence, *, trigger_started_iso, fidelity_valid, had_error,
          static_result, cfg=None, axis="behavior") -> ScoreResult:
    evidence = list(evidence or [])

    # 1) lỗi phép đo -> không tính
    if had_error:
        return ScoreResult("error", reason="phép đo lỗi (reset/trigger/thu log thất bại)")

    # 2) không đủ tin cậy -> không kết luận
    if not fidelity_valid:
        return ScoreResult("inconclusive", evidence_source=_evidence_source(evidence),
                           reason="fidelity dưới ngưỡng — phép đo không hợp lệ")

    src = _evidence_source(evidence)

    # 3a) quét tĩnh bắt mẫu
    if static_result == "threat_found":
        return ScoreResult("detected", detection_layer="static", detect_latency_ms=0,
                           evidence_source=src, reason="MpCmdRun: threat_found")

    # 3b) có sự kiện phát hiện của Defender
    det = [e for e in evidence
           if getattr(e, "source", None) == "defender" and e.event_id in DETECTION_EVENT_IDS]
    if det:
        first = min(det, key=lambda e: getattr(e, "time_created", "") or "")
        latency = None
        t0, t1 = _parse_iso(trigger_started_iso), _parse_iso(getattr(first, "time_created", None))
        if t0 and t1:
            latency = max(0, int((t1 - t0).total_seconds() * 1000))
        return ScoreResult("detected", detection_layer=_infer_layer(det, axis),
                           detect_latency_ms=latency, evidence_source=src,
                           reason=f"Defender events {sorted({e.event_id for e in det})}")

    # 4) không có phát hiện — kỹ thuật có thực sự chạy không?
    technique_ran = any(getattr(e, "source", None) == "sysmon" for e in evidence) \
        or static_result == "clean"
    if technique_ran:
        return ScoreResult("not_detected", evidence_source=src,
                           reason="kỹ thuật chạy (có dấu vết) nhưng Defender không phát hiện")

    # 5) thiếu bằng chứng hai phía -> không kết luận
    return ScoreResult("inconclusive", evidence_source=src,
                       reason="không đủ bằng chứng để kết luận")
