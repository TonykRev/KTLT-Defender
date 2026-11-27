"""
M7 — Scorer: map EVIDENCE -> 1 of 4 STATES (Owner: Opus — the scientific core).

4 states (Chapter 2):
  error         : measurement failed (reset/trigger/log collection failed) -> not counted
  inconclusive  : measurement not reliable enough (low fidelity, or missing evidence)
  detected      : evidence that Defender detected/blocked the technique
  not_detected  : technique ran (traces present) but Defender did NOT detect it

`evidence` is a list of objects with attributes: .source ('defender'|'sysmon'),
.event_id (int), .time_created (ISO8601), .message (str). (Duck typing — not
bound to log_collector, so it can be tested independently.)
"""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime

# --- Event ID classification for Microsoft Defender Operational ---
# Detection by signature / scan (static layer):
SIGNATURE_EVENT_IDS = {1006, 1007, 1008, 1116, 1117, 1118}
# Detection by behavior monitoring:
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
    """Infer the detection layer from the event type and content (heuristic, noted in the report)."""
    msg = " ".join((getattr(e, "message", "") or "") for e in det_events).lower()
    if "amsi" in msg:
        return "amsi"
    ids = {e.event_id for e in det_events}
    if ids & BEHAVIOR_EVENT_IDS and not (ids & SIGNATURE_EVENT_IDS):
        return "behavior"
    return "static"


def score(evidence, *, trigger_started_iso, fidelity_valid, had_error,
          static_result, technique_ran=None, cfg=None, axis="behavior") -> ScoreResult:
    evidence = list(evidence or [])

    # 1) measurement error -> not counted
    if had_error:
        return ScoreResult("error", reason="measurement failed (reset/trigger/log collection failed)")

    # 2) not reliable enough -> no conclusion
    if not fidelity_valid:
        return ScoreResult("inconclusive", evidence_source=_evidence_source(evidence),
                           reason="fidelity below threshold — measurement is not valid")

    src = _evidence_source(evidence)

    # 3a) static scan caught the sample
    if static_result == "threat_found":
        return ScoreResult("detected", detection_layer="static", detect_latency_ms=0,
                           evidence_source=src, reason="MpCmdRun: threat_found")

    # 3b) Defender detection events are present
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

    # 4) no detection — did the technique actually run?
    # Prefer the caller's authoritative signal (the atomic runner / detonation knows whether the
    # technique executed). Fall back to inferring from evidence only when it is not supplied — the
    # old inference fails on the behavioral axis when Sysmon is absent (no sysmon events, no static
    # scan), which would wrongly turn every missed technique into 'inconclusive' instead of
    # 'not_detected' — exactly the gap cases the study is meant to surface.
    ran = technique_ran
    if ran is None:
        ran = any(getattr(e, "source", None) == "sysmon" for e in evidence) \
            or static_result == "clean"
    if ran:
        return ScoreResult("not_detected", evidence_source=src,
                           reason="technique ran but Defender did not detect it")

    # 5) evidence missing on both sides -> no conclusion
    return ScoreResult("inconclusive", evidence_source=src,
                       reason="insufficient evidence to conclude")
