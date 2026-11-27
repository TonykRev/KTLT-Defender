"""
M6 — Fidelity: measures the FIDELITY of a measurement (Owner: Opus).

A measurement is only "valid" if the technique stimulus was delivered and the environment was clean
beforehand. "Stimulus delivered" (technique_ran) means the payload executed OR Defender blocked it at
the access layer (an AV block proves the stimulus reached Defender) — the caller passes that combined
signal. Scores 0..1 from 4 weighted signals; technique_ran is a necessary condition (if the stimulus
was never delivered, the measurement is nearly meaningless, so the score is capped).
"""
from __future__ import annotations
from dataclasses import dataclass, field

WEIGHTS = {
    "reset_ok": 0.20,                 # environment was reset cleanly before measuring
    "technique_ran": 0.45,            # stimulus delivered: payload executed OR Defender blocked it
    "collect_window_complete": 0.20,  # log collection window was long enough and not truncated
    "clean_before": 0.15,             # no noise from the previous measurement (old quarantine...)
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
    # technique_ran is a necessary condition: if it did not run -> cap the score
    if not signals["technique_ran"]:
        s = min(s, 0.30)
    min_valid = 0.5
    if cfg:
        min_valid = cfg.get("scoring", {}).get("fidelity_min_valid", 0.5)
    return FidelityResult(score=round(s, 3), valid=s >= min_valid, signals=signals)
