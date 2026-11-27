"""Unit tests for score/scorer.py + score/fidelity.py (Owner: Opus).
Use a stand-in for evidence events (duck-typing) to test independently of log_collector.
Run from repo root:  python -m unittest tests.test_scorer -v
"""
import unittest
from types import SimpleNamespace

from score import scorer, fidelity


def ev(source, event_id, time_created="2026-11-26T10:00:05+00:00", message=""):
    return SimpleNamespace(source=source, event_id=event_id,
                           time_created=time_created, message=message)


TRIG = "2026-11-26T10:00:00+00:00"


class TestScorer(unittest.TestCase):

    def test_error(self):
        r = scorer.score([], trigger_started_iso=TRIG, fidelity_valid=True,
                         had_error=True, static_result=None)
        self.assertEqual(r.state, "error")

    def test_inconclusive_low_fidelity(self):
        r = scorer.score([ev("sysmon", 1)], trigger_started_iso=TRIG,
                         fidelity_valid=False, had_error=False, static_result=None)
        self.assertEqual(r.state, "inconclusive")

    def test_static_threat_found(self):
        r = scorer.score([], trigger_started_iso=TRIG, fidelity_valid=True,
                         had_error=False, static_result="threat_found")
        self.assertEqual(r.state, "detected")
        self.assertEqual(r.detection_layer, "static")
        self.assertEqual(r.detect_latency_ms, 0)

    def test_defender_detection_latency_behavior_axis(self):
        # Behaviour axis (the default): a bare 1116/1117 is a RUNTIME catch, not a file scan —
        # no on-demand MpCmdRun scan is performed on this axis, so it cannot be 'static'.
        r = scorer.score([ev("defender", 1116)], trigger_started_iso=TRIG,
                         fidelity_valid=True, had_error=False, static_result=None, axis="behavior")
        self.assertEqual(r.state, "detected")
        self.assertEqual(r.detection_layer, "behavior")
        self.assertEqual(r.detect_latency_ms, 5000)  # 10:00:00 -> 10:00:05
        self.assertEqual(r.evidence_source, "defender")

    def test_defender_signature_on_static_axis_is_static(self):
        # Axis A (static): a 1116 reached here is an on-write file-scan catch -> 'static' layer.
        r = scorer.score([ev("defender", 1116)], trigger_started_iso=TRIG,
                         fidelity_valid=True, had_error=False, static_result="clean", axis="static")
        self.assertEqual(r.state, "detected")
        self.assertEqual(r.detection_layer, "static")

    def test_on_demand_source_text_is_static_even_on_behavior_axis(self):
        # If Defender's own text names an on-demand scan, trust it over the axis fallback.
        r = scorer.score([ev("defender", 1116, message="Detection Source: On-Demand scan")],
                         trigger_started_iso=TRIG, fidelity_valid=True, had_error=False,
                         static_result=None, axis="behavior")
        self.assertEqual(r.detection_layer, "static")

    def test_defender_behavior_detection(self):
        r = scorer.score([ev("defender", 1015)], trigger_started_iso=TRIG,
                         fidelity_valid=True, had_error=False, static_result=None)
        self.assertEqual(r.state, "detected")
        self.assertEqual(r.detection_layer, "behavior")

    def test_amsi_layer_from_message(self):
        r = scorer.score([ev("defender", 1116, message="AMSI detected: suspicious script")],
                         trigger_started_iso=TRIG, fidelity_valid=True,
                         had_error=False, static_result=None)
        self.assertEqual(r.detection_layer, "amsi")

    def test_not_detected_with_sysmon(self):
        r = scorer.score([ev("sysmon", 1)], trigger_started_iso=TRIG,
                         fidelity_valid=True, had_error=False, static_result=None)
        self.assertEqual(r.state, "not_detected")
        self.assertEqual(r.evidence_source, "sysmon")

    def test_not_detected_static_clean(self):
        r = scorer.score([], trigger_started_iso=TRIG, fidelity_valid=True,
                         had_error=False, static_result="clean")
        self.assertEqual(r.state, "not_detected")

    def test_inconclusive_no_evidence(self):
        r = scorer.score([], trigger_started_iso=TRIG, fidelity_valid=True,
                         had_error=False, static_result=None)
        self.assertEqual(r.state, "inconclusive")

    def test_evidence_source_both(self):
        r = scorer.score([ev("defender", 1116), ev("sysmon", 1)],
                         trigger_started_iso=TRIG, fidelity_valid=True,
                         had_error=False, static_result=None)
        self.assertEqual(r.evidence_source, "both")


class TestFidelity(unittest.TestCase):

    def test_all_signals_valid(self):
        r = fidelity.compute_fidelity(reset_ok=True, technique_ran=True,
                                      collect_window_complete=True, clean_before=True)
        self.assertAlmostEqual(r.score, 1.0, places=3)
        self.assertTrue(r.valid)

    def test_technique_not_run_capped_invalid(self):
        r = fidelity.compute_fidelity(reset_ok=True, technique_ran=False,
                                      collect_window_complete=True, clean_before=True)
        self.assertLessEqual(r.score, 0.30)
        self.assertFalse(r.valid)

    def test_partial_valid(self):
        # reset + technique_ran = 0.65 >= 0.5 -> valid
        r = fidelity.compute_fidelity(reset_ok=True, technique_ran=True,
                                      collect_window_complete=False, clean_before=False)
        self.assertTrue(r.valid)
        self.assertAlmostEqual(r.score, 0.65, places=3)


if __name__ == "__main__":
    unittest.main()
