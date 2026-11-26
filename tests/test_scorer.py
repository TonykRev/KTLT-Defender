"""Unit test cho score/scorer.py + score/fidelity.py (Chủ: Opus).
Dùng stand-in cho evidence event (duck-typing) để test độc lập với log_collector.
Chạy từ repo root:  python -m unittest tests.test_scorer -v
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

    def test_defender_signature_detection_latency(self):
        r = scorer.score([ev("defender", 1116)], trigger_started_iso=TRIG,
                         fidelity_valid=True, had_error=False, static_result=None)
        self.assertEqual(r.state, "detected")
        self.assertEqual(r.detection_layer, "static")
        self.assertEqual(r.detect_latency_ms, 5000)  # 10:00:00 -> 10:00:05
        self.assertEqual(r.evidence_source, "defender")

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
