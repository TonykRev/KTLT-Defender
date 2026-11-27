"""
Unit tests for run_measure.py (M10 orchestrator).

All Windows / subprocess interactions (reset, detonate, static scan, log
collection, DB writes) are mocked, so these tests are fully OS-independent and
activate NOTHING. The scorer and fidelity modules are exercised for real so the
integration between them and measure_one is validated end-to-end.
"""
import unittest
from types import SimpleNamespace
from unittest import mock

import run_measure as rm


CFG = {
    "payloads": {"variants": ["v0", "v1", "v2", "v3"], "out_dir": "payloads/out"},
    "timing": {"collect_window_s": 0, "reset_timeout_s": 60},
    "scoring": {"states": ["error", "inconclusive", "detected", "not_detected"],
                "fidelity_min_valid": 0.5},
    "environment": {"machine_label": "dev-win11"},
    "evidence": {"defender_log": "D", "sysmon_log": "S"},
}


def _args(**kw):
    base = dict(static=False, static_only=False, plan=None,
                all_behavior=False, variants=None)
    base.update(kw)
    return SimpleNamespace(**base)


class BuildMatrix(unittest.TestCase):
    def test_static_all_variants(self):
        m = rm.build_matrix(_args(static=True), CFG)
        self.assertEqual([it["variant"] for it in m], ["v0", "v1", "v2", "v3"])
        self.assertTrue(all(it["axis"] == "static" for it in m))

    def test_static_variant_filter(self):
        m = rm.build_matrix(_args(static=True, variants="v0,v2"), CFG)
        self.assertEqual([it["variant"] for it in m], ["v0", "v2"])

    def test_static_only_excludes_behavior(self):
        # static_only must ignore --plan / --all-behavior entirely
        m = rm.build_matrix(_args(static_only=True, all_behavior=True), CFG)
        self.assertTrue(m)
        self.assertTrue(all(it["axis"] == "static" for it in m))

    def test_empty_when_nothing_selected(self):
        self.assertEqual(rm.build_matrix(_args(), CFG), [])


class LoadPlan(unittest.TestCase):
    def test_parses_scenario(self):
        items = rm.load_plan("scenarios/g5_discovery_lolbin.yaml")
        self.assertTrue(items)
        self.assertTrue(all(it["axis"] == "behavior" for it in items))
        self.assertTrue(all(it["scenario_group"] == "G5" for it in items))
        ids = {it["technique_id"] for it in items}
        self.assertIn("T1082", ids)
        # non-invasive discovery techniques in this group
        self.assertTrue(all(it["invasive"] is False for it in items))


class SplitEvidence(unittest.TestCase):
    def test_split_by_source(self):
        ev = [
            SimpleNamespace(source="defender", event_id=1116,
                            time_created="t1", message="m1"),
            SimpleNamespace(source="sysmon", event_id=1,
                            time_created="t2", message="m2"),
            SimpleNamespace(source="other", event_id=9,
                            time_created="t3", message="m3"),
        ]
        defender, sysmon = rm._split_evidence(ev)
        self.assertEqual(len(defender), 1)
        self.assertEqual(len(sysmon), 1)
        self.assertEqual(defender[0]["event_id"], 1116)
        self.assertEqual(sysmon[0]["event_id"], 1)


class PsQuote(unittest.TestCase):
    def test_escapes_single_quote(self):
        self.assertEqual(rm._ps_quote("a'b"), "a''b")


class MeasureOneStatic(unittest.TestCase):
    """measure_one on a static item: reset OK + threat_found -> state 'detected'."""

    def _run(self, static_result, had_reset=True):
        item = {"axis": "static", "variant": "v0",
                "sample": {"sha256": "a" * 64, "path": "payloads/out/v0.exe",
                           "size": 4608}}
        patches = {
            "run_reset": mock.Mock(return_value={
                "reset_ok": had_reset, "reset_done_at": "2026-01-01T00:00:00+00:00",
                "actions": []}),
            "detonate_payload": mock.Mock(return_value={
                "trigger_started_at": "2026-01-01T00:00:01+00:00",
                "trigger_ended_at": "2026-01-01T00:00:02+00:00",
                "ran": True, "dropped_path": "payloads/out/sample_v0.bin",
                "exe_path": "payloads/out/v0.exe", "stdout": "VARIANT=v0", "stderr": ""}),
            "static_scan": mock.Mock(return_value={
                "result": static_result, "threat_name": "Virus:DOS/EICAR_Test_File",
                "scan_at": "2026-01-01T00:00:03+00:00"}),
            "wait_collect_window": mock.Mock(return_value=True),
            "collect_evidence": mock.Mock(return_value=[]),
        }
        with mock.patch.multiple(rm, **patches), \
             mock.patch.object(rm.db_writer, "write_sample", return_value=7) as ws, \
             mock.patch.object(rm.db_writer, "write_measurement", return_value=99) as wm:
            rec = rm.measure_one(conn=object(), run_id=1, item=item, cfg=CFG)
        return rec, ws, wm

    def test_threat_found_is_detected(self):
        rec, ws, wm = self._run("threat_found")
        self.assertEqual(rec["state"], "detected")
        self.assertEqual(rec["static_scan_result"], "threat_found")
        self.assertEqual(rec["axis"], "static")
        self.assertEqual(rec["variant"], "v0")
        self.assertEqual(rec["sample_id"], 7)
        self.assertEqual(rec["measurement_id"], 99)
        self.assertEqual(rec["fidelity_valid"], 1)
        ws.assert_called_once()
        wm.assert_called_once()

    def test_clean_is_not_detected(self):
        rec, _, _ = self._run("clean")
        self.assertEqual(rec["state"], "not_detected")

    def test_written_state_is_always_valid(self):
        rec, _, _ = self._run("threat_found")
        self.assertIn(rec["state"], CFG["scoring"]["states"])


class MeasureOneBehaviorBlocked(unittest.TestCase):
    """On dev-win11 an invasive behavior technique must be blocked, not executed."""

    def test_invasive_blocked_on_dev(self):
        item = {"axis": "behavior", "technique_id": "T1003.001",
                "scenario_group": "G3", "test_number": 1, "invasive": True}
        with mock.patch.multiple(
                rm,
                run_reset=mock.Mock(return_value={
                    "reset_ok": True, "reset_done_at": "2026-01-01T00:00:00+00:00"}),
                wait_collect_window=mock.Mock(return_value=True),
                collect_evidence=mock.Mock(return_value=[])), \
             mock.patch.object(rm.db_writer, "write_measurement", return_value=5):
            # real atomic_runner.invoke_atomic -> blocked path (no PowerShell call)
            rec = rm.measure_one(conn=object(), run_id=1, item=item, cfg=CFG)
        # Blocked technique did not run -> not a 'detected' result; a row is still written.
        self.assertEqual(rec["measurement_id"], 5)
        self.assertEqual(rec["technique_id"], "T1003.001")
        self.assertIn(rec["state"], CFG["scoring"]["states"])


if __name__ == "__main__":
    unittest.main()
