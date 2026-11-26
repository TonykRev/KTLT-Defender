import json
import subprocess
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest import mock

import common
from collect import log_collector as lc

CFG = {"evidence": {
    "defender_log": "Microsoft-Windows-Windows Defender/Operational",
    "sysmon_log": "Microsoft-Windows-Sysmon/Operational",
}}
START = "2026-01-01T00:00:00+00:00"
END = "2026-01-01T00:10:00+00:00"


def fake(stdout="", exc=None):
    def _f(script, timeout=120):
        if exc:
            raise exc
        return SimpleNamespace(stdout=stdout, stderr="", returncode=0)
    return _f


class RealMachine(unittest.TestCase):
    def test_defender_real_returns_list(self):
        end = datetime.now(timezone.utc)
        start = end - timedelta(minutes=10)
        r = lc.collect_defender_events(start.isoformat(), end.isoformat(), CFG)
        self.assertIsInstance(r, list)

    def test_sysmon_absent_returns_empty(self):
        end = datetime.now(timezone.utc)
        start = end - timedelta(minutes=10)
        self.assertEqual(lc.collect_sysmon_events(start.isoformat(), end.isoformat(), CFG), [])


class Mocked(unittest.TestCase):
    def run_with(self, stdout="", exc=None, fn=lc.collect_defender_events):
        with mock.patch.object(common, "run_powershell", fake(stdout, exc)):
            return fn(START, END, CFG)

    def test_single_object(self):
        out = json.dumps({"Id": 1116, "TimeCreated": "2026-01-01T00:05:00.0000000Z", "Message": "Threat: Ünïcödé"})
        r = self.run_with(out)
        self.assertEqual(len(r), 1)
        e = r[0]
        self.assertEqual((e.source, e.event_id), ("defender", 1116))
        self.assertEqual(e.time_created, "2026-01-01T00:05:00.0000000Z")
        self.assertIn("Ünïcödé", e.message)
        self.assertEqual(e.raw["Id"], 1116)

    def test_array(self):
        out = json.dumps([{"Id": i, "TimeCreated": "t", "Message": "m"} for i in (1, 2, 3)])
        r = self.run_with(out, fn=lc.collect_sysmon_events)
        self.assertEqual([e.event_id for e in r], [1, 2, 3])
        self.assertTrue(all(e.source == "sysmon" for e in r))

    def test_edge_cases(self):
        self.assertEqual(self.run_with(""), [])
        self.assertEqual(self.run_with("[]"), [])
        self.assertEqual(self.run_with("not json"), [])
        self.assertEqual(self.run_with(exc=subprocess.TimeoutExpired("powershell", 60)), [])

    def test_collect_all_merges(self):
        out = json.dumps([{"Id": 5, "TimeCreated": "t", "Message": "m"}])
        with mock.patch.object(common, "run_powershell", fake(out)):
            r = lc.collect_all(START, END, CFG)
        self.assertEqual(sorted(e.source for e in r), ["defender", "sysmon"])


if __name__ == "__main__":
    unittest.main()
