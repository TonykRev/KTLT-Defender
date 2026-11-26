import subprocess
import unittest
from unittest import mock

import common
from engine import atomic_runner

DEV = {"environment": {"machine_label": "dev-win11"}}
CLOUD = {"environment": {"machine_label": "cloud-vm"}}


def _cp(out="ok", rc=0):
    return subprocess.CompletedProcess(args=[], returncode=rc, stdout=out, stderr="")


class TestAtomicRunner(unittest.TestCase):
    def test_invasive_blocked_on_dev(self):
        with mock.patch.object(common, "run_powershell") as m:
            r = atomic_runner.invoke_atomic("T1003.001", cfg=DEV)
        self.assertFalse(r.ran)
        self.assertFalse(r.exit_ok)
        self.assertIn("blocked", r.stderr)
        m.assert_not_called()

    def test_prefix_invasive_blocked(self):
        with mock.patch.object(common, "run_powershell") as m:
            r = atomic_runner.invoke_atomic("T1562.002", cfg=DEV)
        self.assertFalse(r.ran)
        m.assert_not_called()

    def test_noninvasive_runs_on_dev(self):
        with mock.patch.object(common, "run_powershell", return_value=_cp()) as m:
            r = atomic_runner.invoke_atomic("T1082", cfg=DEV)
        m.assert_called_once()
        self.assertTrue(r.started_iso)
        self.assertTrue(r.ended_iso)
        self.assertTrue(r.ran)
        self.assertTrue(r.exit_ok)

    def test_invasive_allowed_on_cloud(self):
        with mock.patch.object(common, "run_powershell", return_value=_cp()) as m:
            r = atomic_runner.invoke_atomic("T1003.001", cfg=CLOUD)
        m.assert_called_once()
        self.assertTrue(r.ran)

    def test_command_string(self):
        with mock.patch.object(common, "run_powershell", return_value=_cp()) as m:
            atomic_runner.invoke_atomic("T1082", test_number=2, get_prereqs=True,
                                        cleanup=True, cfg=DEV)
        cmd = m.call_args[0][0]
        self.assertIn("Invoke-AtomicTest", cmd)
        self.assertIn("T1082", cmd)
        self.assertIn("-TestNumbers 2", cmd)
        self.assertIn("-GetPrereqs", cmd)
        self.assertIn("-Cleanup", cmd)

    def test_powershell_failure_does_not_crash(self):
        with mock.patch.object(common, "run_powershell", side_effect=OSError("no ps")):
            r = atomic_runner.invoke_atomic("T1082", cfg=DEV)
        self.assertFalse(r.ran)
        self.assertIn("no ps", r.stderr)


if __name__ == "__main__":
    unittest.main()
