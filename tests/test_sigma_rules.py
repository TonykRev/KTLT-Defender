"""
Logical validation of the Sigma rules (M11) as unit tests.

Each rule must fire on a synthetic event modelling the measured atomic behaviour (true positive) and
must NOT fire on a benign event (no false positive). This checks rule logic/specificity; live-telemetry
validation is blocked on the VM (Sysmon unavailable).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import yaml  # noqa: F401
    HAVE_YAML = True
except Exception:
    HAVE_YAML = False


@unittest.skipUnless(HAVE_YAML, "pyyaml not installed")
class SigmaLogic(unittest.TestCase):
    def test_every_rule_fires_on_positive_and_not_on_benign(self):
        from rules import sigma_validate
        results = sigma_validate.validate_all(verbose=False)
        self.assertTrue(results, "no sigma rules found")
        for stem, tp, fp, status in results:
            self.assertNotEqual(status, "NO TEST CASE", f"{stem}: add a validation case")
            self.assertTrue(tp, f"{stem}: rule did not fire on its positive event")
            self.assertFalse(fp, f"{stem}: rule false-fired on the benign event")
            self.assertEqual(status, "OK", f"{stem}: {status}")


if __name__ == "__main__":
    unittest.main()
