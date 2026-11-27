"""
Validation for the supplementary rule set (M11, rules/).

- Sigma rules: always checked — valid YAML + required schema fields (no extra deps).
- YARA rules: checked only when yara-python is installed (skipped otherwise, so the core suite still
  runs on a plain Python). When present, the rules are compiled and must fire on the real encoded
  sample and the built loader binaries, and must NOT fire on random benign data.
"""
import base64
import glob
import os
import unittest

try:
    import yara  # yara-python
    HAVE_YARA = True
except Exception:
    HAVE_YARA = False

try:
    import yaml
    HAVE_YAML = True
except Exception:
    HAVE_YAML = False

# The project's encoded EICAR constant (XOR 0x5A + Base64). base64-decoding it yields the exact bytes
# written to sample_v1.bin. This is the obfuscated form, not the raw signature.
ENC = ("Am8Vewp/GhsKAW4GCgACb25yCgRzbRkZc20nfh8TGRsIdwkOGxQeGwgedxsUDhMMEwgPCXcOHwkO"
       "dxwTFh97fhJxEnA=")

YARA_GLOB = "rules/yara/*.yar"
SIGMA_GLOB = "rules/sigma/*.yml"


@unittest.skipUnless(HAVE_YAML, "pyyaml not installed")
class SigmaRules(unittest.TestCase):
    def test_all_parse_and_have_schema(self):
        files = glob.glob(SIGMA_GLOB)
        self.assertTrue(files, "no Sigma rules found")
        ids = set()
        for f in files:
            with open(f, encoding="utf-8") as fh:
                d = yaml.safe_load(fh)
            for key in ("title", "id", "status", "description", "logsource", "detection"):
                self.assertIn(key, d, f"{f}: missing '{key}'")
            self.assertIn("condition", d["detection"], f"{f}: detection has no condition")
            self.assertNotIn(d["id"], ids, f"{f}: duplicate rule id")
            ids.add(d["id"])


@unittest.skipUnless(HAVE_YARA, "yara-python not installed")
class YaraRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        files = glob.glob(YARA_GLOB)
        assert files, "no YARA rules found"
        cls.rules = yara.compile(filepaths={os.path.basename(f): f for f in files})

    def test_encoded_sample_rule_matches_v1_bytes(self):
        sample_v1 = base64.b64decode(ENC)
        hit = [r.rule for r in self.rules.match(data=sample_v1)]
        self.assertIn("KTLD_Encoded_Sample_On_Disk", hit)

    def test_loader_rule_matches_built_exes(self):
        exes = glob.glob("payloads/out/*.exe")
        if not exes:
            self.skipTest("no built loader .exe in payloads/out")
        for exe in exes:
            hit = [r.rule for r in self.rules.match(exe)]
            self.assertIn("KTLD_Payload_Loader_Binary", hit, f"loader rule missed {exe}")

    def test_no_false_positive_on_random(self):
        hit = [r.rule for r in self.rules.match(data=os.urandom(4096))]
        self.assertEqual(hit, [])


if __name__ == "__main__":
    unittest.main()
