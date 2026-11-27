"""
Integration test for the report pipeline (M12): reconstruct_db -> generate.

Rebuilds db/results.sqlite from the validated data and generates the Chapter 4 tables into a temp
dir, asserting the headline numbers match the validated tally (evidence 18). Keeps report/generate.py
honest against the committed data.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from report import reconstruct_db, generate


class ReportPipeline(unittest.TestCase):
    def test_reconstruct_and_generate(self):
        reconstruct_db.main()  # writes db/results.sqlite (gitignored)
        self.assertTrue(os.path.exists(reconstruct_db.DB_PATH))
        with tempfile.TemporaryDirectory() as tmp:
            out_md = generate.generate_report(db_path=reconstruct_db.DB_PATH, out_dir=tmp)
            text = open(out_md, encoding="utf-8").read()
        # Validated headline (evidence 18): 2 detected / 9 not_detected on Axis B.
        self.assertIn("Detected / blocked by Defender: **2**", text)
        self.assertIn("Not detected (gaps): **9**", text)
        self.assertIn("T1059.001", text)
        self.assertIn("T1562.001", text)
        # Cloud-ON delta = 0/3, and YARA FP = 0%.
        self.assertIn("0 / 3", text)
        self.assertIn("0.000%", text)


if __name__ == "__main__":
    unittest.main()
