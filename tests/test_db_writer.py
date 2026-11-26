"""Unit tests for db/db_writer.py (M8). Run from the repo root directory."""
import json
import os
import shutil
import sqlite3
import tempfile
import unittest

from db import db_writer

SCHEMA = os.path.join("db", "schema.sql")


class TestDbWriter(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test.db")
        self.conn = db_writer.init_db(self.db_path, SCHEMA)

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_full_flow_roundtrip(self):
        env = {
            "machine_label": "dev-win11",
            "os_caption": "Windows 11 Home",
            "os_version": "10.0.26200",
            "defender": {
                "AMEngineVersion": "1.1",
                "AntivirusSignatureVersion": "1.463",
                "AMProductVersion": "4.18",
            },
        }
        run_id = db_writer.start_run(self.conn, env)

        sample_id = db_writer.write_sample(
            self.conn,
            {"variant": "v0", "sample_sha256": "abc123", "size_bytes": 100},
        )
        same_id = db_writer.write_sample(
            self.conn,
            {"variant": "v0", "sample_sha256": "abc123", "size_bytes": 100},
        )
        self.assertEqual(sample_id, same_id)

        meas_id = db_writer.write_measurement(
            self.conn,
            run_id,
            {
                "axis": "static",
                "variant": "v0",
                "sample_id": sample_id,
                "state": "detected",
                "detection_layer": "static",
                "evidence_source": "defender",
                "defender_events_json": [{"id": 1116}],
            },
        )
        db_writer.end_run(self.conn, run_id)

        cur = self.conn.cursor()
        sig, = cur.execute(
            "SELECT defender_sig_version FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        self.assertEqual(sig, "1.463")

        ended, = cur.execute(
            "SELECT ended_at FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        self.assertIsNotNone(ended)

        state, events_json = cur.execute(
            "SELECT state, defender_events_json FROM measurements WHERE measurement_id = ?",
            (meas_id,),
        ).fetchone()
        self.assertEqual(state, "detected")
        self.assertEqual(json.loads(events_json), [{"id": 1116}])

        count, = cur.execute("SELECT COUNT(*) FROM samples").fetchone()
        self.assertEqual(count, 1)

    def test_invalid_state_rejected(self):
        run_id = db_writer.start_run(self.conn, {"machine_label": "dev-win11"})
        with self.assertRaises(AssertionError):
            db_writer.write_measurement(self.conn, run_id, {"state": "bogus"})


if __name__ == "__main__":
    unittest.main()
