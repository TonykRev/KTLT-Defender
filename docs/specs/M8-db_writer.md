# Work Packet M8 — DB Writer

**Worker:** Haiku (boilerplate). **Review:** Opus. **File:** `db/db_writer.py` (stub exists), `db/schema.sql` (COMPLETE — do not edit).

## Goal
Minimal CRUD for SQLite per `schema.sql`. Every record is traceable (hash + time + Defender version).

## Functions (signatures already in the stub)
- `init_db(db_path, schema_path)`: create the file + `executescript(schema)`; enable `PRAGMA foreign_keys=ON`. Return the connection.
- `start_run(conn, env)`: INSERT into `runs` (run_uuid=uuid4, started_at, machine_label, os_*, defender_*,
  cloud_protection_enabled, auto_submit_enabled, sysmon_present, tool_git_commit). Return `run_id`.
- `write_sample(conn, sample)`: UPSERT by `sample_sha256` (if it exists, return the existing id). Return `sample_id`.
- `write_measurement(conn, run_id, record)`: INSERT one full measurement; `created_at=utcnow`;
  `defender_events_json`/`sysmon_events_json` accept dict/list → `json.dumps`.
- `end_run(conn, run_id)`: UPDATE `ended_at`.

## Acceptance
- `tests/test_db_writer.py`: init a temp DB (`:memory:` or tmp), start_run → write_sample → write_measurement →
  end_run, then SELECT back and verify exact values (especially state, sha256, defender_sig_version).
- Use parameterized queries (`?`) — do NOT concatenate SQL strings.
- `state` accepts only one of the 4 valid values (assert/CHECK at the code level).
