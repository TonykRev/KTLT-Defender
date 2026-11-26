"""
M8 — DB writer (Owner: Haiku code boilerplate -> Opus review).
Initializes the schema, opens a `run`, writes `measurement` records, and closes the `run`. Every record is traceable.
Specification: docs/specs/M8-db_writer.md
"""
from __future__ import annotations
import json
import sqlite3
import uuid
from pathlib import Path

import common

VALID_STATES = ("error", "inconclusive", "detected", "not_detected")


def init_db(db_path: str, schema_path: str) -> sqlite3.Connection:
    """Create the DB and apply the schema if it does not exist yet."""
    conn = sqlite3.connect(db_path)
    schema_text = Path(schema_path).read_text(encoding="utf-8")
    conn.executescript(schema_text)
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def start_run(conn: sqlite3.Connection, env: dict) -> int:
    """Open a measurement session and record the environment (defender version, cloud_protection...). Returns run_id."""
    defender = env.get("defender") or {}
    cur = conn.execute(
        """
        INSERT INTO runs (
            run_uuid, started_at, machine_label, os_caption, os_version,
            defender_engine_version, defender_sig_version, defender_platform_version,
            cloud_protection_enabled, auto_submit_enabled, sysmon_present,
            tool_git_commit, notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            str(uuid.uuid4()),
            common.utcnow_iso(),
            env.get("machine_label", None),
            env.get("os_caption", None),
            env.get("os_version", None),
            defender.get("AMEngineVersion", env.get("defender_engine_version", None)),
            defender.get("AntivirusSignatureVersion", env.get("defender_sig_version", None)),
            defender.get("AMProductVersion", env.get("defender_platform_version", None)),
            env.get("cloud_protection_enabled", None),
            env.get("auto_submit_enabled", None),
            env.get("sysmon_present", None),
            env.get("tool_git_commit", None),
            env.get("notes", None),
        ),
    )
    conn.commit()
    return cur.lastrowid


def write_sample(conn: sqlite3.Connection, sample: dict) -> int:
    """Write/read 1 sample keyed by sha256 (UPSERT). Returns sample_id."""
    sha = sample["sample_sha256"]
    row = conn.execute(
        "SELECT sample_id FROM samples WHERE sample_sha256 = ?", (sha,)
    ).fetchone()
    if row is not None:
        return row[0]
    cur = conn.execute(
        """
        INSERT INTO samples (
            variant, sample_sha256, file_path, size_bytes, built_at, csc_version, description
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            sample.get("variant", None),
            sha,
            sample.get("file_path", None),
            sample.get("size_bytes", None),
            sample.get("built_at", None),
            sample.get("csc_version", None),
            sample.get("description", None),
        ),
    )
    conn.commit()
    return cur.lastrowid


def _as_json_text(value):
    """dict/list -> JSON string; None and strings are kept unchanged."""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return value


def write_measurement(conn: sqlite3.Connection, run_id: int, record: dict) -> int:
    """Write 1 complete measurement (state, layer, latency, evidence json...). Returns measurement_id."""
    state = record["state"]
    assert state in VALID_STATES, f"invalid state: {state!r}"
    cur = conn.execute(
        """
        INSERT INTO measurements (
            run_id, axis, technique_id, scenario_group, variant, sample_id,
            reset_done_at, sample_loaded_at, static_scan_at,
            trigger_started_at, trigger_ended_at, collect_until_at,
            static_scan_result, static_threat_name,
            state, detection_layer, detect_latency_ms, fidelity_score, fidelity_valid,
            evidence_source, defender_events_json, sysmon_events_json,
            error_message, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            record.get("axis", None),
            record.get("technique_id", None),
            record.get("scenario_group", None),
            record.get("variant", None),
            record.get("sample_id", None),
            record.get("reset_done_at", None),
            record.get("sample_loaded_at", None),
            record.get("static_scan_at", None),
            record.get("trigger_started_at", None),
            record.get("trigger_ended_at", None),
            record.get("collect_until_at", None),
            record.get("static_scan_result", None),
            record.get("static_threat_name", None),
            state,
            record.get("detection_layer", None),
            record.get("detect_latency_ms", None),
            record.get("fidelity_score", None),
            record.get("fidelity_valid", None),
            record.get("evidence_source", None),
            _as_json_text(record.get("defender_events_json", None)),
            _as_json_text(record.get("sysmon_events_json", None)),
            record.get("error_message", None),
            common.utcnow_iso(),
        ),
    )
    conn.commit()
    return cur.lastrowid


def end_run(conn: sqlite3.Connection, run_id: int) -> None:
    """Close the measurement session (ended_at)."""
    conn.execute(
        "UPDATE runs SET ended_at = ? WHERE run_id = ?",
        (common.utcnow_iso(), run_id),
    )
    conn.commit()
