-- =====================================================================
--  CORE CONTRACT: Database schema for the Defender detection measurement tool
--  Every data row must be traceable: sample hash + timestamp + Defender version
--  (Owner: Opus — this is the data backbone, not delegated to workers)
-- =====================================================================
PRAGMA foreign_keys = ON;

-- A "run" = one measurement session (one pass over the matrix). Records the environment for traceability.
CREATE TABLE IF NOT EXISTS runs (
    run_id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    run_uuid                    TEXT NOT NULL UNIQUE,
    started_at                  TEXT NOT NULL,       -- ISO8601 UTC
    ended_at                    TEXT,
    machine_label               TEXT NOT NULL,       -- 'dev-win11' (this machine) | 'cloud-vm' (official measurement)
    os_caption                  TEXT,
    os_version                  TEXT,
    defender_engine_version     TEXT,
    defender_sig_version        TEXT,                -- LOCKED signature version at measurement time
    defender_platform_version   TEXT,
    cloud_protection_enabled    INTEGER,             -- 0/1 — fixed measurement configuration
    auto_submit_enabled         INTEGER,             -- 0/1
    sysmon_present              INTEGER,             -- 0/1
    tool_git_commit             TEXT,                -- tool commit at measurement time (reproducibility)
    notes                       TEXT
);

-- Each built payload sample is recorded with its hash for traceability (axis A: static/AMSI/memory).
CREATE TABLE IF NOT EXISTS samples (
    sample_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    variant         TEXT NOT NULL,                   -- 'v0'|'v1'|'v2'|'v3'
    sample_sha256   TEXT NOT NULL UNIQUE,
    file_path       TEXT,
    size_bytes      INTEGER,
    built_at        TEXT,
    csc_version     TEXT,
    description     TEXT
);

-- Each "measurement" = one atomic measurement: (run, technique/variant) -> exactly 1 state.
CREATE TABLE IF NOT EXISTS measurements (
    measurement_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id              INTEGER NOT NULL REFERENCES runs(run_id),
    axis                TEXT NOT NULL,       -- 'static' (axis A payload) | 'behavior' (axis B atomic)
    technique_id        TEXT,                -- MITRE, e.g. 'T1059.001' (null if purely static measurement)
    scenario_group      TEXT,                -- 'G1'..'G5'
    variant             TEXT,                -- 'v0'..'v3' if axis A
    sample_id           INTEGER REFERENCES samples(sample_id),

    -- Timestamps for latency calculation (ISO8601 UTC)
    reset_done_at       TEXT,
    sample_loaded_at    TEXT,
    static_scan_at      TEXT,
    trigger_started_at  TEXT,
    trigger_ended_at    TEXT,
    collect_until_at    TEXT,

    -- Static scan result (MpCmdRun -Scan)
    static_scan_result  TEXT,                -- 'clean'|'threat_found'|'error'
    static_threat_name  TEXT,

    -- SCORING (Chapter 2: 4 states)
    state               TEXT NOT NULL,       -- 'error'|'inconclusive'|'detected'|'not_detected'
    detection_layer     TEXT,                -- 'static'|'amsi'|'behavior'|'asr'|null
    detect_latency_ms   INTEGER,             -- trigger_started_at -> first detection event
    fidelity_score      REAL,                -- 0..1 fidelity of the measurement
    fidelity_valid      INTEGER,             -- 0/1 whether the measurement is valid

    evidence_source     TEXT,                -- 'defender'|'sysmon'|'both'|'none'
    defender_events_json TEXT,               -- raw evidence (JSON)
    sysmon_events_json  TEXT,
    error_message       TEXT,
    created_at          TEXT NOT NULL
);

-- Measures the false-positive (FP) rate of supplementary rules on a clean goodware set.
CREATE TABLE IF NOT EXISTS rule_fp (
    rule_fp_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name       TEXT NOT NULL,
    rule_type       TEXT NOT NULL,                   -- 'yara'|'sigma'
    technique_id    TEXT,
    goodware_total  INTEGER,
    false_positives INTEGER,
    fp_rate         REAL,
    measured_at     TEXT
);

-- Mapping table between attack techniques and the corresponding ASR rules.
CREATE TABLE IF NOT EXISTS asr_map (
    asr_map_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    technique_id    TEXT NOT NULL,
    asr_rule_guid   TEXT,
    asr_rule_name   TEXT,
    notes           TEXT
);

CREATE INDEX IF NOT EXISTS idx_meas_run   ON measurements(run_id);
CREATE INDEX IF NOT EXISTS idx_meas_state ON measurements(state);
CREATE INDEX IF NOT EXISTS idx_meas_tech  ON measurements(technique_id);
