-- =====================================================================
--  CONTRACT LÕI: Schema CSDL cho công cụ đo khả năng phát hiện của Defender
--  Mọi dòng số liệu phải truy vết được: hash mẫu + thời điểm + phiên bản Defender
--  (Chủ: Opus — đây là xương sống dữ liệu, không giao worker)
-- =====================================================================
PRAGMA foreign_keys = ON;

-- Một "run" = một phiên đo (một lượt chạy ma trận). Ghi lại môi trường để truy vết.
CREATE TABLE IF NOT EXISTS runs (
    run_id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    run_uuid                    TEXT NOT NULL UNIQUE,
    started_at                  TEXT NOT NULL,       -- ISO8601 UTC
    ended_at                    TEXT,
    machine_label               TEXT NOT NULL,       -- 'dev-win11' (máy này) | 'cloud-vm' (đo chính thức)
    os_caption                  TEXT,
    os_version                  TEXT,
    defender_engine_version     TEXT,
    defender_sig_version        TEXT,                -- KHÓA phiên bản chữ ký lúc đo
    defender_platform_version   TEXT,
    cloud_protection_enabled    INTEGER,             -- 0/1 — cấu hình đo cố định
    auto_submit_enabled         INTEGER,             -- 0/1
    sysmon_present              INTEGER,             -- 0/1
    tool_git_commit             TEXT,                -- commit công cụ lúc đo (tái lập)
    notes                       TEXT
);

-- Mỗi payload sample được build → ghi hash để truy vết (trục A: tĩnh/AMSI/bộ nhớ).
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

-- Mỗi "measurement" = một phép đo nguyên tử: (run, kỹ thuật/biến thể) → đúng 1 trạng thái.
CREATE TABLE IF NOT EXISTS measurements (
    measurement_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id              INTEGER NOT NULL REFERENCES runs(run_id),
    axis                TEXT NOT NULL,       -- 'static' (trục A payload) | 'behavior' (trục B atomic)
    technique_id        TEXT,                -- MITRE, vd 'T1059.001' (null nếu đo trục tĩnh thuần)
    scenario_group      TEXT,                -- 'G1'..'G5'
    variant             TEXT,                -- 'v0'..'v3' nếu trục A
    sample_id           INTEGER REFERENCES samples(sample_id),

    -- Các mốc thời gian để tính độ trễ (ISO8601 UTC)
    reset_done_at       TEXT,
    sample_loaded_at    TEXT,
    static_scan_at      TEXT,
    trigger_started_at  TEXT,
    trigger_ended_at    TEXT,
    collect_until_at    TEXT,

    -- Kết quả quét tĩnh (MpCmdRun -Scan)
    static_scan_result  TEXT,                -- 'clean'|'threat_found'|'error'
    static_threat_name  TEXT,

    -- CHẤM ĐIỂM (Chương 2: 4 trạng thái)
    state               TEXT NOT NULL,       -- 'error'|'inconclusive'|'detected'|'not_detected'
    detection_layer     TEXT,                -- 'static'|'amsi'|'behavior'|'asr'|null
    detect_latency_ms   INTEGER,             -- trigger_started_at -> sự kiện phát hiện đầu tiên
    fidelity_score      REAL,                -- 0..1 độ trung thực của phép đo
    fidelity_valid      INTEGER,             -- 0/1 phép đo có hợp lệ không

    evidence_source     TEXT,                -- 'defender'|'sysmon'|'both'|'none'
    defender_events_json TEXT,               -- bằng chứng thô (JSON)
    sysmon_events_json  TEXT,
    error_message       TEXT,
    created_at          TEXT NOT NULL
);

-- Đo tỉ lệ báo nhầm (FP) của luật bổ sung trên tập goodware lành.
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

-- Bảng ánh xạ kỹ thuật tấn công ↔ luật ASR tương ứng.
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
