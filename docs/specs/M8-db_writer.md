# Work-packet M8 — DB writer

**Worker:** Haiku (boilerplate). **Review:** Opus. **File:** `db/db_writer.py` (stub đã có), `db/schema.sql` (XONG — không sửa).

## Mục tiêu
CRUD tối thiểu cho SQLite theo `schema.sql`. Mọi bản ghi truy vết được (hash + giờ + version Defender).

## Hàm (chữ ký đã có trong stub)
- `init_db(db_path, schema_path)`: tạo file + `executescript(schema)`; bật `PRAGMA foreign_keys=ON`. Trả connection.
- `start_run(conn, env)`: INSERT vào `runs` (run_uuid=uuid4, started_at, machine_label, os_*, defender_*,
  cloud_protection_enabled, auto_submit_enabled, sysmon_present, tool_git_commit). Trả `run_id`.
- `write_sample(conn, sample)`: UPSERT theo `sample_sha256` (đã có thì trả id cũ). Trả `sample_id`.
- `write_measurement(conn, run_id, record)`: INSERT đầy đủ 1 phép đo; `created_at=utcnow`;
  `defender_events_json`/`sysmon_events_json` nhận dict/list → `json.dumps`.
- `end_run(conn, run_id)`: UPDATE `ended_at`.

## Acceptance
- `tests/test_db_writer.py`: init DB tạm (`:memory:` hoặc tmp), start_run → write_sample → write_measurement →
  end_run, rồi SELECT lại kiểm đúng giá trị (nhất là state, sha256, defender_sig_version).
- Dùng tham số hoá (`?`) — KHÔNG nối chuỗi SQL.
- `state` chỉ nhận 1 trong 4 giá trị hợp lệ (assert/CHECK ở tầng code).
