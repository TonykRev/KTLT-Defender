"""
M8 — DB writer (Chủ: Haiku code boilerplate -> Opus review). STUB.
Khởi tạo schema, mở một `run`, ghi `measurement`, chốt `run`. Mọi bản ghi truy vết được.
Đặc tả: docs/specs/M8-db_writer.md
"""
from __future__ import annotations
import sqlite3
from pathlib import Path


def init_db(db_path: str, schema_path: str) -> sqlite3.Connection:
    """Tạo DB + áp schema nếu chưa có. TODO(worker)."""
    raise NotImplementedError


def start_run(conn: sqlite3.Connection, env: dict) -> int:
    """Mở một phiên đo, ghi môi trường (defender version, cloud_protection...). Trả run_id. TODO."""
    raise NotImplementedError


def write_sample(conn: sqlite3.Connection, sample: dict) -> int:
    """Ghi/Đọc 1 sample theo sha256. Trả sample_id. TODO."""
    raise NotImplementedError


def write_measurement(conn: sqlite3.Connection, run_id: int, record: dict) -> int:
    """Ghi 1 phép đo đầy đủ (state, layer, latency, evidence json...). Trả measurement_id. TODO."""
    raise NotImplementedError


def end_run(conn: sqlite3.Connection, run_id: int) -> None:
    """Đóng phiên đo (ended_at). TODO."""
    raise NotImplementedError
