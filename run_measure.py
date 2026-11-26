"""
M10 — Vòng điều phối chính (Chủ: Opus). SKELETON — contract tích hợp giữa các khối.

Mỗi phép đo chạy đúng chuỗi:
  reset sạch -> nạp mẫu -> quét tĩnh (MpCmdRun) -> kích hoạt kỹ thuật ->
  thu log (Defender + Sysmon) -> tính fidelity -> chấm 1/4 trạng thái -> ghi SQLite.

Chạy:  python run_measure.py --plan scenarios/g5_discovery.yaml   (ví dụ)
       python run_measure.py --static-only                        (chỉ trục A trên máy dev)
"""
from __future__ import annotations
import argparse
import time

import common
# from vm import reset            # M9
# from collect import log_collector  # M5
# from score import scorer, fidelity # M6,M7
# from engine import atomic_runner    # M3
# from db import db_writer            # M8


def measure_one(conn, run_id, item, cfg) -> dict:
    """
    Thực hiện 1 phép đo nguyên tử cho 1 (kỹ thuật/biến thể).
    TODO(Opus, Phase 1-2): ghép các bước theo đúng chuỗi ở docstring module.
    """
    raise NotImplementedError


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan", help="file kịch bản YAML (scenarios/*.yaml)")
    ap.add_argument("--static-only", action="store_true",
                    help="chỉ chạy trục đo tĩnh (an toàn trên máy dev)")
    ap.add_argument("--config", default="config.yaml")
    args = ap.parse_args()

    cfg = common.load_config(args.config)
    env = {
        "machine_label": cfg["environment"]["machine_label"],
        "defender": common.get_defender_status(),
        "started_at": common.utcnow_iso(),
    }
    print("[run_measure] môi trường:", env)
    print("[run_measure] SKELETON — các bước đo sẽ được ghép ở Phase 1-2.")
    # conn = db_writer.init_db(cfg["database"]["path"], cfg["database"]["schema"])
    # run_id = db_writer.start_run(conn, env)
    # ... vòng lặp measure_one ...
    # db_writer.end_run(conn, run_id)


if __name__ == "__main__":
    main()
