# Work-packet M3 — Atomic runner wrapper

**Worker:** Sonnet. **Review:** Opus. **File:** `engine/atomic_runner.py` (stub + dataclass đã có).

## Mục tiêu
Bọc Invoke-AtomicRedTeam để kích hoạt 1 kỹ thuật theo MITRE id, trả thời điểm + trạng thái thực thi.

## Cách làm
- Qua `common.run_powershell`:
  `Import-Module Invoke-AtomicRedTeam; Invoke-AtomicTest <id> -TestNumbers <n> [-GetPrereqs] [-Cleanup]`.
- Ghi `started_iso = utcnow` ngay trước, `ended_iso` ngay sau (để scorer tính cửa sổ thu log).
- `ran`: suy từ việc có chạy được lệnh (exit 0 / có output) — tín hiệu cho fidelity.
- Tách `invoke` (chạy) và `cleanup` để orchestrator kiểm soát.

## RÀNG BUỘC AN TOÀN (bắt buộc)
- Module PHẢI kiểm `cfg['environment']['machine_label']`: nếu `dev-win11` và kỹ thuật nằm trong
  DANH SÁCH XÂM LẤN (T1003, T1562, T1547, T1053, T1555, AMSI bypass...) → **từ chối chạy**, trả
  `AtomicResult(ran=False, exit_ok=False, stderr="blocked on dev machine — xem SAFETY.md")`.
- Chỉ cho chạy đầy đủ khi `machine_label == cloud-vm`.
- Một hằng `INVASIVE_TECHNIQUES = {...}` khai báo rõ trong module.

## Acceptance
- `invoke_atomic("T1082", cfg=dev_cfg)` (discovery vô hại) chạy được trên máy dev (nếu đã cài Invoke-Atomic),
  hoặc trả lỗi rõ ràng nếu chưa cài — KHÔNG crash.
- `invoke_atomic("T1003.001", cfg=dev_cfg)` → bị chặn với thông báo an toàn.
- `tests/test_atomic_runner.py` mock subprocess, kiểm cả nhánh chặn xâm lấn.
