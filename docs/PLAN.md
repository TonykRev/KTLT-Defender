# Kế hoạch triển khai 4 ngày (đã duyệt)

Mô hình: **Opus = lead/điều phối** (kiến trúc, contract, phần lõi khoa học, review, tích hợp).
**Subagent Sonnet/Haiku = worker** code module theo đặc tả. (Không dùng opencode/DeepSeek.)

- **Opus [O]** tự làm: kiến trúc, interface, schema, `scorer`, `fidelity`, `run_measure`, `reset`, tích hợp, báo cáo.
- **Sonnet [S]**: `log_collector`, `atomic_runner`, payload v2/v3, luật YARA/Sigma.
- **Haiku [H]**: payload v0/v1, `build.ps1`, scenarios YAML, `db_writer` boilerplate, script goodware, README.

## Môi trường
- **Máy Windows 11 này = trạm DEV + chỉ huy.** Build + smoke test + trục đo tĩnh (an toàn). Đã kiểm chứng: csc.exe, MpCmdRun, đọc log Defender đều OK.
- **Cloud VM Windows 11 = trạm ĐO CHÍNH THỨC.** Mọi kỹ thuật xâm lấn + mọi số liệu Chương 4. Bạn vận hành, Opus hướng dẫn.

## Phase
- **Phase 0 (N1 sáng) — Nền móng:** repo + schema + config + docs + đặc tả module + git. *(đang làm)*
- **Phase 1 (N1 chiều→N2) — Build song song:** spawn worker code M1–M11; Opus review + tích hợp; validate phần an toàn trên máy này.
- **Phase 2 (N2 cuối→N3 sáng) — Tích hợp + chạy thử:** end-to-end phần an toàn; hết lỗi tích hợp; DB ghi đủ truy vết.
- **Phase 3 (N3) — Đo thật trên cloud VM:** Opus viết runbook; bạn dựng VM; chạy ma trận rút gọn ~10–15 kỹ thuật × 4 biến thể.
- **Phase 4 (N4) — Luật + kết quả + đóng gói:** YARA/Sigma cho mẫu miss; đo FP trên goodware; ánh xạ ASR; sinh bảng/biểu Chương 4; viết hạn chế; đóng gói. Buffer nửa ngày.

## Module (bám tiến độ)
| # | Module | File | Chủ |
|---|---|---|---|
| M1 | Payload v0–v3 (C#) | `payloads/src/` | H+S |
| M2 | Build script | `payloads/build.ps1` | H |
| M3 | Atomic runner | `engine/atomic_runner.py` | S |
| M4 | 5 nhóm kịch bản | `scenarios/*.yaml` | H |
| M5 | Log collector | `collect/log_collector.py` | S |
| M6 | Fidelity | `score/fidelity.py` | O |
| M7 | Scorer (4 trạng thái) | `score/scorer.py` | O |
| M8 | DB writer + schema | `db/` | H+O |
| M9 | Reset (soft) | `vm/reset.ps1` | O |
| M10 | Vòng điều phối | `run_measure.py` | O |
| M11 | Luật YARA/Sigma | `rules/` | S |
| M12 | FP + ASR + báo cáo | `report/` | O |

## 5 nhóm kịch bản (G1–G5)
- G1 Execution (TA0002): T1059.001 PowerShell, T1059.003 cmd, T1204
- G2 Defense Evasion (TA0005): T1562.001, T1027, T1140, AMSI bypass
- G3 Credential Access (TA0006): T1003.001 LSASS, T1555
- G4 Persistence (TA0003): T1547.001 Run key, T1053.005 scheduled task
- G5 Discovery/LOLBin (TA0007): T1082, T1057, certutil/mshta/regsvr32
