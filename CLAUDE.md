# CLAUDE.md — Bộ nhớ dự án (đọc đầu mỗi session)

> **LUÔN đọc `docs/PLAN.md` + `docs/SAFETY.md` TRƯỚC KHI LÀM bất cứ việc gì.**
> File này ngắn gọn, cập nhật mỗi khi chốt điều quan trọng hoặc đóng băng tiến độ.

## 🎯 Mục tiêu đề tài
Xây dựng **công cụ tự động đánh giá khả năng phát hiện tấn công của Windows Defender trên Windows 11**,
và **xây dựng bộ luật phát hiện bổ sung** (YARA/Sigma) cho những mẫu Defender bỏ lọt.
Môn KTLT — Học viện Kỹ thuật Mật mã. Nhóm 4 người (Trần Quang Huy + 3). GVHD: Thầy Nguyễn Mạnh Thắng.
Repo public: https://github.com/TonykRev/KTLT-Defender

## 🧭 Cách làm việc (đã chốt)
- **Opus = lead/điều phối**: kiến trúc, contract, phần lõi (scorer, fidelity, run_measure, reset), review, tích hợp, báo cáo.
- **Subagent Sonnet/Haiku = worker** code module theo đặc tả. **KHÔNG dùng opencode/DeepSeek.**
- ⑤ Khi điều phối subagent: subagent **không đọc được hội thoại**, chỉ đọc file mình chỉ → luôn nói rõ
  *"làm theo spec trong `docs/specs/Mx-….md`"* và nêu file input/output cụ thể.

## 🔬 Thiết kế đo (đã chốt)
- **2 trục:** Trục A = 4 biến thể payload C# (v0 trần, v1 mã hoá chuỗi, v2 disk-exec, v3 memory-exec);
  Trục B = Invoke-AtomicRedTeam theo 5 nhóm **G1–G5** ánh xạ MITRE ATT&CK.
- **4 trạng thái chấm điểm:** `error` / `inconclusive` / `detected` / `not_detected`.
- **Bằng chứng:** log `Microsoft-Windows-Windows Defender/Operational` (event ID 1006/1015/1116/1117/1118/1119…) + Sysmon.
- **Truy vết:** mỗi phép đo = SHA-256 mẫu + timestamp + phiên bản chữ ký Defender → bảng `runs`/`measurements`.

## 🧱 Quy ước code
- **Python 3.12**, chỉ dùng chuẩn + `pyyaml`. **Test bằng `unittest`** (không pytest): `python -m unittest`.
- Tương tác Windows (Get-WinEvent, csc, MpCmdRun) gọi qua `common.run_powershell()`; **mọi SQL tham số hoá**.
- **state** phải ∈ `{error, inconclusive, detected, not_detected}` (db_writer assert).
- **EICAR mã hoá XOR(0x5A)+Base64 trong source** → repo & binaries sạch (Defender không cờ source/clone).
  Chỉ khi *chạy* v0/v2 mới thả EICAR trần ra đĩa → Defender phản ứng = chính phép đo.
- Compile bằng **csc.exe .NET Framework v4.0.30319** (không cần Visual Studio / .NET SDK).
- Git identity local: `KTLT Defender Dev <dev@localhost>`. Commit theo phase/wave, mô tả tiếng Việt.

## 🛡️ Ranh giới an toàn (xem đủ ở `docs/SAFETY.md`)
`config.yaml → environment.machine_label` điều khiển khoá an toàn:
- **🟢 `dev-win11` (máy này, mặc định):** CHỈ build, smoke test, quét tĩnh (MpCmdRun), tối đa 1–2 Atomic
  discovery vô hại (T1082/T1057). `atomic_runner` **CHẶN** mọi kỹ thuật xâm lấn; `reset.ps1` **KHÔNG** đụng Defender/log.
- **🔴 `cloud-vm`:** nơi chạy kỹ thuật xâm lấn thật (LSASS T1003, tắt Defender T1562, persistence T1547/T1053, cred T1555)
  và **mọi số liệu chính thức Chương 4**. VM cô lập mạng, có snapshot sạch.

## 📌 STATUS (cập nhật cuối mỗi phase)
_Cập nhật: 2026-11-27_
- ✅ **Phase 0** — Nền móng: schema + config + docs + đặc tả + git. Đã push GitHub.
- ✅ **Phase 1** — Build song song (phần an toàn): `log_collector`(M5), `db_writer`(M8), `scorer`(M7),
  `fidelity`(M6) + **21 unit test pass**; payloads v0–v3 + `build.ps1` (compile sạch 4608B); `atomic_runner`(M3)
  có guard chặn xâm lấn; scenarios G1–G5 + `reset.ps1` có khoá dev/cloud.
- ⏳ **Phase 2 (ĐANG TỚI)** — Tích hợp: **`run_measure.py`(M10) hiện CÒN STUB** → cần hiện thực vòng điều phối
  (reset → build/arm → trigger → collect → score → ghi DB), rồi **smoke test end-to-end** trên máy dev
  (chạy v0/v2 sẽ thả EICAR benign → Defender cách ly; cần user bật đèn xanh "Chạy luôn" trước khi chạy).
- ⬜ **Phase 3** — Đo thật trên cloud VM (runbook + ma trận rút gọn).
- ⬜ **Phase 4** — Luật YARA/Sigma(M11, `rules/`) + FP goodware + ASR + báo cáo(M12, `report/generate.py` còn stub) + bảng Chương 4.

**Việc tiếp theo:** hiện thực `run_measure.py` (M10) rồi smoke test an toàn trên máy dev.

## 🔁 Thói quen cập nhật file này
- Chốt điều quan trọng → ghi vào mục tương ứng ngay.
- Cuối buổi/phase → cập nhật mục **STATUS** (đã xong / đang dở / việc tiếp theo / lưu ý).
- **Làm xong phase nào → commit + push GitHub luôn.**
