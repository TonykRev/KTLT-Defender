# Công cụ tự động đánh giá khả năng phát hiện của Windows Defender (Win11) + bộ luật bổ sung

Bài tập lớn môn KTLT — Học viện Kỹ thuật Mật mã.
Nhóm: Trần Quang Huy, Nguyễn Văn Thành, Nguyễn Viết Nhật Long, Nguyễn Việt Hiếu. GVHD: Thầy Nguyễn Mạnh Thắng.

## Mục tiêu
Định lượng: Defender trên Windows 11 phát hiện **bao nhiêu** kỹ thuật tấn công, **ở tầng nào**, **mất bao lâu**, và **thiếu luật** cho kỹ thuật nào — rồi đề xuất bộ luật YARA/Sigma bổ sung có đo tỉ lệ báo nhầm (FP) và ánh xạ ASR.

Mọi dòng số liệu truy vết được: **hash mẫu + thời điểm + phiên bản Defender**.

## Kiến trúc (3 khối — khớp Chương 3 đề cương)
- **Khối 1 — Sinh mẫu thử:** 4 biến thể payload C# (`payloads/`), đo trục TĨNH/AMSI/bộ nhớ.
  - v0 mẫu trần · v1 +mã hoá chuỗi · v2 +thực thi từ đĩa · v3 +thực thi từ bộ nhớ.
- **Khối 2 — Động cơ hành vi:** Invoke-AtomicRedTeam (`engine/`, `scenarios/`), 5 nhóm kịch bản G1–G5, đo trục HÀNH VI/ASR.
- **Khối 3 — Trạm đo tự động:** vòng lặp mỗi phép đo (`run_measure.py`):
  reset sạch → nạp mẫu → quét tĩnh (MpCmdRun) → kích hoạt kỹ thuật →
  thu log (Defender + Sysmon) → tính fidelity → chấm 1/4 trạng thái → ghi SQLite.

## Cây thư mục
```
payloads/   M1,M2  4 biến thể C# + build.ps1
engine/     M3     wrapper Invoke-AtomicRedTeam
scenarios/  M4     5 nhóm kịch bản G1–G5 (*.yaml)
collect/    M5     đọc Event Log Defender + Sysmon
score/      M6,M7  fidelity + scorer (4 trạng thái)
db/         M8     schema.sql + db_writer + results.sqlite
vm/         M9     reset.ps1 (soft-reset)
rules/      M11    luật YARA + Sigma bổ sung
report/     M12    sinh bảng/biểu Chương 4 + FP + ASR
run_measure.py M10 vòng điều phối chính
docs/       PLAN, SAFETY, đặc tả module (specs/)
tests/             unit test
```

## ⚠️ An toàn — ĐỌC TRƯỚC KHI CHẠY
Xem [docs/SAFETY.md](docs/SAFETY.md). Tóm tắt: **máy dev (Windows cá nhân) chỉ build + đo an toàn**;
mọi kỹ thuật xâm lấn (dump LSASS, tắt Defender, persistence...) và **mọi số liệu chính thức** chỉ chạy
trên **cloud VM cô lập, có snapshot**. Payload là vô hại, chỉ để đo tầng phát hiện.

## Trạng thái
Đang ở Phase 0 (dựng nền). Xem [docs/PLAN.md](docs/PLAN.md).
