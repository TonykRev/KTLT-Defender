# Work-packet M5 — Log collector

**Worker:** Sonnet. **Review:** Opus. **File:** `collect/log_collector.py` (stub + dataclass đã có).

## Mục tiêu
Với cửa sổ thời gian `[start_iso, end_iso]`, trả về list `EvidenceEvent` từ Defender + Sysmon.
Đây là NGUỒN BẰNG CHỨNG độc lập với việc payload "báo thành công" — điểm mạnh khách quan.

## Cách làm
- Dùng `common.run_powershell` gọi `Get-WinEvent -FilterHashtable @{LogName=...; StartTime=...; EndTime=...}`.
  Lấy `Id, TimeCreated, Message`; xuất `ConvertTo-Json`. Parse về `EvidenceEvent`.
- LogName từ `cfg['evidence']['defender_log']` / `['sysmon_log']`.
- Chuyển ISO <-> `[datetime]` cho PowerShell đúng múi giờ (so khớp UTC trong code).
- Sysmon có thể CHƯA cài → `collect_sysmon_events` trả `[]` (bắt lỗi "No events"/log không tồn tại), KHÔNG raise.

## Acceptance
- `collect_defender_events(start,end,cfg)` chạy thật trên máy dev, trả list (có thể rỗng) không lỗi.
- Lọc đúng cửa sổ thời gian (không lấy sự kiện ngoài khoảng).
- Có `tests/test_log_collector.py`: tạo 1 event giả bằng `eventcreate`/ghi test, hoặc mock subprocess,
  khẳng định parse đúng Id/Time/Message.
- Không phụ thuộc pywin32 — chỉ PowerShell qua subprocess.

## Edge cases
Log rỗng, JSON trả 1 object (không phải list) khi chỉ 1 event, ký tự Unicode trong Message, timeout.
