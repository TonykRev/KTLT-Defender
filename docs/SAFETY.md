# Ranh giới an toàn & phạm vi (ĐỌC TRƯỚC KHI CHẠY)

Dự án này kích hoạt các kỹ thuật tấn công đã chuẩn hoá (Invoke-AtomicRedTeam) **chỉ để đo** xem Defender
có phát hiện không. Payload tự viết là **vô hại** (benign) — chỉ mang chuỗi/hành vi "trông giống mã độc"
để đo tầng quét, không gây hại thật.

## Hai môi trường — tách rạch ròi

### 🟢 Máy DEV (Windows 11 cá nhân này) — CHỈ:
- Viết code, compile 4 payload C#, viết luật YARA/Sigma.
- **Smoke test**: code chạy được, parse log thật được, ghi DB được, chấm điểm đúng.
- **Trục đo tĩnh**: quét file payload bằng MpCmdRun (vô hại — chỉ quét file trên đĩa).
- (Tuỳ chọn) 1–2 Atomic discovery vô hại (T1082, T1057) để test đường ống thu log.

### 🔴 KHÔNG chạy trên máy DEV — để dành CLOUD VM:
- Kỹ thuật xâm lấn thật: dump LSASS (T1003), tắt Defender/tool (T1562), AMSI bypass,
  persistence (Run key / scheduled task — T1547, T1053), credential access (T1555).
- Lý do: (a) bị Defender chặn/cách ly gây gián đoạn dev; (b) **sửa đổi thật** registry/dịch vụ
  trên máy chính; (c) làm bẩn số liệu đo.

## Nguyên tắc vàng
**Mọi SỐ LIỆU CHÍNH THỨC cho Chương 4 đều lấy trên CLOUD VM** — môi trường cô lập mạng,
khoá phiên bản Defender, có snapshot "sạch" để khôi phục. Máy dev chỉ để *build cho chắc tay*.

## Khi chạy trên cloud VM
- Cô lập mạng VM (không để lan ra ngoài).
- `machine_label: cloud-vm` trong config; ghi lại phiên bản chữ ký Defender vào bảng `runs`.
- Snapshot "sạch" trước khi đo; soft-reset giữa các lần; snapshot full khi môi trường hỏng.
- Dọn mẫu + quarantine sau mỗi lần đo.
