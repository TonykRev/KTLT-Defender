# Work-packet M1+M2 — 4 biến thể payload C# + build.ps1

**Worker:** v0,v1 → Haiku · v2,v3 → Sonnet (in-memory khó hơn). **Review:** Opus.
**File:** `payloads/src/v0.cs..v3.cs`, `payloads/build.ps1`.

## Mục tiêu khoa học
Mỗi biến thể khác biến thể trước ĐÚNG 1 yếu tố để tách được tác động lên quét tĩnh/AMSI:
| Biến thể | Khác gì | Đo điều gì |
|---|---|---|
| v0 | Mẫu trần: chuỗi "đặc trưng mã độc" mô phỏng lộ rõ | Baseline — Defender bắt bằng chữ ký? |
| v1 | v0 + mã hoá chuỗi (XOR + Base64), giải mã lúc chạy | Mã hoá chuỗi có qua quét tĩnh? |
| v2 | v1 + ghi payload ra ĐĨA rồi chạy | Ghi đĩa có kích hoạt quét tĩnh/RTP? |
| v3 | v1 + thực thi trong BỘ NHỚ (không chạm đĩa) | In-memory né quét tĩnh? AMSI bắt? |

## RÀNG BUỘC AN TOÀN (bắt buộc)
- Payload **VÔ HẠI**: KHÔNG tải/chạy mã độc thật, KHÔNG network ra ngoài, KHÔNG sửa hệ thống.
- "Hành vi mô phỏng" = chỉ ghi 1 dòng ra stdout/ghi 1 file text đánh dấu, ví dụ dùng chuỗi
  đặc trưng EICAR-style HOẶC một marker tự định nghĩa (ghi rõ trong comment). Mục tiêu là
  tạo tín hiệu cho tầng quét, không gây hại.
- v3 "thực thi bộ nhớ": nạp 1 assembly .NET vô hại từ byte[] rồi gọi method in marker — KHÔNG
  shellcode, KHÔNG VirtualAlloc/CreateThread tới mã lạ.

## Interface / Acceptance
- Biên dịch được bằng `csc.exe v4.0.30319` (đã kiểm chứng trên máy dev).
- `build.ps1 -OutDir payloads/out` → ra `v0.exe..v3.exe`, in JSON: `[{variant, sha256, size}]`.
- Mỗi exe chạy được (hoặc bị Defender cách ly — đó là kết quả đo hợp lệ cho v0/v1).
- Code có comment giải thích "khác biến thể trước ở điểm nào".

## Lưu ý
Đưa logic mã hoá chuỗi (v1) ra 1 helper dùng chung để v1/v2/v3 tái sử dụng (chỉ khác cách thực thi).
