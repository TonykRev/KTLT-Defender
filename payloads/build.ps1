# M2 — Build 4 biến thể payload C# bằng csc.exe (Chủ: Haiku worker). STUB.
# Đặc tả: docs/specs/M1-M2-payloads.md
# Mục tiêu: 1 lệnh -> ra payloads/out/v0.exe .. v3.exe + in SHA-256 từng file.
#
# CẢNH BÁO: v0/v1 CỐ TÌNH để Defender bắt -> realtime protection trên máy dev có thể
# cách ly file ngay khi build. Build trong thư mục out/, chấp nhận điều đó (đó là phép đo),
# hoặc build trên cloud-vm. Payload VÔ HẠI (chỉ mang chuỗi/hành vi mô phỏng).

param(
    [string]$OutDir = "payloads/out",
    [string]$Csc = "C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe"
)

Write-Output "STUB: sẽ compile v0..v3 từ payloads/src/*.cs -> $OutDir, rồi in SHA-256."
# TODO(worker): New-Item -ItemType Directory -Force $OutDir
# TODO(worker): foreach variant: & $Csc /nologo /out:... payloads/src/<variant>.cs
# TODO(worker): Get-FileHash -Algorithm SHA256 từng .exe -> xuất JSON cho db_writer
