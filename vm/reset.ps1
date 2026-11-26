# M9 — Soft-reset môi trường đo về trạng thái sạch < 60s (Chủ: Opus). STUB.
# Đặc tả: docs/specs/M9-reset.md
# Mục tiêu (giữa các lần đo, KHÔNG revert snapshot mỗi lần — đây là hạn chế đã ghi nhận):
#   - Xoá quarantine cũ (MpCmdRun -Restore / Remove)      [cloud-vm]
#   - Clear log Defender Operational + Sysmon (wevtutil cl) để tách cửa sổ đo
#   - Re-arm realtime protection nếu bị kỹ thuật tắt
#   - Dọn thư mục mẫu payloads/out, process còn sót
#   - Trả về JSON { reset_ok: bool, took_ms: int }
#
# CẢNH BÁO: KHÔNG chạy phần xoá quarantine / sửa Defender trên MÁY DEV cá nhân.
#   Trên dev chỉ clear log của chính phiên đo. Phần đầy đủ chạy trên cloud-vm.

param([string]$MachineLabel = "dev-win11")

Write-Output "STUB reset ($MachineLabel): sẽ clear log + dọn mẫu; phần Defender chỉ trên cloud-vm."
# TODO(Opus): triển khai theo nhãn máy (dev-win11 vs cloud-vm).
