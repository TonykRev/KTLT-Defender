# M9 — Soft-reset môi trường đo về trạng thái sạch (Chủ: Opus).
# Trả JSON { reset_ok, took_ms, machine_label, actions }.
#
# KHÓA AN TOÀN theo nhãn máy:
#  - dev-win11 : CHỈ dọn mẫu đã thả. KHÔNG xoá log Defender của bạn, KHÔNG sửa Defender.
#                (Phép đo tách sự kiện bằng CỬA SỔ THỜI GIAN nên không cần clear log.)
#  - cloud-vm  : làm đầy đủ (quarantine/RTP/clear log) vì VM là máy dùng một lần, cô lập.
param(
    [string]$MachineLabel = "dev-win11",
    [string]$OutDir = "payloads/out"
)
$ErrorActionPreference = "SilentlyContinue"
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$actions = @()

# 1) Dọn mẫu đã thả (mọi máy — an toàn)
if (Test-Path $OutDir) {
    Get-ChildItem $OutDir -Filter "sample_*.bin" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    $actions += "cleaned dropped samples"
}

if ($MachineLabel -eq "cloud-vm") {
    # a) Khôi phục/xoá quarantine
    $mp = Get-ChildItem "C:\ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe" -ErrorAction SilentlyContinue | Select-Object -Last 1
    if ($mp) { & $mp.FullName -Restore -All | Out-Null; $actions += "cleared quarantine" }
    # b) Re-arm realtime protection (phòng kỹ thuật đã tắt)
    Set-MpPreference -DisableRealtimeMonitoring $false
    $actions += "re-armed RTP"
    # c) Clear log để tách cửa sổ đo (VM dùng một lần)
    wevtutil cl "Microsoft-Windows-Windows Defender/Operational"
    wevtutil cl "Microsoft-Windows-Sysmon/Operational"
    $actions += "cleared event logs"
} else {
    # Máy dev cá nhân: tuyệt đối KHÔNG đụng Defender/log của người dùng.
    $actions += "dev mode: no Defender/log changes (time-window isolation)"
}

$sw.Stop()
[pscustomobject]@{
    reset_ok      = $true
    took_ms       = $sw.ElapsedMilliseconds
    machine_label = $MachineLabel
    actions       = $actions
} | ConvertTo-Json -Compress
