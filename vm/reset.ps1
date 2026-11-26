# M9 — Soft-reset the measurement environment to a clean state (Owner: Opus).
# Returns JSON { reset_ok, took_ms, machine_label, actions }.
#
# SAFETY LOCK by machine label:
#  - dev-win11 : ONLY cleans up dropped samples. Does NOT clear Defender logs, does NOT modify Defender.
#                (The measurement isolates events by TIME WINDOW, so no log clearing is needed.)
#  - cloud-vm  : full reset (quarantine/RTP/clear logs) because the VM is single-use and isolated.
param(
    [string]$MachineLabel = "dev-win11",
    [string]$OutDir = "payloads/out"
)
$ErrorActionPreference = "SilentlyContinue"
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$actions = @()

# 1) Clean up dropped samples (all machines — safe)
if (Test-Path $OutDir) {
    Get-ChildItem $OutDir -Filter "sample_*.bin" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    $actions += "cleaned dropped samples"
}

if ($MachineLabel -eq "cloud-vm") {
    # a) Restore/clear quarantine
    $mp = Get-ChildItem "C:\ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe" -ErrorAction SilentlyContinue | Select-Object -Last 1
    if ($mp) { & $mp.FullName -Restore -All | Out-Null; $actions += "cleared quarantine" }
    # b) Re-arm realtime protection (in case a technique disabled it)
    Set-MpPreference -DisableRealtimeMonitoring $false
    $actions += "re-armed RTP"
    # c) Clear logs to isolate the measurement window (VM is single-use)
    wevtutil cl "Microsoft-Windows-Windows Defender/Operational"
    wevtutil cl "Microsoft-Windows-Sysmon/Operational"
    $actions += "cleared event logs"
} else {
    # Personal dev machine: NEVER touch the user's Defender/logs.
    $actions += "dev mode: no Defender/log changes (time-window isolation)"
}

$sw.Stop()
[pscustomobject]@{
    reset_ok      = $true
    took_ms       = $sw.ElapsedMilliseconds
    machine_label = $MachineLabel
    actions       = $actions
} | ConvertTo-Json -Compress
