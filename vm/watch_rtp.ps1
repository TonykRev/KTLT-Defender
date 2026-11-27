<#
  watch_rtp.ps1 - READ-ONLY monitor of Defender real-time protection + Tamper Protection state.

  Purpose: verify whether an Impair-Defenses attempt (T1562.001) actually DISABLES real-time
  protection, or whether Tamper Protection rejects the change outright. This script only READS
  Get-MpComputerStatus; it never changes any Defender setting.

  Usage (on the cloud-vm): run this in one window, then trigger the technique in another window,
  and watch for a RTP transition.

      powershell -ExecutionPolicy Bypass -File vm\watch_rtp.ps1 -Seconds 60

  Interpretation:
    - RTP stays True the whole time  -> the disable attempt was BLOCKED (Tamper Protection) = Defender WIN.
    - RTP transitions True -> False   -> the disable SUCCEEDED (evasion) = a real gap, even if briefly.
#>
param(
    [int]$Seconds = 60,
    [int]$IntervalMs = 250
)

$end  = (Get-Date).AddSeconds($Seconds)
$last = $null
$everFalse = $false

Write-Host "watch_rtp.ps1 (READ-ONLY) - monitoring RealTimeProtectionEnabled for $Seconds s. Ctrl-C to stop."
while ((Get-Date) -lt $end) {
    try {
        $s   = Get-MpComputerStatus
        $rtp = [bool]$s.RealTimeProtectionEnabled
        $tp  = [bool]$s.IsTamperProtected
        $ts  = (Get-Date).ToString("HH:mm:ss.fff")
        if ($rtp -ne $last) {
            if ($null -eq $last) {
                Write-Host "[$ts] start : RTP=$rtp  TamperProtected=$tp"
            } else {
                $color = if ($rtp) { "Green" } else { "Red" }
                Write-Host "[$ts] *** RTP $last -> $rtp  (TamperProtected=$tp) ***" -ForegroundColor $color
            }
            if (-not $rtp) { $everFalse = $true }
            $last = $rtp
        }
    } catch {
        Write-Host "[$((Get-Date).ToString('HH:mm:ss.fff'))] Get-MpComputerStatus error: $($_.Exception.Message)"
    }
    Start-Sleep -Milliseconds $IntervalMs
}

Write-Host ""
if ($everFalse) {
    Write-Host "RESULT: RTP went FALSE at least once -> the disable SUCCEEDED (real evasion gap)." -ForegroundColor Red
} else {
    Write-Host "RESULT: RTP never left True -> the disable attempt was BLOCKED (Tamper Protection) = Defender WIN." -ForegroundColor Green
}
