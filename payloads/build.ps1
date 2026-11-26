# M2 — Build 4 biến thể payload C# bằng csc.exe (Chủ: Opus).
# 1 lệnh -> payloads/out/v0..v3.exe + in JSON [{variant, path, sha256, size}].
#
# AN TOÀN: binary chỉ chứa EICAR DẠNG MÃ HOÁ -> biên dịch & lưu trữ an toàn trên máy dev.
# Chỉ khi CHẠY v0/v2 mới thả EICAR thô ra đĩa (Defender RTP sẽ cách ly — đó là phép đo).
param(
    [string]$OutDir = "payloads/out",
    [string]$Csc = "C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe"
)
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$src = Join-Path $PSScriptRoot "src"
$common = Join-Path $src "PayloadCommon.cs"

$results = @()
foreach ($v in "v0", "v1", "v2", "v3") {
    $out = Join-Path $OutDir "$v.exe"
    if (Test-Path $out) { Remove-Item $out -Force }
    & $Csc /nologo /optimize+ /platform:anycpu /out:"$out" (Join-Path $src "$v.cs") $common | Out-Null
    if (Test-Path $out) {
        $h = (Get-FileHash -Algorithm SHA256 $out).Hash.ToLower()
        $results += [pscustomobject]@{
            variant = $v; path = $out
            sha256  = $h; size = (Get-Item $out).Length
        }
    } else {
        $results += [pscustomobject]@{ variant = $v; path = $out; sha256 = $null; size = 0 }
    }
}
$results | ConvertTo-Json -Compress
