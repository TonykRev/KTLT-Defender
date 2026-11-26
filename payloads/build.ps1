# M2 — Build the 4 C# payload variants with csc.exe (Owner: Opus).
# One command -> payloads/out/v0..v3.exe + prints JSON [{variant, path, sha256, size}].
#
# SAFETY: the binaries contain only the ENCODED EICAR -> compiling & storing them is safe on the dev machine.
# Only RUNNING v0/v2 drops the raw EICAR to disk (Defender RTP will quarantine it — that is the measurement).
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
