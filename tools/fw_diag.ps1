# Add/remove per-process firewall block rules for the GM8 IDE (diagnosis only).
# Must run elevated (UAC). Result is written to %TEMP%\gmsave_fw_result.txt so a
# non-elevated shell can verify. ASCII-only on purpose (PS 5.1 + BOM-less UTF-8).
param([string]$Action = 'add')

$ErrorActionPreference = 'Stop'
$out = Join-Path $env:TEMP 'gmsave_fw_result.txt'

try {
    $gmDir = Get-ChildItem 'C:\Program Files (x86)' -Directory |
        Where-Object { $_.Name -like '*amemaker 8.0*' } |
        Select-Object -First 1
    if (-not $gmDir) { throw 'GM8 install dir not found' }
    $exe = Join-Path $gmDir.FullName 'Game_Maker.exe'
    if (-not (Test-Path $exe)) { throw "exe not found: $exe" }

    if ($Action -eq 'add') {
        New-NetFirewallRule -DisplayName 'GMSave-Diag-Block-GM8-out' `
            -Program $exe -Direction Outbound -Action Block -Profile Any | Out-Null
        New-NetFirewallRule -DisplayName 'GMSave-Diag-Block-GM8-in' `
            -Program $exe -Direction Inbound -Action Block -Profile Any | Out-Null
        "OK added for $exe" | Out-File $out -Encoding ascii
    }
    else {
        Remove-NetFirewallRule -DisplayName 'GMSave-Diag-Block-GM8-out' -ErrorAction SilentlyContinue
        Remove-NetFirewallRule -DisplayName 'GMSave-Diag-Block-GM8-in' -ErrorAction SilentlyContinue
        "OK removed" | Out-File $out -Encoding ascii
    }
    exit 0
}
catch {
    "FAILED: $($_.Exception.Message)" | Out-File $out -Encoding ascii
    exit 4
}
