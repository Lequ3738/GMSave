# Deploy GMSave.dll (Debug or Release build) to the installed GameMaker 8.0's
# FoxPlugin folder. Run AFTER closing Game Maker (the DLL is locked while the
# IDE runs). ASCII-only on purpose: PowerShell 5.1 reads BOM-less UTF-8 as ANSI.
# Result is written to %TEMP%\gmsave_deploy_result.txt so an elevated (UAC)
# invocation can be verified from a non-elevated shell afterwards.
param([string]$Config = 'Debug')

$ErrorActionPreference = 'Stop'
$result = Join-Path $env:TEMP 'gmsave_deploy_result.txt'

# Fresh logs: the plugin appends across sessions, which mixes unrelated runs.
foreach ($name in @('GMSave.log', 'GMSave.perf.log')) {
    $p = Join-Path $env:TEMP $name
    if (Test-Path $p) { Remove-Item $p -Force }
}

# The DLL is locked while the IDE runs; deploying then would fail or corrupt.
$gm = @(Get-Process -Name 'Game_Maker' -ErrorAction SilentlyContinue)
if ($gm.Count -gt 0) {
    $ids = ($gm | ForEach-Object { $_.Id }) -join ','
    "BLOCKED: Game_Maker.exe still running (pid $ids)" | Out-File $result -Encoding ascii
    exit 2
}

$src = "C:\Project\C++\GMSave\$Config\GMSave.dll"
if (-not (Test-Path $src)) {
    "FAILED: build not found: $src" | Out-File $result -Encoding ascii
    exit 3
}

$gmDir = Get-ChildItem 'C:\Program Files (x86)' -Directory |
    Where-Object { $_.Name -like '*amemaker 8.0*' } |
    Select-Object -First 1
if (-not $gmDir) {
    "FAILED: GameMaker 8.0 install not found under C:\Program Files (x86)" | Out-File $result -Encoding ascii
    exit 3
}
$dst = Join-Path $gmDir.FullName 'FoxPlugin\GMSave.dll'

try {
    Copy-Item $src $dst -Force
    $s1 = (Get-FileHash $src -Algorithm MD5).Hash
    $s2 = (Get-FileHash $dst -Algorithm MD5).Hash
    "OK src_md5=$s1 dst_md5=$s2 bytes=$((Get-Item $src).Length) dst=$dst" |
        Out-File $result -Encoding ascii
    exit 0
} catch {
    "FAILED: $($_.Exception.Message)" | Out-File $result -Encoding ascii
    exit 4
}
