# One-time elevation: grant Users modify rights on the GMSave deploy
# directory tree, so dev-time plugin/tool deployment needs no admin.
# NOTE: kept pure ASCII on purpose - PowerShell 5.1 reads BOM-less UTF-8
# scripts as ANSI/GBK and a Chinese path here would turn into mojibake.
$dir = Get-ChildItem 'C:\Program Files (x86)' -Directory -Filter 'Gamemaker*' |
    Select-Object -First 1
if (-not $dir) { Write-Host 'target directory not found'; exit 1 }
Write-Host "Granting modify rights on: $($dir.FullName)"
icacls $dir.FullName /grant '*S-1-5-32-545:(OI)(CI)M' /T
Write-Host 'Done.'
