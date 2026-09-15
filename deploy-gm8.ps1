# GMSave 部署脚本（需 GM8 关闭后，以管理员身份运行）
# 用法：右键"使用 PowerShell 运行"，或在管理员终端:
#   powershell -ExecutionPolicy Bypass -File deploy-gm8.ps1          # Release 版
#   powershell -ExecutionPolicy Bypass -File deploy-gm8.ps1 -Debug   # Debug 版（带 %TEMP%\GMSave.log 日志）
param([switch]$Debug)

$gmDir = "C:\Program Files (x86)\Gamemaker 8.0 超强汉化破解版\FoxPlugin"
$src = "C:\Project\C++\GMSave"
$cfg = if ($Debug) { "Debug" } else { "Release" }

$gmProc = Get-Process -Name Game_Maker -ErrorAction SilentlyContinue
if ($gmProc) {
    Write-Host "Game_Maker.exe 正在运行，请先关闭 GM8 再部署。" -ForegroundColor Red
    exit 1
}

try {
    Copy-Item "$src\$cfg\GMSave.dll" "$gmDir\GMSave.dll" -Force -ErrorAction Stop
} catch {
    Write-Host "复制 GMSave.dll 失败（需要管理员权限？）：$_" -ForegroundColor Red
    exit 1
}
Copy-Item "$src\GMSaveMerge\src-tauri\target\release\gmsave-merge.exe" "$gmDir\gmsave-merge.exe" -Force
if ($Debug) {
    Write-Host "已部署 DEBUG 版 GMSave.dll + GMSaveMerge.exe -> $gmDir" -ForegroundColor Green
    Write-Host "日志输出: %TEMP%\GMSave.log" -ForegroundColor Cyan
} else {
    Write-Host "已部署: GMSave.dll + GMSaveMerge.exe -> $gmDir" -ForegroundColor Green
}
