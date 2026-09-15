# GMSave 部署脚本（需 GM8 关闭后，以管理员身份运行）
# 用法：右键"使用 PowerShell 运行"，或在管理员终端: powershell -ExecutionPolicy Bypass -File deploy-gm8.ps1
$gmDir = "C:\Program Files (x86)\Gamemaker 8.0 超强汉化破解版\FoxPlugin"
$src = "C:\Project\C++\GMSave"

$gmProc = Get-Process -Name Game_Maker -ErrorAction SilentlyContinue
if ($gmProc) {
    Write-Host "Game_Maker.exe 正在运行，请先关闭 GM8 再部署。" -ForegroundColor Red
    exit 1
}

Copy-Item "$src\Release\GMSave.dll" "$gmDir\GMSave.dll" -Force
Copy-Item "$src\GMSaveMerge\src-tauri\target\release\gmsave-merge.exe" "$gmDir\GMSaveMerge.exe" -Force
Write-Host "已部署: GMSave.dll + GMSaveMerge.exe -> $gmDir" -ForegroundColor Green
