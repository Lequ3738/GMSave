# 诊断：PostMessage DOWN 后高速读键盘表，分辨"帧内被清表"还是"消息没入"
# 必须用 pwsh 7 运行：Windows PowerShell 5.1 会把无 BOM 的 UTF-8 按 GBK 解析。
# 用法：pwsh -File downTbl_race_read.ps1 [-Vk 90] [-Seconds 1.2]
param([int]$Vk = 90, [double]$Seconds = 1.2, [long]$Hwnd = 0)
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Race {
    [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint msg, IntPtr wp, IntPtr lp);
    [DllImport("kernel32.dll")] public static extern bool ReadProcessMemory(IntPtr p, IntPtr addr, byte[] buf, int size, out int read);
}
"@
$p = Get-Process -Name "Nature Edition" -ErrorAction Stop | Select-Object -First 1
# 必须显式传 TRunnerForm（桥发现文件里的 hwnd）；$p.MainWindowHandle 会拿到 VCL TApplication 壳窗（消息死路）
if ($Hwnd -eq 0) { throw "必须传 -Hwnd（TRunnerForm 句柄，见 Debug\MCP\bridge_*.json）" }
$hwnd = $Hwnd
$addr = [IntPtr](0x6C8674 + $Vk)   # GM8R_KB_DownTbl + vk（R10 实证地址，引擎静态无 ASLR）

$buf = New-Object byte[] 1; $read = 0
[Race]::ReadProcessMemory($p.Handle, $addr, $buf, 1, [ref]$read) | Out-Null
$pre = $buf[0]
[Race]::PostMessage($hwnd, 0x100, [IntPtr]$Vk, [IntPtr]0) | Out-Null
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$vals = @()
while ($sw.Elapsed.TotalSeconds -lt $Seconds) {
    [Race]::ReadProcessMemory($p.Handle, $addr, $buf, 1, [ref]$read) | Out-Null
    $vals += $buf[0]
    Start-Sleep -Milliseconds 30
}
[Race]::PostMessage($hwnd, 0x101, [IntPtr]$Vk, [IntPtr]0xC0000001) | Out-Null
Start-Sleep -Milliseconds 200
[Race]::ReadProcessMemory($p.Handle, $addr, $buf, 1, [ref]$read) | Out-Null
$ones = ($vals | Where-Object { $_ -ne 0 }).Count
Write-Output ("pre={0} reads={1} nonzero={2} post_up={3} 序列前20: {4}" -f $pre, $vals.Count, $ones, $buf[0], (($vals | Select-Object -First 20) -join ','))
