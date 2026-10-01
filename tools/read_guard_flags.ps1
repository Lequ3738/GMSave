# 读/写 GM8 游戏进程的引擎输入标志（诊断注入链路用）
# 必须用 pwsh 7 运行：pwsh 5 对该进程属性返回空壳、param 绑定失灵。
# 用法：读 -Action read；写 0 -Action zero（写 58F0BC/58F098 两字节）
param([string]$Action = "read")
$p = Get-Process -Name "Nature Edition" -ErrorAction Stop
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class PM {
    [DllImport("kernel32.dll")] public static extern bool ReadProcessMemory(IntPtr p, IntPtr addr, byte[] buf, int size, out int read);
    [DllImport("kernel32.dll")] public static extern bool WriteProcessMemory(IntPtr p, IntPtr addr, byte[] buf, int size, out int written);
}
"@
$addrs = @(0x58F0BC, 0x58F098, 0x58D2FC, 0x58D6B0, 0x58F0E4)
if ($Action -eq "zero") {
    $one = New-Object byte[] 1; $one[0] = 0; $written = 0
    foreach ($a in @(0x58F0BC, 0x58F098)) {
        [PM]::WriteProcessMemory($p.Handle, [IntPtr]$a, $one, 1, [ref]$written) | Out-Null
        Write-Output ("write0 0x{0:X} ok={1}" -f $a, $written)
    }
}
foreach ($a in $addrs) {
    $buf = New-Object byte[] 1; $read = 0
    [PM]::ReadProcessMemory($p.Handle, [IntPtr]$a, $buf, 1, [ref]$read) | Out-Null
    Write-Output ("0x{0:X} = {1}" -f $a, $buf[0])
}
