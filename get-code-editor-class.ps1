# Enumerate visible top-level windows of the Game_Maker process and write
# "class<TAB>title" lines to gm8windows.txt next to this script.
# Run this WHILE a standalone code editor window is open, then tell me.
Add-Type @"
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public class WinEnum {
    public delegate bool EnumProc(IntPtr hWnd, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr lp);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder sb, int max);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder sb, int max);
    public static List<string> Go(uint targetPid) {
        var list = new List<string>();
        EnumWindows((h, lp) => {
            uint pid; GetWindowThreadProcessId(h, out pid);
            if (pid == targetPid && IsWindowVisible(h)) {
                var t = new StringBuilder(256); GetWindowText(h, t, 256);
                var c = new StringBuilder(256); GetClassName(h, c, 256);
                list.Add(c.ToString() + "\t" + t.ToString());
            }
            return true;
        }, IntPtr.Zero);
        return list;
    }
}
"@

$p = Get-Process -Name Game_Maker -ErrorAction SilentlyContinue
if (-not $p) { Write-Host "Game_Maker.exe is not running"; exit 1 }
$out = Join-Path $PSScriptRoot "gm8windows.txt"
[WinEnum]::Go($p.Id) | Out-File -FilePath $out -Encoding UTF8
Write-Host "Written: $out ($(($([WinEnum]::Go($p.Id))).Count) windows)"
