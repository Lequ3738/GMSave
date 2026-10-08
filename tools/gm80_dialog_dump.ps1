# Dump top-level windows (and child text) of every Game_Maker process.
# ASCII-only on purpose: PowerShell 5.1 reads BOM-less UTF-8 as ANSI.
param([string]$Out = "$env:TEMP\gm80_dialogs.txt", [switch]$Dismiss)
$ErrorActionPreference = 'Stop'

Add-Type @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public class WinEnum {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc cb, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint msg, IntPtr wp, IntPtr lp);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
}
'@

$fg = [WinEnum]::GetForegroundWindow()
$fgCls = New-Object System.Text.StringBuilder 256
[void][WinEnum]::GetClassNameW($fg, $fgCls, 256)
$fgT = New-Object System.Text.StringBuilder 512
[void][WinEnum]::GetWindowTextW($fg, $fgT, 512)
$fgPid = [uint32]0
[void][WinEnum]::GetWindowThreadProcessId($fg, [ref]$fgPid)
$foreground = "FOREGROUND pid=$fgPid class='$($fgCls.ToString())' title='$($fgT.ToString())'"

$procs = @(Get-Process -Name 'Game_Maker' -ErrorAction SilentlyContinue)
$lines = New-Object System.Collections.ArrayList
[void]$lines.Add($foreground)
if ($procs.Count -eq 0) { [void]$lines.Add('NO Game_Maker process') }
$pids = @($procs | ForEach-Object { [uint32]$_.Id })

$childCb = [WinEnum+EnumProc]{
  param($c, $l)
  $cls = New-Object System.Text.StringBuilder 256
  [void][WinEnum]::GetClassNameW($c, $cls, 256)
  $t = New-Object System.Text.StringBuilder 2048
  [void][WinEnum]::GetWindowTextW($c, $t, 2048)
  if ($t.Length -gt 0) { [void]$script:lines.Add("    child class='$($cls.ToString())' text='$($t.ToString())'") }
  return $true
}
$topCb = [WinEnum+EnumProc]{
  param($h, $l)
  $wpid = [uint32]0
  [void][WinEnum]::GetWindowThreadProcessId($h, [ref]$wpid)
  if ($script:pids -contains $wpid) {
    $cls = New-Object System.Text.StringBuilder 256
    [void][WinEnum]::GetClassNameW($h, $cls, 256)
    $t = New-Object System.Text.StringBuilder 1024
    [void][WinEnum]::GetWindowTextW($h, $t, 1024)
    $vis = [WinEnum]::IsWindowVisible($h)
    [void]$script:lines.Add("TOP pid=$wpid hwnd=0x$("{0:X}" -f [int64]$h) class='$($cls.ToString())' visible=$vis title='$($t.ToString())'")
    [void][WinEnum]::EnumChildWindows($h, $script:childCb, [IntPtr]::Zero)
    if ($script:Dismiss -and $cls.ToString() -eq '#32770' -and $vis) {
      [void][WinEnum]::PostMessageW($h, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)  # WM_CLOSE
      [void]$script:lines.Add('    -> posted WM_CLOSE to this dialog')
    }
  }
  return $true
}

[void][WinEnum]::EnumWindows($topCb, [IntPtr]::Zero)
$text = ($lines -join "`r`n") + "`r`n"
[System.IO.File]::WriteAllText($Out, $text, [System.Text.Encoding]::UTF8)
Write-Output "written: $Out"
