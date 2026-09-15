# Kill gmsave-merge and its orphaned WebView2 process trees (by UDD path match)
Get-Process -Name gmsave-merge -ErrorAction SilentlyContinue | Stop-Process -Force
Get-CimInstance Win32_Process -Filter "name like '%edgewebview2%'" | Where-Object {
    $_.CommandLine -like '*gmsave-merge*'
} | ForEach-Object {
    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
}
Write-Host "cleaned"
