@echo off
REM ---------------------------------------------------------------
REM  Stop the 4kwallpapers server started by start-server.cmd.
REM
REM  Why this exists: if the server was ever launched from another
REM  shell, it can outlive that shell and keep holding the port.
REM  Then start-server.cmd fails with "address already in use" and
REM  there is no obvious way to stop the old one. Run this first.
REM ---------------------------------------------------------------
setlocal

echo Looking for running server.py processes...
echo.

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$found = $false; Get-CimInstance Win32_Process | Where-Object { $_.Name -like 'python*' -and $_.CommandLine -like '*server.py*' } | ForEach-Object { $found = $true; Write-Host ('  stopping PID ' + $_.ProcessId); Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }; if (-not $found) { Write-Host '  nothing running.' }"

echo.
echo Done. You can start it again with start-server.cmd
pause
