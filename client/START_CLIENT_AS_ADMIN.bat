@echo off
title NetCafe Pro 2.0 - Client Launcher
echo.
echo ==========================================
echo    🎮 NetCafe Pro 2.0 - Gaming Client
echo ==========================================
echo.
echo Checking administrator privileges...

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo ✅ Administrator privileges detected
    echo.
    echo Starting NetCafe Gaming Client...
    echo 🔐 Keyboard protection will be ACTIVE
    echo 📁 Folder protection will be ACTIVE
    echo.
    cd /d "%~dp0"
    echo 🚀 Starting client in background...
    start "NetCafe Client" /min python netcafe_client.py
    echo ✅ NetCafe Gaming Client started in background
    echo 📱 Check system tray for client status
    echo.
    timeout /t 3 > nul
    echo 👋 Client launcher completed. You can close this window.
    pause
) else (
    echo ❌ Administrator privileges required!
    echo.
    echo 🛡️  NetCafe Pro 2.0 requires administrator privileges to:
    echo    • Block system keyboard shortcuts (Alt+Tab, Alt+F4, Windows key)
    echo    • Protect against unauthorized file access
    echo    • Ensure proper gaming session security
    echo.
    echo Restarting with administrator privileges...
    echo.
    
    REM Request administrator privileges and restart
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
) 