@echo off
title NetCafe Experience Simulator - Background Mode

echo 🚀 Starting NetCafe Client in BACKGROUND MODE...
echo 🫥 The client will be INVISIBLE and cannot be closed from Alt+Tab
echo 🔒 Only the lock screen will be visible when needed
echo.

echo ⚠️  IMPORTANT: To exit the client, you must:
echo    1. Right-click the system tray icon (bottom-right corner)
echo    2. Select "Exit Client"
echo    3. Or restart your computer
echo.

echo 💡 Starting in 3 seconds...
timeout /t 3 /nobreak >nul

echo ✅ Client starting in stealth mode...

:: Run Python script with no visible window
start /min /b python "%~dp0client\netcafe_client.py"

echo 🎯 Client is now running invisibly in the background!
echo 👁️  Look for the system tray icon to interact with the client
echo 📱 Press any key to close this window...
pause >nul 