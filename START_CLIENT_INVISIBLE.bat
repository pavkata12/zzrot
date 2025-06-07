@echo off
title NetCafe Experience Simulator - INVISIBLE MODE

echo 🚀 Starting NetCafe Client in ULTRA INVISIBLE MODE...
echo 👻 The client will be COMPLETELY INVISIBLE!
echo 🫥 No windows, no console, no Alt+Tab visibility!
echo 🔒 Only the lock screen will appear when needed
echo.

echo ⚠️  CRITICAL WARNING: To exit the client, you must:
echo    1. Use Task Manager (Ctrl+Shift+Esc) and find "pythonw.exe"
echo    2. Or right-click system tray icon if visible
echo    3. Or restart your computer
echo.

echo 💀 This mode is VERY HARD to stop once started!
echo 🤔 Are you sure you want to continue? (Press any key or Ctrl+C to cancel)
pause

echo ✅ Starting in ghost mode...
timeout /t 2 /nobreak >nul

:: Use pythonw.exe to run completely invisibly (no console window at all)
start /b pythonw "%~dp0client\netcafe_client.py"

echo 👻 Client is now COMPLETELY INVISIBLE!
echo 🔍 Check Task Manager for "pythonw.exe" process
echo 🔒 Lock screen will appear when server requires login
echo.
echo 📱 Press any key to close this window...
pause >nul 