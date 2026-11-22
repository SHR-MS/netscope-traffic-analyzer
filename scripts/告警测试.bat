@echo off
chcp 936 >nul
title NetScope 告警测试
cd /d "%~dp0.."
net session >nul 2>&1
if errorlevel 1 goto elevate
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0告警测试.ps1"
goto end
:elevate
echo 正在申请管理员权限（点“是”后在新窗口继续）...
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
exit /b
:end
echo.
pause
