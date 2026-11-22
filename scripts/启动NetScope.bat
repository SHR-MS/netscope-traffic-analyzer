@echo off
chcp 936 >nul
title NetScope 网络流量分析系统
cd /d "%~dp0.."
net session >nul 2>&1
if errorlevel 1 goto elevate
if exist ".venv\Scripts\python.exe" goto run
echo 没有找到虚拟环境，请先执行：
echo   python -m venv .venv
echo   .venv\Scripts\python.exe -m pip install -r requirements.txt
pause
exit /b
:run
".venv\Scripts\python.exe" src\main.py
pause
exit /b
:elevate
echo 正在申请管理员权限（真实抓包需要）...
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
exit /b
