@echo off
chcp 936 >nul
cd /d "%~dp0.."
echo ==== 1/3 单元测试 ====
".venv\Scripts\python.exe" -m unittest discover -s tests -t . -v
echo.
echo ==== 2/3 界面冒烟测试 ====
".venv\Scripts\python.exe" src\smoke_test.py
echo.
echo ==== 3/3 端到端验证 ====
".venv\Scripts\python.exe" verify_e2e.py
echo.
echo 判定标准：出现 OK 和 E2E: PASS 即通过
pause
