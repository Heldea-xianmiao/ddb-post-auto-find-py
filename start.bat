@echo off
chcp 65001 >nul
setlocal

rem DDB Beyond Sentinel — Windows 启动脚本（需先运行 deploy.bat）

cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo [提示] 尚未安装环境，正在自动执行 deploy.bat ...
    call deploy.bat
    if errorlevel 1 exit /b 1
)

echo [启动] DDB Beyond Sentinel ...
".venv\Scripts\python.exe" start_gui.py

echo.
echo [停止] 程序已退出。
pause
