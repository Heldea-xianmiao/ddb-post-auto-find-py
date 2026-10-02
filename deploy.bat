@echo off
setlocal

rem ============================================================
rem DDB Beyond Sentinel - Windows 一键部署脚本
rem
rem 用法：双击 deploy.bat 或在 cmd 中运行
rem 可选环境变量（运行前 set）：
rem   set DDB_HOST=0.0.0.0     监听地址（默认 127.0.0.1）
rem   set DDB_PORT=8765        监听端口
rem ============================================================

if not defined DDB_HOST set "DDB_HOST=127.0.0.1"
if not defined DDB_PORT set "DDB_PORT=8765"
rem 国内镜像加速；海外网络可改为 set PIP_INDEX=
set "PIP_INDEX=https://pypi.tuna.tsinghua.edu.cn/simple"

cd /d "%~dp0"

echo [部署] 检查 Python 3 ...

set "PY="
py -3 --version >nul 2>&1
if not errorlevel 1 set "PY=py -3"
if not defined PY (
    python --version >nul 2>&1
    if not errorlevel 1 set "PY=python"
)
if not defined PY (
    echo [失败] 未找到 Python 3。
    echo        请到 https://www.python.org/downloads/ 安装，
    echo        安装时务必勾选 "Add Python to PATH"，完成后重新运行本脚本。
    pause
    exit /b 1
)

for /f "tokens=*" %%v in ('%PY% --version 2^>^&1') do echo [部署] %%v

rem --- 检查项目文件 ---
for %%f in (start_gui.py monitor_core.py translator.py web\index.html) do (
    if not exist "%%f" (
        echo [失败] 缺少文件: %%f
        echo        请确保 start_gui.py / monitor_core.py / translator.py / web\ 与本脚本在同一目录。
        pause
        exit /b 1
    )
)

rem --- 虚拟环境 ---
if exist ".venv\Scripts\python.exe" (
    echo [部署] 虚拟环境 .venv 已存在，跳过创建
) else (
    echo [部署] 创建虚拟环境 .venv ...
    %PY% -m venv .venv
    if errorlevel 1 (
        echo [失败] 虚拟环境创建失败，请检查 Python 安装是否完整。
        pause
        exit /b 1
    )
)

rem --- 依赖（镜像失败自动回退官方源）---
echo [部署] 安装依赖 requests ...
set "PIP_OK=0"
if defined PIP_INDEX (
    ".venv\Scripts\python.exe" -m pip install --quiet requests -i %PIP_INDEX% >nul 2>&1 && set "PIP_OK=1"
)
if "%PIP_OK%"=="0" (
    if defined PIP_INDEX echo [部署] 镜像源不可达，改用官方源 ...
    ".venv\Scripts\python.exe" -m pip install --quiet requests && set "PIP_OK=1"
)
if "%PIP_OK%"=="0" (
    echo [失败] requests 安装失败，请检查网络后重试。
    pause
    exit /b 1
)

rem --- 冒烟验证 ---
echo [部署] 验证模块可加载 ...
".venv\Scripts\python.exe" -c "import start_gui" >nul 2>&1
if errorlevel 1 (
    echo [失败] 模块导入失败，请确认项目文件完整。
    pause
    exit /b 1
)

echo.
echo [完成] 部署完成！
echo   [启动] 双击 start.bat（或运行 .venv\Scripts\python.exe start_gui.py）
echo   [访问] http://127.0.0.1:%DDB_PORT% （启动后自动打开浏览器）
echo   [说明] LLM 翻译配置在网页内填写，保存在本目录 settings.json
echo.
echo 如需修改监听地址/端口，先执行例如: set DDB_HOST=0.0.0.0 再启动
pause
