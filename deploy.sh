#!/usr/bin/env bash
# ============================================================
# DDB Beyond Sentinel — Linux 服务器一键部署脚本
#
# 用法（在项目目录内执行）:
#   bash deploy.sh                # 安装环境（venv + requests）
#   bash deploy.sh --service      # 安装环境并注册 systemd 常驻服务
#
# 可选环境变量:
#   DDB_HOST=0.0.0.0              监听地址（默认 127.0.0.1，仅本机访问）
#   DDB_PORT=8765                 监听端口
#   PIP_INDEX=https://...         pip 镜像源（国内服务器加速用）
#
# 示例:
#   DDB_HOST=0.0.0.0 PIP_INDEX=https://pypi.tuna.tsinghua.edu.cn/simple bash deploy.sh --service
# ============================================================

set -euo pipefail

HOST="${DDB_HOST:-127.0.0.1}"
PORT="${DDB_PORT:-8765}"
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$APP_DIR/.venv"
SERVICE_NAME="ddb-sentinel"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

log()  { printf '\033[33m[部署]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[完成]\033[0m %s\n' "$*"; }
fail() { printf '\033[31m[失败]\033[0m %s\n' "$*" >&2; exit 1; }

# --- 1. 检查 Python ---
log "检查 Python 3 ..."
command -v python3 >/dev/null 2>&1 \
  || fail "未找到 python3（Debian/Ubuntu: apt install -y python3 python3-venv；CentOS: yum install -y python3）"

PY_VER="$(python3 -c 'import sys; print("{}.{}".format(*sys.version_info[:2]))')"
log "Python 版本: $PY_VER"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' \
  || fail "需要 Python 3.8+，当前 $PY_VER"

# --- 2. 检查项目文件 ---
for f in start_gui.py monitor_core.py translator.py web/index.html; do
  [[ -f "$APP_DIR/$f" ]] || fail "缺少文件: $f（请把项目四个文件 start_gui.py / monitor_core.py / translator.py / web/ 放在同一目录后再运行）"
done

# --- 3. 虚拟环境 + 依赖 ---
PIP_EXTRA=""
[[ -n "$PIP_INDEX" ]] && PIP_EXTRA="--index-url $PIP_INDEX"

if [[ ! -d "$VENV" ]]; then
  log "创建虚拟环境 .venv ..."
  if ! python3 -m venv "$VENV" 2>/dev/null; then
    log "venv 模块不可用，尝试自动安装 python3-venv ..."
    if command -v apt >/dev/null 2>&1; then
      sudo apt update -qq && sudo apt install -y python3-venv
    elif command -v yum >/dev/null 2>&1; then
      sudo yum install -y python3
    else
      fail "无法自动安装 python3-venv，请手动安装后重试"
    fi
    python3 -m venv "$VENV" || fail "创建虚拟环境失败"
  fi
fi

log "安装依赖 requests ..."
"$VENV/bin/pip" install --quiet --upgrade pip $PIP_EXTRA || true
"$VENV/bin/pip" install --quiet requests $PIP_EXTRA \
  || fail "requests 安装失败；国内服务器可加镜像重试: PIP_INDEX=https://pypi.tuna.tsinghua.edu.cn/simple bash deploy.sh"
ok "依赖安装完成"

# --- 4. 冒烟验证 ---
log "验证模块可加载 ..."
(cd "$APP_DIR" && "$VENV/bin/python" -c "import start_gui") \
  || fail "模块导入失败，请检查文件是否完整（git clone 或 scp 传输）"
ok "验证通过"

# --- 5. 注册 systemd 常驻服务（可选） ---
if [[ "${1:-}" == "--service" ]]; then
  command -v systemctl >/dev/null 2>&1 \
    || fail "当前系统无 systemd，请直接运行: $VENV/bin/python start_gui.py"

  log "注册 systemd 服务 $SERVICE_NAME ..."
  SUDO=""
  [[ $EUID -ne 0 ]] && SUDO="sudo"

  $SUDO tee "$SERVICE_FILE" >/dev/null <<EOF
[Unit]
Description=DDB Beyond Sentinel (ddb-post-auto-find-py)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
ExecStart=$VENV/bin/python start_gui.py
Environment=DDB_HOST=$HOST
Environment=DDB_PORT=$PORT
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

  $SUDO systemctl daemon-reload
  $SUDO systemctl enable --now "$SERVICE_NAME"
  sleep 1
  systemctl is-active --quiet "$SERVICE_NAME" \
    || fail "服务启动异常，查看日志: journalctl -u $SERVICE_NAME -e"
  ok "服务已启动并设为开机自启"
fi

# --- 6. 完成 ---
echo ""
ok "部署完成"
echo "  ┌─ 启动/管理:"
if [[ "${1:-}" == "--service" ]]; then
  echo "  │   状态:   systemctl status $SERVICE_NAME"
  echo "  │   日志:   journalctl -u $SERVICE_NAME -f"
  echo "  │   重启:   sudo systemctl restart $SERVICE_NAME"
else
  echo "  │   运行:   $VENV/bin/python start_gui.py"
  echo "  │   后台:   nohup $VENV/bin/python start_gui.py >/dev/null 2>&1 &"
fi
echo "  ├─ 访问:"
if [[ "$HOST" == "0.0.0.0" ]]; then
  echo "  │   http://<服务器IP>:$PORT  （已监听公网，请确认安全组仅放行可信来源）"
else
  echo "  │   本机: http://127.0.0.1:$PORT"
  echo "  │   远程: ssh -L $PORT:127.0.0.1:$PORT user@服务器  后访问 http://localhost:$PORT"
fi
echo "  └─ LLM 翻译配置在页面内填写，保存于 $APP_DIR/settings.json"
