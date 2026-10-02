"""
DDB Beyond Sentinel v2.5 — 本地 Web 界面版

启动后自动打开浏览器访问 http://127.0.0.1:8765
后端仅使用 Python 标准库 + requests，无需额外依赖。
标题翻译需配置 OpenAI 兼容 LLM API（在页面设置区填写）。
"""

import json
import logging
import os
import sys
import threading
import time
import webbrowser
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests

import monitor_core as core
import translator as tr

# 监听地址与端口（可用环境变量覆盖，如 DDB_HOST=0.0.0.0）
WEB_HOST = os.environ.get("DDB_HOST", "127.0.0.1")
WEB_PORT = int(os.environ.get("DDB_PORT", "8765"))

# 配置日志（同时输出到控制台与 Web 日志面板）
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)


def resource_path(rel):
    """兼容 PyInstaller 打包后的资源路径"""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, rel)


def data_dir():
    """可写数据目录：打包版为 exe 所在目录（settings/翻译缓存需持久化）"""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


class AppState:
    """监控状态容器（线程共享，读写均需持锁）"""

    def __init__(self):
        self.lock = threading.Lock()
        self.monitoring = False
        self.stop_event = threading.Event()
        self.monitor_thread = None
        self.table = []            # [{id, title, tag, reason_zh, changed, final_url}]
        self.logs = deque(maxlen=300)
        self.config = {
            "start_id": 2230, "end_id": 2260, "extra_ids": "",
            "day_iv": 3600, "night_iv": 900,
        }
        self.next_scan_ts = None
        self.alert_history = {}
        # 标题翻译（slug → 中文）
        self.translator = tr.TranslationService(data_dir())
        self.translating = False

    def snapshot(self):
        with self.lock:
            return {
                "monitoring": self.monitoring,
                "table": self.table,
                "logs": list(self.logs),
                "config": self.config,
                "next_scan_ts": self.next_scan_ts,
                "now": time.time(),
                "translations": self.translator.cache,
                "llm": self.translator.public_info(),
                "translating": self.translating,
            }

    def log(self, level, msg):
        with self.lock:
            self.logs.append({"time": time.strftime("%H:%M:%S"), "level": level, "msg": msg})


class WebLogHandler(logging.Handler):
    """把 logging 输出镜像到 Web 日志面板"""

    def __init__(self, app_state):
        super().__init__()
        self.app_state = app_state
        self.setFormatter(logging.Formatter("%(message)s"))

    def emit(self, record):
        try:
            self.app_state.log(record.levelname, self.format(record))
        except Exception:
            pass


def status_tag(info):
    """返回行状态标签"""
    if info["reason"].startswith("error:"):
        return "error"
    if info["viewable"]:
        return "viewable"
    if info["present"]:
        return "partial"
    return "absent"


def build_rows(current, prev_table):
    """由扫描结果构建表格行（跳过异常行，标记变化行）"""
    rows = []
    for n, info in sorted(current.items()):
        if info["reason"].startswith("error:"):
            continue
        prev = prev_table.get(n)
        changed = prev is not None and prev["tag"] != status_tag(info)
        rows.append({
            "id": n,
            "title": info["title"],
            "tag": status_tag(info),
            "reason_zh": core.reason_zh(info["reason"]),
            "changed": changed,
            "final_url": info["final_url"],
        })
    return rows


def trigger_translation(app_state, rows=None, manual=False):
    """后台翻译表格中未翻译的标题（防重入）；返回是否已启动

    - 已缓存标题不会重复翻译、不会重复消耗 token
    - 自动触发受失败退避限制（连续失败后暂停），手动触发不受限
    """
    with app_state.lock:
        if app_state.translating or not app_state.translator.configured:
            return False
        if not manual and not app_state.translator.auto_allowed():
            return False
        app_state.translating = True

    def worker():
        try:
            table = rows if rows is not None else app_state.snapshot()["table"]
            slugs = [r["title"] for r in table
                     if r["tag"] in ("viewable", "partial")
                     and r["title"] and r["title"] != "未知标题"
                     and not app_state.translator.cached(r["title"])]
            if not slugs:
                logging.debug("所有标题均已翻译，无需调用 LLM")
                return
            logging.info(f"正在翻译 {len(slugs)} 个标题…")
            app_state.translator.translate_batch(slugs)
        finally:
            with app_state.lock:
                app_state.translating = False

    threading.Thread(target=worker, daemon=True).start()
    return True


def monitor_loop(app_state, target_ids, day_iv, night_iv):
    """监控线程：循环扫描并更新共享状态"""
    session = requests.Session()
    session.headers.update({"User-Agent": core.USER_AGENT})
    prev_table = {}

    while app_state.monitoring:
        try:
            current = core.run_scan(session, target_ids)
            rows = build_rows(current, prev_table)
            prev_table = {r["id"]: r for r in rows}

            with app_state.lock:
                app_state.table = rows

            # 自动翻译新增的未翻译标题（后台线程，不阻塞扫描）
            trigger_translation(app_state, rows)

            notifications = []
            for n, info in current.items():
                if info["reason"].startswith("error:"):
                    continue
                old_state = app_state.alert_history.get(n)
                cur_state = (info["present"], info["viewable"])
                if old_state == cur_state:
                    continue
                if cur_state[0] and (not old_state or not old_state[0]):
                    notifications.append(f"【发现新篇】ID {n}: {info['title']}")
                    app_state.alert_history[n] = cur_state
                elif cur_state[1] and (not old_state or not old_state[1]):
                    notifications.append(f"【全文解锁】ID {n}: {info['title']}")
                    app_state.alert_history[n] = cur_state

            if notifications:
                core.flash_taskbar()
                core.show_notification("DDB Sentinel 警报", f"捕获到 {len(notifications)} 条关键更新")
                for msg in notifications:
                    logging.info(f"关键更新: {msg}")

            # 休眠（可中断），并告知前端下次扫描时间
            hour = time.localtime().tm_hour
            wait = day_iv if 8 <= hour < 20 else night_iv
            with app_state.lock:
                app_state.next_scan_ts = time.time() + wait
            logging.info(f"周期完成 ({'日间' if 8 <= hour < 20 else '夜间'})，休眠 {wait}s...")

            for _ in range(wait):
                if app_state.stop_event.is_set():
                    break
                time.sleep(1)

        except Exception as e:
            logging.error(f"侦察期间发生执行冲突: {e}")
            time.sleep(10)

    logging.info("Sentinel 已停机。")


def start_monitoring(app_state, params):
    """校验参数并启动监控线程，返回 (ok, error/count)"""
    try:
        start_id = int(params.get("start_id", ""))
        end_id = int(params.get("end_id", ""))
        day_iv = int(params.get("day_iv", ""))
        night_iv = int(params.get("night_iv", ""))
    except (TypeError, ValueError):
        return False, "ID 范围与间隔时间必须为有效整数"

    extra_raw = str(params.get("extra_ids", "")).strip()
    extra_ids = []
    if extra_raw:
        extra_ids = core.parse_ids(extra_raw)
        if not extra_ids:
            return False, f"额外 ID 无法解析：{extra_raw}（示例: 2100,2155-2158）"

    range_ids = list(range(start_id, end_id + 1)) if start_id <= end_id else []
    target_ids = sorted(set(range_ids) | set(extra_ids))
    if not target_ids:
        return False, "没有可监控的 ID：请检查起始/终止 ID 范围"

    with app_state.lock:
        app_state.monitoring = True
        app_state.stop_event.clear()
        app_state.config = {
            "start_id": start_id, "end_id": end_id, "extra_ids": extra_raw,
            "day_iv": day_iv, "night_iv": night_iv,
        }
        app_state.alert_history = {}
        app_state.next_scan_ts = None

    app_state.monitor_thread = threading.Thread(
        target=monitor_loop,
        args=(app_state, target_ids, day_iv, night_iv),
        daemon=True,
    )
    app_state.monitor_thread.start()

    range_desc = f"{start_id}-{end_id}" if range_ids else "（无范围）"
    extra_desc = f"，额外 {len(extra_ids)} 个" if extra_ids else ""
    logging.info(f"Sentinel 已启动：范围 {range_desc}{extra_desc}，共 {len(target_ids)} 个 ID")
    return True, len(target_ids)


def stop_monitoring(app_state):
    with app_state.lock:
        if not app_state.monitoring:
            return False, "当前未在监测"
        app_state.monitoring = False
        app_state.stop_event.set()
        app_state.next_scan_ts = None
    logging.warning("监控系统已被用户手动挂起。")
    return True, None


def make_handler(app_state, index_path):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass  # 静默 HTTP 访问日志

        def _send_json(self, obj, code=200):
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/" or self.path == "/index.html":
                try:
                    with open(index_path, "rb") as f:
                        body = f.read()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except OSError:
                    self.send_error(404, "index.html not found")
            elif self.path == "/api/status":
                self._send_json(app_state.snapshot())
            else:
                self.send_error(404)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            try:
                params = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                self._send_json({"ok": False, "error": "请求体不是有效的 JSON"}, 400)
                return

            if self.path == "/api/start":
                if app_state.monitoring:
                    self._send_json({"ok": False, "error": "监测已在运行中，请先停止"}, 409)
                    return
                ok, result = start_monitoring(app_state, params)
                if ok:
                    self._send_json({"ok": True, "count": result})
                else:
                    self._send_json({"ok": False, "error": result}, 400)
            elif self.path == "/api/stop":
                ok, result = stop_monitoring(app_state)
                self._send_json({"ok": True} if ok else {"ok": False, "error": result})
            elif self.path == "/api/llm":
                base_url = str(params.get("base_url", ""))
                api_key = str(params.get("api_key", ""))
                model = str(params.get("model", ""))
                if not (base_url and model and (api_key or app_state.translator.settings.get("api_key"))):
                    self._send_json({"ok": False, "error": "Base URL、API Key、模型均不能为空"}, 400)
                    return
                app_state.translator.configure(base_url, api_key, model)
                logging.info(f"LLM 翻译已配置：{app_state.translator.public_info()['model']} @ {base_url}")
                self._send_json({"ok": True, "llm": app_state.translator.public_info()})
            elif self.path == "/api/translate":
                if not app_state.translator.configured:
                    self._send_json({"ok": False, "error": "请先在设置中配置 LLM API"}, 400)
                    return
                started = trigger_translation(app_state, manual=True)
                if started:
                    self._send_json({"ok": True, "message": "翻译已开始"})
                else:
                    self._send_json({"ok": False, "error": "翻译正在进行中或没有需要翻译的标题"})
            else:
                self.send_error(404)

    return Handler


def main():
    app_state = AppState()
    logging.getLogger().addHandler(WebLogHandler(app_state))

    index_path = resource_path(os.path.join("web", "index.html"))
    server = ThreadingHTTPServer((WEB_HOST, WEB_PORT), make_handler(app_state, index_path))
    url = f"http://{'127.0.0.1' if WEB_HOST in ('127.0.0.1', 'localhost') else WEB_HOST}:{WEB_PORT}"
    logging.info(f"DDB Beyond Sentinel v2.5 已就绪：{url}")

    # 仅本机监听时自动打开浏览器（服务器部署无桌面环境则跳过）
    if WEB_HOST in ("127.0.0.1", "localhost"):
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("收到退出信号，正在关闭…")
    finally:
        stop_monitoring(app_state)
        server.server_close()


if __name__ == "__main__":
    main()
