"""
DDB 帖子监控核心模块 (v2.2)

统一的帖子状态检测逻辑，供 CLI 监控、GUI 和全量扫描 (scan_all.py) 复用。
"""

import argparse
import re
import logging
import html
import os
import time
import ctypes
import subprocess
from typing import List, Dict, Any

import requests

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)

# 常量配置
BASE_URL = "https://www.dndbeyond.com/posts/{}"
REQUEST_TIMEOUT = 10
USER_AGENT = "jianshi/1.2 (+https://example.local/)"
BODY_TEXT_MIN = 200

# 阻断页关键词（优先在正文中匹配，避免全站头部 "Sign in" 误判）
BLOCKED_PHRASES = (
    r"(need to sign in|please sign in|sign in to view|log in|please log in|"
    r"you do not have permission|access denied|403 forbidden|preview only|"
    r"subscribe to view|paywall|会员|登录|请登录|需要登录)"
)
EXPLICIT_403_PATTERN = r"(error-page-403|Forbidden - D&amp;D Beyond)"

# 状态原因中文映射（CLI 与 GUI 共用）
REASON_MAP = {
    "not_found": "404 未找到",
    "blocked_403": "403 已被阻断",
    "viewable_despite_403": "可查看（尽管 403）",
    "present_but_blocked": "存在但无法查看",
    "viewable": "可查看",
    "not_present": "不存在",
    "unknown": "未知状态",
}


def reason_zh(reason: str) -> str:
    """将 reason 代码转为中文说明"""
    if reason.startswith("error:"):
        return f"请求异常 ({reason[6:].strip()})"
    return REASON_MAP.get(reason, reason)


def flash_taskbar():
    """闪烁任务栏图标"""
    try:
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.FlashWindow(hwnd, True)
    except Exception:
        pass


def show_notification(title, message):
    """发送 Windows 系统通知（通过环境变量传参，避免特殊字符注入 PowerShell）"""
    ps_script = r"""
$title = [System.Security.SecurityElement]::Escape($env:DDB_TOAST_TITLE)
$message = [System.Security.SecurityElement]::Escape($env:DDB_TOAST_MSG)
$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$textNodes = $template.GetElementsByTagName("text")
[void]$textNodes.Item(0).AppendChild($template.CreateTextNode($title))
[void]$textNodes.Item(1).AppendChild($template.CreateTextNode($message))
$toast = [Windows.UI.Notifications.ToastNotification]::new($template)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('DDB Monitor').Show($toast)
"""
    try:
        env = {**os.environ, "DDB_TOAST_TITLE": title, "DDB_TOAST_MSG": message}
        subprocess.run(
            ["powershell", "-Command", ps_script],
            check=False, creationflags=0x08000000, env=env
        )
    except Exception as e:
        logging.debug(f"通知发送失败: {e}")


def parse_ids(raw: str) -> List[int]:
    """解析 ID 字符串（支持逗号分隔和范围）"""
    ids = []
    for part in raw.split(','):
        part = part.strip()
        if not part: continue
        if '-' in part:
            try:
                a_s, b_s = part.split('-', 1)
                a, b = int(a_s), int(b_s)
                ids.extend(range(min(a, b), max(a, b) + 1))
            except ValueError:
                logging.warning(f"无法解析区间: {part}")
        else:
            try:
                ids.append(int(part))
            except ValueError:
                logging.warning(f"无法解析 ID: {part}")
    return sorted(list(set(ids)))


def _extract_body_text(html_text: str) -> str:
    """从 HTML 中提取正文文本"""
    if not html_text:
        return ""
    # 移除脚本和样式
    t = re.sub(r'(?is)<(script|style).*?>.*?</\1>', '', html_text)
    # 尝试匹配 <article> 或常见正文容器
    m = re.search(r'(?is)<article\b[^>]*>(.*?)</article>', t)
    if not m:
        m = re.search(r'(?is)<(div|section)[^>]+class=["\'][^"\']*(post|article|post-content|article-content|entry-content)[^"\']*["\'][^>]*>(.*?)</\1>', t)

    if m:
        # 如果有多个 group，取最后一个
        body_html = m.group(m.lastindex)
        body_text = re.sub(r'(?s)<[^>]+>', ' ', body_html)
        body_text = html.unescape(body_text)
        body_text = re.sub(r'\s+', ' ', body_text).strip()
        return body_text
    return ""


def _extract_title(url: str) -> str:
    """从最终 URL 中提取标题部分"""
    if not url:
        return "未知标题"
    # 匹配 /posts/1234-title-slug
    m = re.search(r"/posts/(\d+-.+)", url)
    if m:
        return m.group(1)
    # 兜底：取 URL 最后一段
    candidate = url.rstrip('/').split('/')[-1]
    if candidate and not candidate.startswith("www.") and "://" not in candidate:
        return candidate
    return url


def check_id_detailed(session: requests.Session, n: int) -> Dict[str, Any]:
    """检查单个 ID 的详细状态"""
    url = BASE_URL.format(n)
    res = {
        "id": n, "present": False, "viewable": False, "status": None,
        "final_url": None, "reason": "unknown", "title": "未知标题"
    }

    try:
        r = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        res["status"] = r.status_code
        res["final_url"] = r.url
        final = r.url or ""
        text = r.text or ""

        if r.status_code == 404:
            res["reason"] = "not_found"
            return res

        res["title"] = _extract_title(final)

        # 存在性判断（多重线索）
        slug_in_final = bool(re.search(rf"/posts/{n}-", final))
        has_canonical = bool(re.search(
            rf'<link[^>]+rel=["\']canonical["\'][^>]+href=["\'][^"\']*?/posts/{n}-[A-Za-z0-9\-]+["\']',
            text, re.I))
        body_has_slug = bool(re.search(rf"/posts/{n}-[A-Za-z0-9\-]+", text))
        has_marker = bool(re.search(
            r"<article\b|property=[\"']og:type[\"']\s+content=[\"']article[\"']|class=[\"'](post|article)-content",
            text, re.I))
        present = slug_in_final or has_canonical or body_has_slug or has_marker
        res["present"] = present

        # 阻断判断（v2.1 修复：提取到正文时只搜正文，避免全站头部 "Sign in to view" 误杀）
        body_text = _extract_body_text(text)
        search_target = body_text if body_text else text
        is_blocked_page = bool(re.search(BLOCKED_PHRASES, search_target, re.I))
        is_explicit_403 = bool(re.search(EXPLICIT_403_PATTERN, text, re.I))

        body_len = len(body_text)

        if r.status_code == 403:
            if is_explicit_403:
                res["reason"] = "blocked_403"
            elif body_len >= BODY_TEXT_MIN and has_marker:
                res["viewable"] = True
                res["reason"] = "viewable_despite_403"
            else:
                res["reason"] = "blocked_403"
        else:
            if present:
                if is_blocked_page or is_explicit_403 or body_len < BODY_TEXT_MIN:
                    res["reason"] = "present_but_blocked"
                else:
                    res["viewable"] = True
                    res["reason"] = "viewable"
            else:
                res["reason"] = "not_present"
    except Exception as e:
        res["reason"] = f"error: {str(e)}"

    return res


def run_scan(session: requests.Session, ids: List[int]) -> Dict[int, Dict[str, Any]]:
    """运行一次完整的扫描循环"""
    results = {}

    for n in ids:
        info = check_id_detailed(session, n)
        results[n] = info

        p_str = "存在" if info["present"] else "不存在"
        v_str = "可查看" if info["viewable"] else "不可查看"
        reason_zh_str = reason_zh(info["reason"])

        title_display = f"，标题为: \n{info['title']}" if info["present"] else ""
        logging.info(f"ID {n:4} | {p_str} | {v_str} | 原因: {reason_zh_str}{title_display}")
    return results


def detect_changes(last_results: Dict[int, Dict[str, Any]],
                   current_results: Dict[int, Dict[str, Any]]) -> List[str]:
    """对比两次扫描结果，返回变化通知列表"""
    notifications = []
    for n, info in current_results.items():
        old = last_results.get(n)
        if not old: continue  # 第一次运行不报警

        # 变化检测
        if not old["present"] and info["present"]:
            notifications.append(f"【新发现】ID {n}: {info['title']}\n{info['final_url']}")
        elif not old["viewable"] and info["viewable"]:
            notifications.append(f"【可查看】ID {n}: {info['title']}\n{info['final_url']}")
    return notifications


def notify(notifications: List[str]):
    """本地通知：任务栏闪烁 + Windows Toast + 日志"""
    if not notifications:
        return
    flash_taskbar()
    show_notification("DDB 监控更新", f"发现 {len(notifications)} 处变动")
    for msg in notifications:
        logging.info(f"状态更新: {msg}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DDB 帖子状态监控 v2.2")
    parser.add_argument("--ids", default="2230-2260", help="要监控的 ID（例如: 2230-2260,2265）")
    parser.add_argument("--interval", type=int, default=0, help="检测间隔（秒），如果不提供则根据时间段自动调整")
    args = parser.parse_args()

    target_ids = parse_ids(args.ids)
    if not target_ids:
        logging.error("没有有效的 ID 可监控。")
        exit(1)

    logging.info(f"开始监控 ID: {target_ids}")

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    last_results = {}

    try:
        while True:
            current_results = run_scan(session, target_ids)
            notify(detect_changes(last_results, current_results))
            last_results = current_results

            # 确定等待时间
            if args.interval > 0:
                wait = args.interval
            else:
                # 默认逻辑：日间 1 小时，夜间 15 分钟
                hour = time.localtime().tm_hour
                wait = 3600 if 8 <= hour < 20 else 900

            logging.info(f"等待 {wait} 秒后进行下次检查...")
            time.sleep(wait)

    except KeyboardInterrupt:
        logging.info("用户停止监控。")
    except Exception as e:
        logging.error(f"全局异常: {e}", exc_info=True)
