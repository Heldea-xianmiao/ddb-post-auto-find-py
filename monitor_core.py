"""
DDB 帖子监控脚本 (Optimized Version)
"""

import argparse
import re
import requests
import logging
import html
import time
import ctypes
import subprocess
import urllib.parse
from typing import List, Dict, Any

# 配置日志
logging.basicConfig(
    level=logging.INFO, 
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)

# 常量配置
BASE_URL = "https://www.dndbeyond.com/posts/{}"
REQUEST_TIMEOUT = 10
USER_AGENT = "jianshi/1.1 (+https://example.local/)"
DEFAULT_QQ_KEY = ""
# 这里填Qmsg的Key
BODY_TEXT_MIN = 200

def flash_taskbar():
    """闪烁任务栏图标"""
    try:
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.FlashWindow(hwnd, True)
    except Exception:
        pass

def show_notification(title, message):
    """发送 Windows 系统通知"""
    ps_script = f"""
    $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
    $textNodes = $template.GetElementsByTagName("text")
    $textNodes.Item(0).AppendChild($template.CreateTextNode('{title}')) > $null
    $textNodes.Item(1).AppendChild($template.CreateTextNode('{message}')) > $null
    $toast = [Windows.UI.Notifications.ToastNotification]::new($template)
    [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('DDB Monitor').Show($toast)
    """
    try:
        subprocess.run(["powershell", "-Command", ps_script], check=False, creationflags=0x08000000)
    except Exception as e:
        logging.debug(f"通知发送失败: {e}")

def send_qq_msg(message, key=None):
    """通过 WebHook 发送 QQ 消息"""
    if not key:
        return  # 用户未填写 Key 则不发送，保护隐私
    
    url = f"https://qmsg.zendee.cn/send/{key}"
    try:
        resp = requests.get(url, params={"msg": message}, timeout=10)
        if resp.status_code == 200:
            logging.info(f"QQ 消息已发送: {resp.text}")
        else:
            logging.error(f"QQ 发送失败 (HTTP {resp.status_code})")
    except Exception as e:
        logging.error(f"QQ 发送异常: {e}")

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
    """提取正文以判断是否有实质内容"""
    if not html_text: return ""
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
        return html.unescape(body_text).strip()
    return ""

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
        res["title"] = _extract_title(r.url)
        text = r.text

        if r.status_code == 404:
            res["reason"] = "not_found"
            return res

        # 存在性判断
        has_slug = bool(re.search(rf"/posts/{n}-", r.url))
        has_canonical = bool(re.search(rf'rel=["\']canonical["\'][^>]+posts/{n}-', text))
        has_marker = bool(re.search(r"<article\b|class=[\"'](post|article)-content", text, re.I))
        res["present"] = has_slug or has_canonical or has_marker

        # 阻断判断
        blocked_phrases = r"(need to sign in|please sign in|sign in to view|log in|access denied|403 forbidden|登录|会员)"
        is_blocked_page = bool(re.search(blocked_phrases, text, re.I))
        is_explicit_403 = bool(re.search(r"(error-page-403|Forbidden - D&amp;D Beyond)", text, re.I))
        
        body_len = len(_extract_body_text(text))
        
        if r.status_code == 403:
            if is_explicit_403:
                res["reason"] = "blocked_403"
            elif body_len >= BODY_TEXT_MIN:
                res["viewable"] = True
                res["reason"] = "viewable_despite_403"
            else:
                res["reason"] = "blocked_403"
        else:
            if res["present"]:
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

def _extract_title(url: str) -> str:
    """从 URL 中提取标题部分"""
    if not url: return "未知标题"
    # 匹配 /posts/1234-title-slug
    m = re.search(r"/posts/(\d+-.+)", url)
    return m.group(1) if m else url

def run_scan(session: requests.Session, ids: List[int]) -> Dict[int, Dict[str, Any]]:
    """运行一次完整的扫描循环"""
    results = {}
    reason_map = {
        "not_found": "404 未找到（不存在）",
        "blocked_403": "403 已被阻断",
        "viewable_despite_403": "存在且可查看（尽管 403）",
        "present_but_blocked": "存在但无法查看",
        "viewable": "可查看",
        "not_present": "不存在",
        "unknown": "未知状态"
    }

    for n in ids:
        info = check_id_detailed(session, n)
        results[n] = info
        
        status = info["status"]
        p_str = "存在" if info["present"] else "不存在"
        v_str = "可查看" if info["viewable"] else "不可查看"
        
        raw_reason = info["reason"]
        # 处理带 error 前缀的情况
        if raw_reason.startswith("error:"):
            reason_zh = f"请求异常 ({raw_reason[6:].strip()})"
        else:
            reason_zh = reason_map.get(raw_reason, raw_reason)

        title_display = f"，标题为: \n{info['title']}" if info["present"] else ""
        logging.info(f"ID {n:4} | {p_str} | {v_str} | 原因: {reason_zh}{title_display}")
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DDB 帖子状态监控 v1.1")
    parser.add_argument("--ids", default="2150-2170", help="要监控的 ID（例如: 2150-2160,2165）")
    parser.add_argument("--interval", type=int, default=0, help="检测间隔（秒），如果不提供则根据时间段自动调整")
    args = parser.parse_args()

    target_ids = parse_ids(args.ids)
    if not target_ids:
        logging.error("没有有效的 ID 可监控。")
        exit(1)

    logging.info(f"开始监控 ID: {target_ids}")
    send_qq_msg(f"DDB 监控已启动 (ID: {args.ids})")
    
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    
    last_results = {}
    
    try:
        while True:
            current_results = run_scan(session, target_ids)
            notifications = []

            for n, info in current_results.items():
                old = last_results.get(n)
                if not old: continue # 第一次运行不报警

                # 变化检测
                if not old["present"] and info["present"]:
                    notifications.append(f"【新发现】ID {n}: {info['title']}\n{info['final_url']}")
                elif not old["viewable"] and info["viewable"]:
                    notifications.append(f"【可查看】ID {n}: {info['title']}\n{info['final_url']}")

            if notifications:
                msg = "\n\n".join(notifications)
                logging.info("发现状态更新，发送通知...")
                flash_taskbar()
                show_notification("DDB 监控更新", f"发现 {len(notifications)} 处变动")
                send_qq_msg(msg)

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


