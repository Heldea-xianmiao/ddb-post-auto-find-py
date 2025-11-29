import argparse
import re
import requests
import logging
import html
import time
import ctypes
import subprocess
from typing import List

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

BASE = "https://www.dndbeyond.com/posts/{}"
REQUEST_TIMEOUT = 10
USER_AGENT = "jianshi/1.0 (+https://example.local/)"

# 在常量区加入正文最小长度阈值
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
    """发送 Windows 通知 (通过 PowerShell)"""
    ps_script = f"""
    $ErrorActionPreference = 'Stop'
    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
    $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
    $textNodes = $template.GetElementsByTagName("text")
    $textNodes.Item(0).AppendChild($template.CreateTextNode('{title}')) > $null
    $textNodes.Item(1).AppendChild($template.CreateTextNode('{message}')) > $null
    $toast = [Windows.UI.Notifications.ToastNotification]::new($template)
    $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('DDB Monitor')
    $notifier.Show($toast)
    """
    try:
        # 0x08000000 is CREATE_NO_WINDOW
        subprocess.run(["powershell", "-Command", ps_script], check=False, creationflags=0x08000000)
    except Exception as e:
        logging.error(f"发送通知失败: {e}")

def parse_ids(raw: str) -> List[int]:
    ids = []
    for part in raw.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            try:
                a_s, b_s = part.split('-', 1)
                a, b = int(a_s), int(b_s)
                if a > b:
                    a, b = b, a
                ids.extend(range(a, b + 1))
            except ValueError:
                logging.warning("跳过无法解析的区间: %r", part)
        else:
            try:
                ids.append(int(part))
            except ValueError:
                logging.warning("跳过无法解析的 ID: %r", part)
    return ids

def _extract_body_text(html_text: str) -> str:
    # 优先抽取 <article> 或常见正文容器的内部文本；否则返回空（避免把导航/侧栏/页脚当正文）
    if not html_text:
        return ""
    # 去掉脚本和样式
    t = re.sub(r'(?is)<(script|style).*?>.*?</\1>', '', html_text)
    # 尝试 <article>
    m = re.search(r'(?is)<article\b[^>]*>(.*?)</article>', t)
    if m:
        body_html = m.group(1)
    else:
        # 常见正文类名（只在匹配到时才取出内部）
        m2 = re.search(r'(?is)<(div|section)[^>]+class=["\'][^"\']*(post|article|post-content|article-content|entry-content)[^"\']*["\'][^>]*>(.*?)</\1>', t)
        if m2:
            body_html = m2.group(3)
        else:
            # 不找不到正文容器时返回空，避免把整页导航/错误页当正文
            return ""
    # 去掉所有标签，解码 HTML 实体，压缩空白
    body_text = re.sub(r'(?s)<[^>]+>', ' ', body_html)
    body_text = html.unescape(body_text)
    body_text = re.sub(r'\s+', ' ', body_text).strip()
    return body_text

def check_id_detailed(session: requests.Session, n: int):
    url = BASE.format(n)
    try:
        r = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        final = r.url or ""
        text = r.text or ""

        # 明确 404
        if r.status_code == 404:
            return {"id": n, "present": False, "viewable": False, "status": r.status_code, "final_url": final, "error": None, "reason": "404_not_found"}

        # 常用存在性线索（slug / canonical / body slug / article 标记）
        slug_in_final = bool(re.search(rf"/posts/{n}-", final))
        canonical = re.search(rf'<link[^>]+rel=["\']canonical["\'][^>]+href=["\']([^"\']*?/posts/{n}-[A-Za-z0-9\-]+)["\']', text, re.I)
        body_has_slug = bool(re.search(rf"/posts/{n}-[A-Za-z0-9\-]+", text))
        article_marker = bool(re.search(r"<article\b|property=[\"']og:type[\"']\s+content=[\"']article[\"']|class=[\"'](post|article)-content", text, re.I))

        # 检测页面是否为登录/付费/受限提示（页面提示短语或明显的 403 错误页结构）
        access_denied_phrases = r"(need to sign in|please sign in|sign in to view|log in|please log in|you do not have permission|access denied|403 forbidden|preview only|subscribe to view|paywall|会员|登录|请登录|需要登录)"
        blocked_by_phrase = bool(re.search(access_denied_phrases, text, re.I))

        # 额外检测 403 错误页的显式标识（使用你提供的样例参考）
        explicit_403_indicators = bool(re.search(r"(error-page-403|error-page error-page-403|Forbidden - D&amp;D Beyond|<title>Forbidden|403 Forbidden|In other words, you don’t have access to this page|body-error)", text, re.I))

        # 提取正文文本并判断长度（注意：如果页面没有明确正文容器，_extract_body_text 会返回空）
        body_text = _extract_body_text(text)
        body_len = len(body_text)

        # 特殊处理 403：优先使用显式 403 错误页标识；若没有错误页标识且确实能提取到正文（article 或 post-content），则认为可查看
        if r.status_code == 403:
            if explicit_403_indicators:
                # 明确的 403 错误页 -> 真正被阻断
                present = bool(slug_in_final or canonical or body_has_slug or article_marker)
                viewable = False
                reason = "http_403_blocked"
            else:
                # 返回 403 但没有错误页模板标识，检查是否能抽取到实际正文且长度足够
                if body_len >= BODY_TEXT_MIN and article_marker:
                    present = True
                    viewable = True
                    reason = "viewable_despite_403"
                else:
                    present = bool(slug_in_final or canonical or body_has_slug or article_marker)
                    viewable = False
                    reason = "http_403_blocked"
            return {"id": n, "present": present, "viewable": viewable, "status": r.status_code, "final_url": final, "error": None, "reason": reason}

        # 非 403 情况，继续常规判断
        present = slug_in_final or bool(canonical) or body_has_slug or article_marker
        # 如果页面包含登录/付费提示或显式 403 模板标识，则视为不可查看
        blocked = blocked_by_phrase or explicit_403_indicators
        viewable = present and (not blocked)
        # 如果存在但无法提取到实际正文（正文容器为空或正文太短），也认为不可查看
        if present and body_len < BODY_TEXT_MIN:
            viewable = False

        if explicit_403_indicators:
            reason = "http_403_blocked"
        elif blocked_by_phrase:
            reason = "blocked_by_page"
        elif present and not viewable:
            reason = "present_but_not_viewable"
        elif present and viewable:
            reason = "viewable"
        else:
            reason = "not_present"

        return {"id": n, "present": present, "viewable": viewable, "status": r.status_code, "final_url": final, "error": None, "reason": reason}
    except Exception as e:
        return {"id": n, "present": False, "viewable": False, "status": None, "final_url": None, "error": str(e), "reason": "exception"}

def main():
    p = argparse.ArgumentParser(description="DDB帖子链接监控：检测给定 ID（逗号或范围），输出后退出")
    p.add_argument("--ids", required=True, help="单个ID、逗号列表或范围，例如 2075-2090 或 2080,2085")
    args = p.parse_args()
    ids = parse_ids(args.ids)
    if not ids:
        logging.error("未解析到任何 ID")
        return

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    found = []
    for n in ids:
        info = check_id_detailed(session, n)
        if info["error"]:
            print(f"ID {n}: 错误：{info['error']}")
            continue

        status = info.get("status")
        present = info.get("present", False)
        viewable = info.get("viewable", False)
        reason = info.get("reason")

        present_str = "链接存在" if present else "链接不存在"
        viewable_str = "内容可查看" if viewable else "内容不可查看"

        reason_map = {
            "404_not_found": "404 未找到",
            "http_403": "HTTP 403（受限）",
            "http_403_blocked": "HTTP 403（已被阻断）",
            "viewable_despite_403": "尽管 403 但可查看",
            "blocked_by_page": "页面受限（需登录/付费）",
            "present_but_not_viewable": "存在但不可查看",
            "viewable": "可查看",
            "not_present": "不存在",
            "exception": "请求异常"
        }
        reason_str = reason_map.get(reason, reason or "")

        print(f"ID {n}: 状态={status}, {present_str}, {viewable_str}, 原因={reason_str}, 链接={info.get('final_url')}")

        # 把“已发现”定义为 链接存在（present=True），不再要求必须可查看
        if present:
            found.append((n, info.get("final_url"), viewable))

    # 修改：将以下代码块向左取消缩进，使其在 for 循环结束后只执行一次
    if found:
        # 选最大 ID 的已发现项（即使该项不可查看也会被选中）
        max_id, max_url, max_viewable = max(found, key=lambda x: x[0])
        viewable_note = "（可查看）" if max_viewable else "（不可查看）"
        print(f"最大已发现内容的 ID: {max_id} -> {max_url} {viewable_note}")
        return max_id
    else:
        print("未发现已发布的帖子（链接存在）")
        return None

if __name__ == "__main__":
    last_max_id = None
    print("开始循环监控模式... (按 Ctrl+C 停止)")
    
    while True:
        try:
            # 运行主检查逻辑
            current_max_id = main()
            
            if current_max_id is not None:
                # 如果是第一次运行，记录当前最大ID
                if last_max_id is None:
                    last_max_id = current_max_id
                # 如果发现比上次记录更大的ID，则触发通知
                elif current_max_id > last_max_id:
                    msg = f"发现新帖子 ID: {current_max_id}"
                    print(f"\n{'!'*20}\n{msg}\n{'!'*20}\n")
                    flash_taskbar()
                    show_notification("DDB 监控更新", msg)
                    last_max_id = current_max_id
            
            print(f"当前系统时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
            print("-" * 40)
            print("等待 240 秒后重新检查...")
            time.sleep(240)
            print("\n正在重新开始检查...\n")
            
        except KeyboardInterrupt:
            print("\n程序已退出。")
            break
        except SystemExit:
            # 处理 argparse 的帮助或错误退出
            break
        except Exception as e:
            logging.error(f"运行中发生错误: {e}")
            time.sleep(60)