"""
DDB 帖子监控脚本 (AI Friendly Version)

Description:
    此脚本用于监控 D&D Beyond (DDB) 网站上的新帖子发布情况。
    它通过遍历指定的 ID 范围，检查 URL 的有效性、HTTP 状态码以及页面内容特征（如 canonical 标签、文章标记等），
    来判断帖子是否存在以及是否可查看。

Key Features:
    - ID 范围扫描: 支持单个 ID、逗号分隔列表及连字符范围（如 2000-2010）。
    - 智能检测: 综合使用 HTTP 状态码 (404/403) 和页面内容正则匹配来判断帖子状态。
    - 通知系统: 支持 Windows 任务栏闪烁、系统通知 (Toast) 以及 QQ 消息推送 (WebHook)。
    - 动态调度: 根据当前系统时间自动调整检测频率（日间低频，夜间高频）。

Dependencies:
    - requests: 用于发送 HTTP 请求。
    - argparse: 用于解析命令行参数。
    - logging: 用于日志记录。
    - ctypes, subprocess: 用于 Windows 系统交互。

Configuration:
    - QQ_WEBHOOK_URL: QQ 消息推送接口地址。
    - BODY_TEXT_MIN: 判定内容有效的最小字符长度阈值。
    - REQUEST_TIMEOUT: HTTP 请求超时时间。

Author: AI Assistant & User
Date: 2025-12-01
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
from typing import List

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

BASE = "https://www.dndbeyond.com/posts/{}"
REQUEST_TIMEOUT = 10
USER_AGENT = "jianshi/1.0 (+https://example.local/)"

# --- 新增配置 ---
# 在此处填入你的 QQ 消息发送接口
QQ_WEBHOOK_URL = "" 

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

def send_qq_msg(message):
    """
    发送 QQ 消息通知。
    
    此函数通过 HTTP GET 请求调用配置的 WebHook 接口发送消息。
    支持 Qmsg 酱（需 URL 编码）和其他简单的 HTTP 接口。

    Args:
        message (str): 要发送的消息内容。

    Global Variables:
        QQ_WEBHOOK_URL (str): WebHook 接口地址。如果为空，则不执行发送。

    Side Effects:
        - 发起网络请求。
        - 记录 INFO 或 ERROR 级别的日志。
    """
    if not QQ_WEBHOOK_URL:
        return
    
    try:
        logging.info(f"正在尝试发送 QQ 消息...")
        
        # 1. 针对 Qmsg 格式 (包含 {msg})
        if "{msg}" in QQ_WEBHOOK_URL:
            # 关键修复：对中文消息进行 URL 编码
            encoded_msg = urllib.parse.quote(message)
            url = QQ_WEBHOOK_URL.format(msg=encoded_msg)
            resp = requests.get(url, timeout=10)
        else:
            # 2. 针对其他接口 (使用 params 自动编码)
            resp = requests.get(QQ_WEBHOOK_URL, params={"message": message}, timeout=10)
        
        # 3. 输出接口返回的详细结果，以便排查问题
        if resp.status_code == 200:
            logging.info(f"QQ 接口响应: {resp.text}")
        else:
            logging.error(f"QQ 接口请求失败 (HTTP {resp.status_code}): {resp.text}")
            
    except Exception as e:
        logging.error(f"QQ 消息发送异常: {e}")

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
    """
    检查指定 ID 的帖子状态。

    这是核心检测逻辑。它请求 DDB 的帖子 URL，并根据响应内容判断帖子是否存在、是否被阻断（403/登录墙）以及是否可查看。

    Args:
        session (requests.Session): 复用的 HTTP 会话对象。
        n (int): 帖子 ID。

    Returns:
        dict: 包含检测结果的字典，键包括：
            - id (int): 帖子 ID。
            - present (bool): 链接是否有效（非 404）。
            - viewable (bool): 内容是否可直接查看（未被阻断且内容长度足够）。
            - status (int): HTTP 状态码。
            - final_url (str): 重定向后的最终 URL。
            - reason (str): 判定结果的具体原因代码。
            - error (str): 异常信息（如果有）。
    """
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

        # --- 修复开始：清理混乱的代码块 ---
        
        # 1. 定义受限短语
        access_denied_phrases = r"(need to sign in|please sign in|sign in to view|log in|please log in|you do not have permission|access denied|403 forbidden|preview only|subscribe to view|paywall|会员|登录|请登录|需要登录)"
        blocked_by_phrase = bool(re.search(access_denied_phrases, text, re.I))

        # 2. 额外检测 403 错误页的显式标识
        explicit_403_indicators = bool(re.search(r"(error-page-403|error-page error-page-403|Forbidden - D&amp;D Beyond|<title>Forbidden|403 Forbidden|In other words, you don’t have access to this page|body-error)", text, re.I))

        # 3. 提取正文文本并判断长度
        body_text = _extract_body_text(text)
        body_len = len(body_text)

        # 4. 特殊处理 403：优先使用显式 403 错误页标识；若没有错误页标识且确实能提取到正文，则认为可查看
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

        # 5. 非 403 情况，继续常规判断
        present = slug_in_final or bool(canonical) or body_has_slug or article_marker
        
        # 如果页面包含登录/付费提示或显式 403 模板标识，则视为不可查看
        blocked = blocked_by_phrase or explicit_403_indicators
        
        # 如果存在但无法提取到实际正文（正文容器为空或正文太短），也认为不可查看
        if present and body_len < BODY_TEXT_MIN:
            viewable = False
            # 如果是因为被阻断导致的短内容
            if blocked:
                reason = "blocked_by_page"
            else:
                reason = "present_but_not_viewable"
        else:
            viewable = present and (not blocked)
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
        
        # --- 修复结束 ---

    except Exception as e:
        return {"id": n, "present": False, "viewable": False, "status": None, "final_url": None, "error": str(e), "reason": "exception"}

def main():
    """
    单次检测流程的主入口。

    流程：
    1. 解析命令行参数获取目标 ID 列表。
    2. 初始化 HTTP 会话。
    3. 遍历 ID 列表调用 `check_id_detailed` 进行检查。
    4. 打印每个 ID 的状态。
    5. 统计并返回当前发现的最大有效 ID。

    Returns:
        tuple or None: 如果发现有效帖子，返回 (max_id, max_url)；否则返回 None。
    """
    p = argparse.ArgumentParser(description="DDB帖子链接监控：检测给定 ID（逗号或范围），输出后退出")
    p.add_argument("--ids", required=True, help="单个ID、逗号列表或范围，例如 2075-2090 或 2080,2085")
    
    # 捕获参数解析错误
    try:
        args = p.parse_args()
    except SystemExit:
        raise

    ids = parse_ids(args.ids)
    if not ids:
        logging.error("未解析到任何 ID")
        return None

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

    if found:
        # 选最大 ID 的已发现项
        max_id, max_url, max_viewable = max(found, key=lambda x: x[0])
        viewable_note = "（可查看）" if max_viewable else "（不可查看）"
        print(f"最大已发现内容的 ID: {max_id} -> {max_url} {viewable_note}")
        return max_id, max_url
    else:
        print("未发现已发布的帖子（链接存在）")
        return None

if __name__ == "__main__":
    """
    程序入口点：循环监控模式。
    
    逻辑：
    1. 启动无限循环。
    2. 调用 `main()` 执行一次完整扫描。
    3. 比较本次扫描的最大 ID 与上次记录的最大 ID (`last_max_id`)。
    4. 如果发现新 ID (current > last)，触发通知 (弹窗、Toast、QQ)。
    5. 根据当前时间段动态休眠：
       - 日间 (08:00-20:00): 休眠 1 小时。
       - 夜间 (20:00-08:00): 休眠 15 分钟。
    """
    last_max_id = None
    print("开始循环监控模式... (按 Ctrl+C 停止)")

    # --- 新增：启动时发送一条测试消息 ---
    print("正在发送测试消息到 QQ...")
    send_qq_msg("DDB监控程序已启动，QQ消息配置成功！")
    # ----------------------------------
    
    while True:
        try:
            # 运行主检查逻辑
            result = main()
            
            if result is not None:
                current_max_id, current_max_url = result

                # 如果是第一次运行，记录当前最大ID
                if last_max_id is None:
                    last_max_id = current_max_id
                # 如果发现比上次记录更大的ID，则触发通知
                elif current_max_id > last_max_id:
                    # 尝试从 URL 中提取标题 (移除 ID 前缀)
                    title_part = current_max_url
                    if current_max_url:
                        # 匹配 /posts/1234-some-title-here
                        m = re.search(rf"/posts/{current_max_id}-(.+)", current_max_url)
                        if m:
                            title_part = m.group(1)
                    
                    msg = f"发现新帖子 ID: {current_max_id}\n{title_part}"
                    print(f"\n{'!'*20}\n{msg}\n{'!'*20}\n")
                    flash_taskbar()
                    show_notification("DDB 监控更新", msg)
                    
                    # 发送 QQ 消息
                    send_qq_msg(msg)

                    last_max_id = current_max_id
            
            print(f"当前系统时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
            print("-" * 40)
            
            # 根据时间调整检测频率
            # 8:00 - 20:00 每小时 (3600秒)
            # 20:00 - 08:00 每15分钟 (900秒)
            current_hour = time.localtime().tm_hour
            if 8 <= current_hour < 20:
                wait_seconds = 3600
                period_name = "日间模式 (8点-20点)"
            else:
                wait_seconds = 900
                period_name = "夜间模式 (20点-次日8点)"

            print(f"当前处于 {period_name}，等待 {wait_seconds} 秒 ({int(wait_seconds/60)}分钟) 后重新检查...")
            time.sleep(wait_seconds)
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