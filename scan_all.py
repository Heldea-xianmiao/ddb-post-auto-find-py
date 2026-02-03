"""
DDB 帖子全量扫描脚本 (查漏补缺版)

Description:
    此脚本用于全量扫描 D&D Beyond (DDB) 网站上的帖子（ID 1 到 2150）。
    它会自动读取 `dic.txt`，跳过已存在的 ID，只扫描缺失的部分。
    扫描结果（包括不存在的 ID）会按顺序插入到文件中。

Dependencies:
    - requests
    - re
    - time
    - html

Author: AI Assistant & User
Date: 2025-12-07
"""

import requests
import re
import time
import logging
import os
import random
import html

# 配置日志
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# 常量配置
BASE_URL = "https://www.dndbeyond.com/posts/{}"
USER_AGENT = "jianshi/1.0 (+https://example.local/)"
OUTPUT_FILE = "dic.txt"
START_ID = 1
END_ID = 2150
REQUEST_TIMEOUT = 10
BATCH_SIZE = 20  # 每扫描20个新ID保存一次
BODY_TEXT_MIN = 200

def _extract_body_text(html_text: str) -> str:
    """从 HTML 中提取正文文本"""
    if not html_text:
        return ""
    t = re.sub(r'(?is)<(script|style).*?>.*?</\1>', '', html_text)
    m = re.search(r'(?is)<article\b[^>]*>(.*?)</article>', t)
    if m:
        body_html = m.group(1)
    else:
        m2 = re.search(r'(?is)<(div|section)[^>]+class=["\'][^"\']*(post|article|post-content|article-content|entry-content)[^"\']*["\'][^>]*>(.*?)</\1>', t)
        if m2:
            body_html = m2.group(3)
        else:
            return ""
    body_text = re.sub(r'(?s)<[^>]+>', ' ', body_html)
    body_text = html.unescape(body_text)
    body_text = re.sub(r'\s+', ' ', body_text).strip()
    return body_text

def check_id_detailed(session, n):
    """详细检查 ID 状态"""
    url = BASE_URL.format(n)
    try:
        r = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        final = r.url or ""
        text = r.text or ""

        if r.status_code == 404:
            return {"id": n, "present": False, "viewable": False, "title": None, "reason": "404"}

        # 提取标题
        title = "未知标题"
        m = re.search(rf"/posts/{n}-(.+)", final)
        if m:
            title = m.group(1)
        elif final:
            parts = final.rstrip('/').split('/')
            if parts:
                candidate = parts[-1]
                if candidate and not candidate.startswith("www.") and "://" not in candidate:
                    title = candidate
                else:
                    title = final
            else:
                title = final

        # 存在性线索
        slug_in_final = bool(re.search(rf"/posts/{n}-", final))
        canonical = re.search(rf'<link[^>]+rel=["\']canonical["\'][^>]+href=["\']([^"\']*?/posts/{n}-[A-Za-z0-9\-]+)["\']', text, re.I)
        body_has_slug = bool(re.search(rf"/posts/{n}-[A-Za-z0-9\-]+", text))
        article_marker = bool(re.search(r"<article\b|property=[\"']og:type[\"']\s+content=[\"']article[\"']|class=[\"'](post|article)-content", text, re.I))

        # 阻断线索
        access_denied_phrases = r"(need to sign in|please sign in|sign in to view|log in|please log in|you do not have permission|access denied|403 forbidden|preview only|subscribe to view|paywall|会员|登录|请登录|需要登录)"
        blocked_by_phrase = bool(re.search(access_denied_phrases, text, re.I))
        explicit_403_indicators = bool(re.search(r"(error-page-403|error-page error-page-403|Forbidden - D&amp;D Beyond|<title>Forbidden|403 Forbidden|In other words, you don’t have access to this page|body-error)", text, re.I))

        body_text = _extract_body_text(text)
        body_len = len(body_text)

        # 403 处理
        if r.status_code == 403:
            if explicit_403_indicators:
                present = bool(slug_in_final or canonical or body_has_slug or article_marker)
                return {"id": n, "present": present, "viewable": False, "title": title, "reason": "403_blocked"}
            else:
                if body_len >= BODY_TEXT_MIN and article_marker:
                    return {"id": n, "present": True, "viewable": True, "title": title, "reason": "viewable_despite_403"}
                else:
                    present = bool(slug_in_final or canonical or body_has_slug or article_marker)
                    return {"id": n, "present": present, "viewable": False, "title": title, "reason": "403_blocked"}

        # 常规处理
        present = slug_in_final or bool(canonical) or body_has_slug or article_marker
        blocked = blocked_by_phrase or explicit_403_indicators
        
        if present and body_len < BODY_TEXT_MIN:
            viewable = False
            reason = "blocked_by_page" if blocked else "present_but_not_viewable"
        else:
            viewable = present and (not blocked)
            reason = "viewable" if viewable else ("not_present" if not present else "blocked")

        return {"id": n, "present": present, "viewable": viewable, "title": title, "reason": reason}

    except Exception as e:
        logging.error(f"ID {n} 检测异常: {e}")
        return {"id": n, "present": False, "viewable": False, "title": None, "reason": "error"}

def load_existing_data(filepath):
    """读取现有文件，返回 {id: line_content} 字典"""
    data = {}
    if not os.path.exists(filepath):
        return data
    
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # 匹配行首的 ID (例如 "2106: ...")
            match = re.match(r"^(\d+):", line)
            if match:
                try:
                    n = int(match.group(1))
                    data[n] = line
                except ValueError:
                    pass
    return data

def save_sorted_data(filepath, data):
    """将数据按 ID 排序并写入文件"""
    sorted_ids = sorted(data.keys())
    with open(filepath, "w", encoding="utf-8") as f:
        for n in sorted_ids:
            f.write(data[n] + "\n")
    logging.info(f"文件已更新，当前共 {len(sorted_ids)} 条记录")

def main():
    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), OUTPUT_FILE)
    
    # 1. 读取现有数据
    logging.info(f"正在读取现有文件: {output_path}")
    existing_data = load_existing_data(output_path)
    logging.info(f"已加载 {len(existing_data)} 条现有记录")

    # 2. 计算缺失 ID
    all_ids = range(START_ID, END_ID + 1)
    missing_ids = [n for n in all_ids if n not in existing_data]

    if not missing_ids:
        logging.info("太棒了！所有 ID (1-2150) 都已存在，无需扫描。")
        return

    logging.info(f"发现 {len(missing_ids)} 个缺失 ID，准备开始补全...")

    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(max_retries=3)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": USER_AGENT})
    
    new_results_count = 0
    
    try:
        for current_id in missing_ids:
            info = check_id_detailed(session, current_id)
            
            # 构造输出行
            if info["present"]:
                status_tag = "[可查看]" if info["viewable"] else "[存在但不可查看]"
                title = info["title"] or "未知标题"
                line = f"{current_id}: {status_tag} {title}"
            else:
                # 即使不存在也记录，防止下次重复扫描
                line = f"{current_id}: [不存在]"
            
            logging.info(f"补全: {line}")
            
            # 更新内存数据
            existing_data[current_id] = line
            new_results_count += 1

            # 批量保存 (重写文件以保持排序)
            if new_results_count % BATCH_SIZE == 0:
                save_sorted_data(output_path, existing_data)
            
            time.sleep(random.uniform(0.1, 1.5))

        # 循环结束后的最终保存
        if new_results_count % BATCH_SIZE != 0:
            save_sorted_data(output_path, existing_data)

    except KeyboardInterrupt:
        logging.warning("\n扫描中断，正在保存已获取的数据...")
        save_sorted_data(output_path, existing_data)
        return

    logging.info(f"补全完成！共补全 {len(missing_ids)} 个 ID，文件更新至 {output_path}")

if __name__ == "__main__":
    main()
