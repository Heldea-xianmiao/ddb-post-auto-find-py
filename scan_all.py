"""
DDB 帖子全量扫描脚本 (查漏补缺版)

Description:
    此脚本用于全量扫描 D&D Beyond (DDB) 网站上的帖子。
    它会自动读取 `dic.txt`，跳过已存在的 ID，只扫描缺失的部分。
    扫描结果（包括不存在的 ID）会按顺序插入到文件中。

    检测逻辑复用 monitor_core.check_id_detailed，与监控程序保持一致。

Usage:
    python scan_all.py                    # 扫描 1-2260（默认）
    python scan_all.py --start 2100       # 从 2100 开始
    python scan_all.py --end 2300         # 扫描至 2300

Author: AI Assistant & User
Date: 2025-12-07 (updated 2026-10-02)
"""

import os
import re
import time
import random
import logging
import argparse

import requests

from monitor_core import (
    USER_AGENT,
    check_id_detailed,
)

# 配置日志
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# 常量配置
OUTPUT_FILE = "dic.txt"
DEFAULT_START_ID = 1
DEFAULT_END_ID = 2260  # 截至 2026-10，DDB 最新帖子 ID 约 2248
BATCH_SIZE = 20  # 每扫描20个新ID保存一次


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
    parser = argparse.ArgumentParser(description="DDB 帖子全量补缺扫描")
    parser.add_argument("--start", type=int, default=DEFAULT_START_ID, help="起始 ID（默认 1）")
    parser.add_argument("--end", type=int, default=DEFAULT_END_ID, help="终止 ID（默认 2260）")
    parser.add_argument("--file", default=OUTPUT_FILE, help="输出文件路径（默认 dic.txt）")
    args = parser.parse_args()

    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), args.file)

    # 1. 读取现有数据
    logging.info(f"正在读取现有文件: {output_path}")
    existing_data = load_existing_data(output_path)
    logging.info(f"已加载 {len(existing_data)} 条现有记录")

    # 2. 计算缺失 ID
    all_ids = range(args.start, args.end + 1)
    missing_ids = [n for n in all_ids if n not in existing_data]

    if not missing_ids:
        logging.info(f"太棒了！所有 ID ({args.start}-{args.end}) 都已存在，无需扫描。")
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
