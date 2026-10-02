"""
标题翻译服务 — 调用 OpenAI 兼容 LLM API 将帖子标题 slug 翻译为中文

- 配置持久化到 settings.json（base_url / api_key / model）
- 翻译缓存持久化到 translations.json，避免重复调用计费
- 单文件、无状态，可独立测试
"""

import json
import logging
import os
import re
import threading
import time

import requests

logger = logging.getLogger(__name__)

SETTINGS_FILE = "settings.json"
CACHE_FILE = "translations.json"
LLM_TIMEOUT = 60
# 连续失败后的自动重试退避：60s 起步指数翻倍，封顶 30 分钟
BACKOFF_BASE = 60
BACKOFF_MAX = 1800

SYSTEM_PROMPT = (
    "你是一个标题翻译器。用户会给出一个 JSON 数组，元素是英文文章标题的 URL slug "
    "（单词以连字符分隔）。请将每个标题翻译为简体中文，遵循以下规则：\n"
    "1. 先把 slug 还原为正常英文标题再翻译\n"
    "2. D&D 桌游术语使用通行译名，例如 Dragonlance=龙枪、Dragonmark=龙纹、"
    "Artificer=工匠、Bard=吟游诗人、Spell=法术、Feat=专长、Subclass=子职业\n"
    "3. 仅输出一个 JSON 对象，格式为 {\"<原slug>\": \"<中文翻译>\"}，不要输出其他任何内容"
)


def slug_to_title(slug):
    """slug 转可读标题：from-kalimdor-to-northrend → From Kalimdor To Northrend"""
    return slug.replace("-", " ").strip().title()


class TranslationService:
    def __init__(self, base_dir):
        self.lock = threading.Lock()
        self.base_dir = base_dir
        self.settings_path = os.path.join(base_dir, SETTINGS_FILE)
        self.cache_path = os.path.join(base_dir, CACHE_FILE)
        self.settings = self._load_json(self.settings_path, {})
        self.cache = self._load_json(self.cache_path, {})
        # 失败退避状态（防止自动重试空烧 token）
        self._fail_count = 0
        self._fail_until = 0.0

    def auto_allowed(self):
        """自动翻译是否被退避限制（手动触发不受限）"""
        return time.time() >= self._fail_until

    @staticmethod
    def _load_json(path, default):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return default

    def _save_json(self, path, obj):
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(obj, f, ensure_ascii=False, indent=2)
        except OSError as e:
            logger.warning(f"写入 {os.path.basename(path)} 失败: {e}")

    # ---------- 配置 ----------

    @property
    def configured(self):
        s = self.settings
        return bool(s.get("base_url") and s.get("api_key") and s.get("model"))

    def public_info(self):
        """返回不含密钥的配置摘要（供前端展示）"""
        s = self.settings
        return {
            "configured": self.configured,
            "base_url": s.get("base_url", ""),
            "model": s.get("model", ""),
            "has_key": bool(s.get("api_key")),
        }

    def configure(self, base_url, api_key, model):
        base_url = (base_url or "").strip().rstrip("/")
        api_key = (api_key or "").strip()
        model = (model or "").strip()
        with self.lock:
            # api_key 传空表示保留原有密钥
            if not api_key and base_url and base_url == self.settings.get("base_url"):
                api_key = self.settings.get("api_key", "")
            self.settings = {"base_url": base_url, "api_key": api_key, "model": model}
            self._save_json(self.settings_path, self.settings)
        return self.configured

    # ---------- 翻译 ----------

    def cached(self, slug):
        with self.lock:
            return self.cache.get(slug)

    def translate_batch(self, slugs):
        """
        翻译一批 slug，返回 {slug: 中文}。
        已缓存的直接返回；调用失败返回空 dict 并记录日志。
        """
        if not self.configured:
            return {}
        with self.lock:
            pending = [s for s in slugs if s and s not in self.cache]
        if not pending:
            with self.lock:
                return {s: self.cache[s] for s in slugs if s in self.cache}

        result = {}
        try:
            batch = pending[:30]  # 单次最多 30 条，避免请求过大
            resp = requests.post(
                f"{self.settings['base_url']}/chat/completions",
                headers={"Authorization": f"Bearer {self.settings['api_key']}"},
                json={
                    "model": self.settings["model"],
                    "temperature": 0.2,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": json.dumps(batch, ensure_ascii=False)},
                    ],
                },
                timeout=LLM_TIMEOUT,
            )
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"]
            mapping = self._parse_mapping(content, batch)
            if mapping:
                self._fail_count = 0
                self._fail_until = 0.0
                with self.lock:
                    self.cache.update(mapping)
                    self._save_json(self.cache_path, self.cache)
                result = mapping
                logger.info(f"标题翻译完成：{len(mapping)} 条")
            else:
                self._record_failure()
                logger.warning("LLM 返回内容无法解析为 slug 映射")
        except Exception as e:
            self._record_failure()
            logger.error(f"标题翻译失败: {e}")

        # 合并已缓存部分
        with self.lock:
            for s in slugs:
                if s in self.cache:
                    result[s] = self.cache[s]
        return result

    def _record_failure(self):
        """记录一次失败并指数延长自动重试间隔"""
        self._fail_count += 1
        wait = min(BACKOFF_MAX, BACKOFF_BASE * (2 ** (self._fail_count - 1)))
        self._fail_until = time.time() + wait
        logger.warning(f"翻译失败退避：{wait}s 内暂停自动翻译（连续失败 {self._fail_count} 次）")

    @staticmethod
    def _parse_mapping(content, batch):
        """从 LLM 回复中提取 {slug: 中文} 映射，容忍 markdown 代码块包裹"""
        m = re.search(r"\{.*\}", content, re.S)
        if not m:
            return {}
        try:
            obj = json.loads(m.group(0))
        except json.JSONDecodeError:
            return {}
        # 只接受请求过的 slug，且值为字符串
        return {k: str(v) for k, v in obj.items()
                if isinstance(k, str) and k in batch and isinstance(v, str) and v.strip()}
