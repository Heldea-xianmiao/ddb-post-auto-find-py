import re
import requests
from urllib.parse import urlparse

BASE = "https://www.dndbeyond.com/posts/{}"
HEADERS = {"User-Agent": "jianshi-test/1.0"}

ids = [2086, 2088]

for n in ids:
    url = BASE.format(n)
    try:
        r = requests.get(url, headers=HEADERS, timeout=15, allow_redirects=True)
        final = r.url
        path = urlparse(final).path or ""
        has_slug = bool(re.match(rf"^/posts/{n}-", path) or re.search(rf"/posts/{n}-[A-Za-z0-9\-]+", r.text))
        print(f"ID {n}: status={r.status_code}, final_url={final}, has_slug={has_slug}")
    except Exception as e:
        print(f"ID {n}: error: {e}")
