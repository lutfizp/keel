from __future__ import annotations

import hashlib
import json
from urllib.parse import urlparse


def fingerprint(kind: str, host: str, path: str, matcher: str) -> str:
    path_norm = path.rstrip("/") or "/"
    raw = "|".join([kind.lower(), host.lower(), path_norm, matcher.lower()])
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def split_url(url: str) -> tuple[str, str]:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = (parsed.hostname or "").lower()
    path = parsed.path or "/"
    return host, path


def load_json_lines(text: str) -> list[dict]:
    rows: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows
