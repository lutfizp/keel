import re
from typing import Any

_SECRET = re.compile(
    r"(?i)(authorization\s*:\s*[^\r\n]*|(?:set-)?cookie\s*:\s*[^\r\n]*|"
    r"bearer\s+\S+|(?:x-)?api[_-]?key\s*[:=]\s*\S+|password\s*[:=]\s*\S+)"
)
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_DROP_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "request",
    "response",
    "raw-request",
    "raw-response",
    "curl-command",
}


def clip(text: str, limit: int = 2000) -> str:
    redacted = _SECRET.sub("[redacted]", text)
    redacted = _EMAIL.sub("[email]", redacted)
    if len(redacted) <= limit:
        return redacted
    return redacted[:limit] + "…"


def sanitize_evidence(value: Any, depth: int = 0) -> Any:
    if depth > 5:
        return "[depth-limited]"
    if isinstance(value, dict):
        clean: dict[str, Any] = {}
        for key, item in list(value.items())[:100]:
            name = str(key)
            if name.lower() in _DROP_KEYS:
                clean[name] = "[redacted]"
            else:
                clean[name] = sanitize_evidence(item, depth + 1)
        return clean
    if isinstance(value, list):
        return [sanitize_evidence(item, depth + 1) for item in value[:100]]
    if isinstance(value, str):
        return clip(value, 2000)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return clip(str(value), 500)
