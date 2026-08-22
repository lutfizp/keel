import re

_SECRET = re.compile(
    r"(?i)(authorization:\s+\S+(?:\s+\S+)*|bearer\s+\S+|api[_-]?key\s*[:=]\s*\S+|"
    r"password\s*[:=]\s*\S+)"
)
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def clip(text: str, limit: int = 2000) -> str:
    redacted = _SECRET.sub("[redacted]", text)
    redacted = _EMAIL.sub("[email]", redacted)
    if len(redacted) <= limit:
        return redacted
    return redacted[:limit] + "…"
