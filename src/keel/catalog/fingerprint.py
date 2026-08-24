from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlparse


_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_INTEGER = re.compile(r"^\d+$")
_HEX_TOKEN = re.compile(r"^[0-9a-f]{16,}$", re.IGNORECASE)
_SLUG = re.compile(r"[^a-z0-9]+")

_CWE_CLASSES = {
    "cwe-22": "path_traversal",
    "cwe-78": "command_injection",
    "cwe-79": "cross_site_scripting",
    "cwe-89": "sql_injection",
    "cwe-94": "code_injection",
    "cwe-200": "sensitive_data_exposure",
    "cwe-287": "authentication_bypass",
    "cwe-352": "cross_site_request_forgery",
    "cwe-639": "broken_object_authorization",
    "cwe-862": "missing_authorization",
    "cwe-863": "incorrect_authorization",
    "cwe-918": "server_side_request_forgery",
    "cwe-601": "open_redirect",
}

_KEYWORD_CLASSES = (
    (("idor", "bola", "broken object", "object authorization"), "broken_object_authorization"),
    (("auth bypass", "authentication bypass"), "authentication_bypass"),
    (("sql injection", "sqli"), "sql_injection"),
    (("cross-site scripting", "cross site scripting", "xss"), "cross_site_scripting"),
    (("server-side request forgery", "server side request forgery", "ssrf"), "server_side_request_forgery"),
    (("command injection", "os command"), "command_injection"),
    (("path traversal", "directory traversal", "lfi"), "path_traversal"),
    (("remote code execution", " rce"), "remote_code_execution"),
    (("sensitive data", "information disclosure", "data exposure"), "sensitive_data_exposure"),
    (("open redirect",), "open_redirect"),
    (("html injection", "html_injection"), "html_injection"),
)


def normalize_route(path: str) -> str:
    parsed = urlparse(path if "://" in path else f"https://placeholder{path}")
    segments: list[str] = []
    for segment in parsed.path.split("/"):
        lowered = segment.lower()
        if _UUID.fullmatch(lowered):
            segments.append("{uuid}")
        elif _INTEGER.fullmatch(lowered):
            segments.append("{id}")
        elif _HEX_TOKEN.fullmatch(lowered):
            segments.append("{token}")
        else:
            segments.append(lowered)
    normalized = "/".join(segments).rstrip("/") or "/"
    return normalized if normalized.startswith("/") else f"/{normalized}"


def canonical_vulnerability_class(
    template: str,
    title: str = "",
    cwes: list[str] | None = None,
    tags: list[str] | None = None,
) -> str:
    for cwe in cwes or []:
        canonical = str(cwe).strip().lower()
        if canonical in _CWE_CLASSES:
            return _CWE_CLASSES[canonical]

    blob = " ".join([template, title, *(tags or [])]).lower()
    for markers, vulnerability_class in _KEYWORD_CLASSES:
        if any(marker in blob for marker in markers):
            return vulnerability_class

    fallback = _SLUG.sub("_", template.lower()).strip("_")
    return fallback or "unclassified"


def fingerprint(vulnerability_class: str, host: str, path: str, parameter: str = "") -> str:
    raw = "|".join(
        [
            vulnerability_class.lower(),
            host.rstrip(".").lower(),
            normalize_route(path),
            parameter.lower(),
        ]
    )
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
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def invalid_json_line_count(text: str) -> int:
    invalid = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            invalid += 1
            continue
        if not isinstance(row, dict):
            invalid += 1
    return invalid
