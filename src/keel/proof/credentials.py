from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from keel.errors import ProofDenied


class CredentialEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    authorization: str = ""
    cookie: str = ""


def credentials_file_summary() -> dict | None:
    configured = os.environ.get("KEEL_CREDENTIALS_FILE", "").strip()
    if not configured:
        return None
    path, document = _load_credentials(configured)
    return {"path": str(path), "references": sorted(str(key) for key in document)}


def _load_credentials(configured: str) -> tuple[Path, dict[str, CredentialEntry]]:
    configured_path = Path(configured).expanduser()
    if configured_path.is_symlink():
        raise ProofDenied("credentials file must not be a symlink")
    path = configured_path.resolve()
    _check_permissions(path)
    try:
        raw = path.read_bytes()
        if len(raw) > 1_048_576:
            raise ValueError("credentials file exceeds 1 MiB")
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise ProofDenied(f"cannot load credentials file: {exc}") from exc
    if not isinstance(payload, dict):
        raise ProofDenied("credentials file must contain an object of named references")
    try:
        document = {
            str(key): CredentialEntry.model_validate(value)
            for key, value in payload.items()
        }
    except ValueError as exc:
        raise ProofDenied(f"cannot load credentials file: {exc}") from exc
    for reference, entry in document.items():
        if not reference.strip():
            raise ProofDenied("credential references cannot be empty")
        if not entry.authorization and not entry.cookie:
            raise ProofDenied(f"credential reference {reference!r} has no usable headers")
        if entry.authorization:
            _safe_header(entry.authorization)
        if entry.cookie:
            _safe_header(entry.cookie)
    return path, document


def resolve_credential(reference: str, allowed_refs: list[str]) -> dict[str, str]:
    if not reference:
        raise ProofDenied("a tester credential reference is required")
    if reference not in allowed_refs:
        raise ProofDenied(f"credential reference {reference!r} is not operator-approved")
    configured = os.environ.get("KEEL_CREDENTIALS_FILE", "").strip()
    if not configured:
        raise ProofDenied("KEEL_CREDENTIALS_FILE is not configured")
    try:
        _, document = _load_credentials(configured)
        entry = document[reference]
    except KeyError as exc:
        raise ProofDenied(f"cannot resolve credential reference {reference!r}: {exc}") from exc
    headers: dict[str, str] = {}
    if entry.authorization:
        headers["Authorization"] = _safe_header(entry.authorization)
    if entry.cookie:
        headers["Cookie"] = _safe_header(entry.cookie)
    if not headers:
        raise ProofDenied(f"credential reference {reference!r} has no usable headers")
    return headers


def _check_permissions(path: Path) -> None:
    if not path.is_file():
        raise ProofDenied("credentials file must be a regular file")
    if os.name != "nt" and path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ProofDenied("credentials file must not be accessible by group or other users")


def _safe_header(value: str) -> str:
    if len(value) > 8192 or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ProofDenied("invalid credential header value")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"duplicate JSON key: {key}")
        document[key] = value
    return document
