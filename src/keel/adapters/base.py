from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass


ProgressCallback = Callable[[float, str], None]


@dataclass(frozen=True)
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    throttled: bool
    retry_after_seconds: float | None = None
