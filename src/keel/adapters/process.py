from __future__ import annotations

import shutil
import subprocess

from keel.adapters.base import CommandResult
from keel.errors import AdapterFailed


def run_cli(argv: list[str], timeout: int = 120) -> CommandResult:
    binary = argv[0]
    if shutil.which(binary) is None:
        raise AdapterFailed(f"{binary} is not installed")
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise AdapterFailed(f"{binary} timed out") from exc
    blob = (completed.stdout + completed.stderr).lower()
    throttled = completed.returncode == 429 or "429" in blob or "too many requests" in blob
    return CommandResult(
        argv=argv,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        throttled=throttled,
    )
