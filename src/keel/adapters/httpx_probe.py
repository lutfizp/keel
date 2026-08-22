from keel.adapters.base import CommandResult
from keel.adapters.process import run_cli


def probe_alive(target: str, rate: float) -> CommandResult:
    delay = max(int(1 / max(rate, 0.1) * 1000), 50)
    return run_cli(
        [
            "httpx",
            "-u",
            target,
            "-json",
            "-silent",
            "-timeout",
            "10",
            "-rate-limit",
            str(max(int(rate), 1)),
            "-delay",
            f"{delay}ms",
        ],
        timeout=90,
    )
