from keel.adapters.base import CommandResult
from keel.adapters.process import run_cli


def template_scan(target: str, rate: float, severity: str) -> CommandResult:
    return run_cli(
        [
            "nuclei",
            "-u",
            target,
            "-jsonl",
            "-silent",
            "-rl",
            str(max(int(rate), 1)),
            "-c",
            "5",
            "-severity",
            severity,
        ],
        timeout=300,
    )
