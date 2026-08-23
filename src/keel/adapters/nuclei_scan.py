from __future__ import annotations

from pathlib import Path

from keel.adapters.base import CommandResult
from keel.adapters.process import isolated_scanner_config, run_cli


def template_scan(
    target: str,
    rate: float,
    severity: str,
    timeout: int = 120,
    max_response_bytes: int = 1_048_576,
    template_id: str = "",
    project_path: Path | None = None,
) -> CommandResult:
    with isolated_scanner_config() as config_path:
        argv = [
            "nuclei",
            "-u",
            target,
            "-jsonl",
            "-silent",
            "-no-color",
            "-omit-raw",
            "-disable-update-check",
            "-disable-unsigned-templates",
            "-no-interactsh",
            "-disable-redirects",
            "-auth=false",
            "-config",
            str(config_path),
            "-type",
            "http",
            "-exclude-tags",
            "dos,fuzz,bruteforce,intrusive",
            "-c",
            "1",
            "-bulk-size",
            "1",
            "-payload-concurrency",
            "1",
            "-probe-concurrency",
            "1",
            "-retries",
            "0",
            "-timeout",
            "10",
            "-max-host-error",
            "5",
            "-response-size-read",
            str(max_response_bytes),
            "-response-size-save",
            str(max_response_bytes),
            "-severity",
            severity,
            *_rate_arguments(rate),
        ]
        if template_id:
            argv.extend(["-template-id", template_id])
        if project_path is not None:
            project_path.mkdir(parents=True, exist_ok=True)
            argv.extend(["-project", "-project-path", str(project_path)])
        return run_cli(argv, timeout=timeout)


def _rate_arguments(rate: float) -> list[str]:
    bounded = max(rate, 0.01)
    if bounded >= 1.0:
        return ["-rate-limit", str(max(1, int(bounded)))]
    duration_seconds = max(1, round(1.0 / bounded))
    return ["-rate-limit", "1", "-rate-limit-duration", f"{duration_seconds}s"]
