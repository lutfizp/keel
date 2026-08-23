from keel.adapters.base import CommandResult
from keel.adapters.process import isolated_scanner_config, run_cli


def probe_alive(
    target: str,
    rate: float,
    timeout: int = 90,
    max_response_bytes: int = 1_048_576,
) -> CommandResult:
    delay = max(int(1 / max(rate, 0.01) * 1000), 50)
    with isolated_scanner_config() as config_path:
        return run_cli(
            [
                "httpx",
                "-u",
                target,
                "-json",
                "-silent",
                "-timeout",
                "10",
                "-threads",
                "1",
                "-retries",
                "0",
                "-rate-limit",
                str(max(int(rate), 1)),
                "-delay",
                f"{delay}ms",
                "-response-size-to-read",
                str(max_response_bytes),
                "-response-size-to-save",
                str(max_response_bytes),
                "-config",
                str(config_path),
                "-auth=false",
                "-no-color",
            ],
            timeout=timeout,
        )
