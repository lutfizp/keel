import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from keel.adapters import httpx_probe, nuclei_scan, process
from keel.adapters.base import CommandResult
from keel.errors import OperationCancelled


def test_nuclei_uses_conservative_flags_and_fractional_rate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, object] = {}

    def fake_run(argv: list[str], timeout: int) -> CommandResult:
        captured.update(argv=argv, timeout=timeout)
        return CommandResult(argv, 0, "", "", False)

    monkeypatch.setattr(nuclei_scan, "run_cli", fake_run)

    nuclei_scan.template_scan(
        "https://app.example.com",
        0.5,
        "high",
        timeout=60,
        max_response_bytes=4096,
        template_id="safe-template",
        project_path=tmp_path / "project",
    )
    argv = captured["argv"]

    assert "-disable-unsigned-templates" in argv
    assert "-no-interactsh" in argv
    assert "-config" in argv
    assert "-auth=false" in argv
    assert argv[argv.index("-c") + 1] == "1"
    assert argv[argv.index("-rate-limit-duration") + 1] == "2s"
    assert argv[argv.index("-template-id") + 1] == "safe-template"


def test_httpx_disables_retries_and_caps_response(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_run(argv: list[str], timeout: int) -> CommandResult:
        captured.update(argv=argv, timeout=timeout)
        return CommandResult(argv, 0, "", "", False)

    monkeypatch.setattr(httpx_probe, "run_cli", fake_run)
    httpx_probe.probe_alive("https://app.example.com", 2, max_response_bytes=8192)
    argv = captured["argv"]

    assert argv[argv.index("-threads") + 1] == "1"
    assert argv[argv.index("-retries") + 1] == "0"
    assert argv[argv.index("-response-size-to-read") + 1] == "8192"
    assert "-config" in argv
    assert "-auth=false" in argv


def test_process_parses_retry_after_without_any_429_substring_false_positive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(process.shutil, "which", lambda binary: f"/bin/{binary}")
    monkeypatch.setattr(
        process.subprocess,
        "run",
        lambda *_, **__: SimpleNamespace(
            returncode=0,
            stdout='{"status_code":429}\nRetry-After: 45',
            stderr="",
        ),
    )

    result = process.run_cli(["custom-scanner"])

    assert result.throttled is True
    assert result.retry_after_seconds == 45


def test_scanner_process_does_not_inherit_proxy_or_cloud_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid")
    monkeypatch.setenv("PDCP_API_KEY", "cloud-secret")
    monkeypatch.setenv("KEEL_TEST_SENTINEL", "kept")
    monkeypatch.setattr(process.shutil, "which", lambda binary: f"/bin/{binary}")

    def fake_run(*_: object, **kwargs: object) -> SimpleNamespace:
        captured.update(kwargs)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(process.subprocess, "run", fake_run)

    process.run_cli(["custom-scanner"])

    environment = captured["env"]
    assert "HTTPS_PROXY" not in environment
    assert "PDCP_API_KEY" not in environment
    assert environment["KEEL_TEST_SENTINEL"] == "kept"


def test_managed_process_honors_cancellation() -> None:
    cancelled = threading.Event()
    cancelled.set()

    with pytest.raises(OperationCancelled, match="cancelled"):
        process.run_cli(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            timeout=5,
            cancel_event=cancelled,
            progress_callback=lambda *_: None,
        )
