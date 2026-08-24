from __future__ import annotations


class KeelError(Exception):
    pass


class PolicyDenied(KeelError):
    pass


class WaveBusy(PolicyDenied):
    pass


class UnknownEngagement(KeelError):
    pass


class UnknownCard(KeelError):
    pass


class AdapterFailed(KeelError):
    pass


class OperationCancelled(KeelError):
    pass


class ProofDenied(KeelError):
    pass


class ProofFailed(KeelError):
    pass


class TargetThrottled(KeelError):
    def __init__(self, host: str, retry_after_seconds: float | None = None) -> None:
        self.host = host
        self.retry_after_seconds = retry_after_seconds
        detail = (
            f"; retry after {retry_after_seconds:.1f}s"
            if retry_after_seconds is not None
            else ""
        )
        super().__init__(f"target {host} throttled the request{detail}")
