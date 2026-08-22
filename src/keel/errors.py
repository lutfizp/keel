class KeelError(Exception):
    pass


class PolicyDenied(KeelError):
    pass


class UnknownEngagement(KeelError):
    pass


class UnknownCard(KeelError):
    pass


class AdapterFailed(KeelError):
    pass


class ProofDenied(KeelError):
    pass
