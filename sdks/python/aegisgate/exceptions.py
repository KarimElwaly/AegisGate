class AegisGateError(Exception):
    """Base exception for all AegisGate client errors."""


class PolicyViolationError(AegisGateError):
    def __init__(self, message: str, verdict=None):
        super().__init__(message)
        self.verdict = verdict


class KillSwitchActiveError(PolicyViolationError):
    pass


class BudgetExceededError(PolicyViolationError):
    pass

