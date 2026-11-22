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


class ApprovalRequiredError(PolicyViolationError):
    def __init__(self, message: str, ticket_id: str | None = None, verdict=None):
        super().__init__(message, verdict=verdict)
        self.ticket_id = ticket_id

