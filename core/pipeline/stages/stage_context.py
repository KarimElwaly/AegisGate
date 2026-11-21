from dataclasses import dataclass, field
from typing import Any

from core.schemas.common import DecisionEnum, EffectiveModeEnum
from core.schemas.events import EvaluationRequest
from core.schemas.policy import PolicyPackDefinition
from core.schemas.verdicts import (
    ApprovalTicketInfo,
    BudgetSnapshot,
    ScannerFinding,
    TriggeredRule,
)


@dataclass
class PipelineStageContext:
    """Carries mutable evaluation context across decoupled pipeline stages."""

    request: EvaluationRequest
    start_time: float
    policy_pack: PolicyPackDefinition
    effective_mode: EffectiveModeEnum
    resolved_context: dict[str, Any] = field(default_factory=dict)
    scanner_findings: list[ScannerFinding] = field(default_factory=list)
    mutated_content_map: dict[str, Any] = field(default_factory=dict)
    mutated_parameters_map: dict[str, Any] = field(default_factory=dict)
    redaction_map: dict[str, str] = field(default_factory=dict)
    triggered_rules: list[TriggeredRule] = field(default_factory=list)
    budget_snapshot: BudgetSnapshot = field(default_factory=BudgetSnapshot)
    approval_ticket: ApprovalTicketInfo | None = None
    nominal_decision: DecisionEnum = DecisionEnum.ALLOW
    would_have_decided: DecisionEnum = DecisionEnum.ALLOW
    effective_decision: DecisionEnum = DecisionEnum.ALLOW
    risk_score: float = 0.0
    short_circuit: bool = False
    stage_latencies_ms: dict[str, float] = field(default_factory=dict)

