import uuid
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field
from core.schemas.common import DecisionEnum, EffectiveModeEnum, SeverityEnum


class TriggeredRule(BaseModel):
    model_config = ConfigDict(extra="allow")

    rule_id: str
    policy_pack: str
    policy_version: str
    severity: SeverityEnum | str = SeverityEnum.MEDIUM
    reason: str
    compliance_tags: list[str] = Field(default_factory=list)


class ScannerFinding(BaseModel):
    model_config = ConfigDict(extra="allow")

    scanner_name: str
    tier: int
    status: str  # pass | flag | block | error
    score: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)
    message: Optional[str] = None


class BudgetSnapshot(BaseModel):
    model_config = ConfigDict(extra="allow")

    tokens_used: int = 0
    tokens_limit: int = 0
    cost_used_usd: float = 0.0
    cost_limit_usd: float = 0.0
    tool_calls_used: int = 0
    tool_calls_limit: int = 0


class ApprovalTicketInfo(BaseModel):
    model_config = ConfigDict(extra="allow")

    ticket_id: Optional[str] = None
    status: Optional[str] = None  # pending | approved | rejected | expired
    required_approvals: int = 1
    expires_at: Optional[str] = None


class EvaluationVerdict(BaseModel):
    model_config = ConfigDict(extra="allow")

    verdict_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    decision: DecisionEnum | str = DecisionEnum.ALLOW
    effective_mode: EffectiveModeEnum | str = EffectiveModeEnum.ENFORCE
    would_have_decided: DecisionEnum | str = DecisionEnum.ALLOW
    risk_score: float = 0.0
    mutated_content: Optional[Any] = None
    mutated_parameters: Optional[dict[str, Any]] = None
    redaction_map_ref: Optional[str] = None
    triggered_rules: list[TriggeredRule] = Field(default_factory=list)
    scanner_findings: list[ScannerFinding] = Field(default_factory=list)
    resolved_context: dict[str, Any] = Field(default_factory=dict)
    budget_snapshot: Optional[BudgetSnapshot] = None
    approval_ticket: Optional[ApprovalTicketInfo] = None
    latency_ms: float = 0.0
