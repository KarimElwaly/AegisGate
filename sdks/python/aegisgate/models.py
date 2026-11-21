import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class DecisionEnum(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    MODIFY = "MODIFY"
    SUSPEND_FOR_APPROVAL = "SUSPEND_FOR_APPROVAL"


class StageEnum(str, Enum):
    LLM_INPUT = "llm_input"
    LLM_OUTPUT = "llm_output"
    TOOL_PRE_CALL = "tool_pre_call"
    TOOL_POST_CALL = "tool_post_call"
    AGENT_HANDOFF = "agent_handoff"


class ActorModel(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str = "default_agent"
    role: str = "agent"
    delegation_depth: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


class ActionModel(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str
    target: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    estimated_tokens: int = 0
    estimated_cost_usd: float = 0.0


class ContentModel(BaseModel):
    model_config = ConfigDict(extra="allow")

    trusted_instructions: str | None = None
    untrusted_data: Any | None = None
    streaming: bool = False
    attachments: list[dict[str, Any]] = Field(default_factory=list)


class EvaluationRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    trace_id: str = Field(default_factory=lambda: f"tr-{uuid.uuid4()}")
    session_id: str | None = None
    tenant_id: str = "default"
    workspace_id: str = "default"
    policy_pack_id: str = "base-enterprise"
    stage: StageEnum = StageEnum.TOOL_PRE_CALL
    actor: ActorModel = Field(default_factory=ActorModel)
    action: ActionModel = Field(default_factory=lambda: ActionModel(name="default"))
    content: ContentModel = Field(default_factory=ContentModel)
    execution_mode_override: str | None = None


class TriggeredRule(BaseModel):
    model_config = ConfigDict(extra="allow")

    rule_id: str
    policy_pack: str = "base-enterprise"
    policy_version: str = "1.0.0"
    severity: str = "medium"
    reason: str = ""
    compliance_tags: list[str] = Field(default_factory=list)


class ScannerFinding(BaseModel):
    model_config = ConfigDict(extra="allow")

    scanner_name: str
    tier: int = 1
    status: str = "pass"
    score: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)
    message: str | None = None


class BudgetSnapshot(BaseModel):
    model_config = ConfigDict(extra="allow")

    tokens_remaining: int | None = None
    cost_remaining_usd: float | None = None
    tool_calls_remaining: int | None = None


class ApprovalTicketInfo(BaseModel):
    model_config = ConfigDict(extra="allow")

    ticket_id: str | None = None
    status: str = "pending"
    required_approvals: int = 1
    expires_at: str | None = None


class EvaluationVerdict(BaseModel):
    model_config = ConfigDict(extra="allow")

    decision: DecisionEnum = DecisionEnum.ALLOW
    effective_mode: str = "enforce"
    would_have_decided: DecisionEnum = DecisionEnum.ALLOW
    risk_score: float = 0.0
    mutated_content: dict[str, Any] | None = None
    mutated_parameters: dict[str, Any] | None = None
    triggered_rules: list[TriggeredRule] = Field(default_factory=list)
    scanner_findings: list[ScannerFinding] = Field(default_factory=list)
    resolved_context: dict[str, Any] = Field(default_factory=dict)
    budget_snapshot: BudgetSnapshot = Field(default_factory=BudgetSnapshot)
    approval_ticket: ApprovalTicketInfo | None = None
    latency_ms: float = 0.0

