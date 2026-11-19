from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field
from core.schemas.common import DecisionEnum, SeverityEnum


class ScannerConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str
    enabled: bool = True
    tier: Optional[int] = None
    timeout_ms: int = 500
    on_timeout: str = "flag"  # allow | deny | flag
    config: dict[str, Any] = Field(default_factory=dict)


class ResolverBinding(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str
    enabled: bool = True
    timeout_ms: int = 500
    cache_ttl_seconds: int = 300
    config: dict[str, Any] = Field(default_factory=dict)


class ConditionExpression(BaseModel):
    model_config = ConfigDict(extra="allow")

    all: Optional[list["ConditionExpression"]] = None
    any: Optional[list["ConditionExpression"]] = None
    not_: Optional["ConditionExpression"] = Field(default=None, alias="not")

    # Direct clause checks:
    field: Optional[str] = None  # e.g., "stage", "actor.role", "action.name", "scanner_findings.secrets_scanner.status", "resolved_context.asset_tier"
    operator: Optional[str] = None  # eq, neq, in, not_in, contains, regex, gt, lt, gte, lte
    value: Optional[Any] = None


class RuleAction(BaseModel):
    model_config = ConfigDict(extra="allow")

    decision: DecisionEnum | str = DecisionEnum.DENY
    severity: SeverityEnum | str = SeverityEnum.HIGH
    reason: str = "Policy violation triggered"
    compliance_tags: list[str] = Field(default_factory=list)
    mutated_content: Optional[Any] = None
    mutated_parameters: Optional[dict[str, Any]] = None
    approval_config: Optional[dict[str, Any]] = None  # e.g. required_approvals: 2


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    id: str
    name: Optional[str] = None
    priority: int = 100
    description: Optional[str] = None
    stages: list[str] = Field(default_factory=list)
    condition: Optional[ConditionExpression] = None
    action: RuleAction


class PolicyPackDefinition(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str
    name: str
    version: str = "1.0.0"
    extends: Optional[str] = None
    execution_mode: str = "enforce"  # enforce | shadow
    description: Optional[str] = None
    scanners: list[ScannerConfig] = Field(default_factory=list)
    resolvers: list[ResolverBinding] = Field(default_factory=list)
    budgets: dict[str, Any] = Field(default_factory=dict)
    rules: list[PolicyRule] = Field(default_factory=list)
