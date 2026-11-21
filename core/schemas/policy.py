from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from core.schemas.common import DecisionEnum, SeverityEnum


class ScannerConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str
    enabled: bool = True
    tier: int | None = None
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

    all: list["ConditionExpression"] | None = None
    any: list["ConditionExpression"] | None = None
    not_: Optional["ConditionExpression"] = Field(default=None, alias="not")

    # Direct clause checks:
    field: str | None = None  # e.g., "stage", "actor.role", "action.name", "scanner_findings.secrets_scanner.status", "resolved_context.asset_tier"
    operator: str | None = None  # eq, neq, in, not_in, contains, regex, gt, lt, gte, lte
    value: Any | None = None


class RuleAction(BaseModel):
    model_config = ConfigDict(extra="allow")

    decision: DecisionEnum | str = DecisionEnum.DENY
    severity: SeverityEnum | str = SeverityEnum.HIGH
    reason: str = "Policy violation triggered"
    compliance_tags: list[str] = Field(default_factory=list)
    mutated_content: Any | None = None
    mutated_parameters: dict[str, Any] | None = None
    approval_config: dict[str, Any] | None = None  # e.g. required_approvals: 2
    add_taints: list[str] = Field(default_factory=list)


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    id: str
    name: str | None = None
    priority: int = 100
    description: str | None = None
    stages: list[str] = Field(default_factory=list)
    condition: ConditionExpression | None = None
    action: RuleAction


class PolicyPackDefinition(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str
    name: str
    version: str = "1.0.0"
    extends: str | None = None
    execution_mode: str = "enforce"  # enforce | shadow
    description: str | None = None
    scanners: list[ScannerConfig] = Field(default_factory=list)
    resolvers: list[ResolverBinding] = Field(default_factory=list)
    budgets: dict[str, Any] = Field(default_factory=dict)
    rules: list[PolicyRule] = Field(default_factory=list)

