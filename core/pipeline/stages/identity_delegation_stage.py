import time

from core.governance.delegation import DelegationPolicyConfig, DelegationValidator
from core.pipeline.stages.stage_context import PipelineStageContext
from core.schemas.common import DecisionEnum, EffectiveModeEnum, SeverityEnum
from core.schemas.verdicts import EvaluationVerdict, TriggeredRule


class IdentityDelegationStage:
    """Stage 2: Delegation depth and privilege escalation boundary check."""

    def __init__(self, delegation_validator: DelegationValidator) -> None:
        self.validator = delegation_validator

    async def execute(self, ctx: PipelineStageContext) -> EvaluationVerdict | None:
        req = ctx.request
        pack = ctx.policy_pack
        delegation_cfg_dict = pack.budgets.get("delegation", {}) if pack.budgets else {}
        delegation_cfg = DelegationPolicyConfig(**delegation_cfg_dict)

        is_valid, reason = self.validator.validate_delegation(
            actor=req.actor,
            action_name=req.action.name if req.action else "default_action",
            config=delegation_cfg,
        )
        if is_valid:
            return None

        latency_ms = (time.perf_counter() - ctx.start_time) * 1000.0
        return EvaluationVerdict(
            decision=DecisionEnum.DENY if ctx.effective_mode == EffectiveModeEnum.ENFORCE else DecisionEnum.ALLOW,
            effective_mode=ctx.effective_mode,
            would_have_decided=DecisionEnum.DENY,
            risk_score=0.9,
            triggered_rules=[
                TriggeredRule(
                    rule_id="delegation-privilege-escalation",
                    policy_pack=pack.id,
                    policy_version=pack.version,
                    severity=SeverityEnum.HIGH,
                    reason=reason or "Delegation validation failed",
                    compliance_tags=["RBAC", "PRIVILEGE-ESCALATION"],
                )
            ],
            latency_ms=round(latency_ms, 2),
        )

