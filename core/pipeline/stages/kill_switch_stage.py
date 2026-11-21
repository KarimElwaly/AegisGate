import time

from core.governance.kill_switch import KillSwitchService
from core.schemas.common import DecisionEnum, EffectiveModeEnum, SeverityEnum
from core.schemas.events import EvaluationRequest
from core.schemas.verdicts import EvaluationVerdict, TriggeredRule


class KillSwitchStage:
    """Stage 1: Sub-millisecond emergency circuit breaker check."""

    def __init__(self, kill_switch_service: KillSwitchService) -> None:
        self.kill_switch = kill_switch_service

    async def execute(
        self, request: EvaluationRequest, start_time: float
    ) -> EvaluationVerdict | None:
        is_killed, kill_scope, kill_reason = await self.kill_switch.check_kill_switches(
            tenant_id=request.tenant_id,
            workspace_id=request.workspace_id,
            agent_id=request.actor.id,
            tool_name=request.action.name if request.action else None,
        )
        if not is_killed:
            return None

        latency_ms = (time.perf_counter() - start_time) * 1000.0
        return EvaluationVerdict(
            decision=DecisionEnum.DENY,
            effective_mode=EffectiveModeEnum.ENFORCE,
            would_have_decided=DecisionEnum.DENY,
            risk_score=1.0,
            triggered_rules=[
                TriggeredRule(
                    rule_id="kill-switch-engaged",
                    policy_pack="governance-kill-switch",
                    policy_version="1.0.0",
                    severity=SeverityEnum.CRITICAL,
                    reason=f"Emergency Kill Switch active on scope '{kill_scope}': {kill_reason}",
                    compliance_tags=["CIRCUIT-BREAKER", "EMERGENCY-HALT"],
                )
            ],
            latency_ms=round(latency_ms, 2),
        )
