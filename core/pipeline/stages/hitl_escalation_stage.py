from typing import Any

from core.logger import get_logger
from core.pipeline.stages.stage_context import PipelineStageContext
from core.schemas.common import DecisionEnum
from core.schemas.verdicts import ApprovalTicketInfo, EvaluationVerdict

logger = get_logger("core.pipeline.stages.hitl_escalation")


class HITLEscalationStage:
    """Stage 7: Human-in-the-Loop ticket provisioning on SUSPEND_FOR_APPROVAL."""

    async def execute(self, ctx: PipelineStageContext, rule_mutations: dict[str, Any]) -> None:
        if ctx.nominal_decision != DecisionEnum.SUSPEND_FOR_APPROVAL:
            return

        req = ctx.request
        pack = ctx.policy_pack
        approval_cfg = rule_mutations.get("approval_config", {})

        try:
            from core.hitl.engine import get_hitl_engine
            hitl_eng = get_hitl_engine()
            pack_name = getattr(pack, "id", getattr(pack, "name", "default")) if pack else "default"

            created_ticket = await hitl_eng.create_ticket(
                request=req,
                verdict=EvaluationVerdict(
                    decision=ctx.effective_decision,
                    effective_mode=ctx.effective_mode,
                    would_have_decided=ctx.would_have_decided,
                    risk_score=ctx.risk_score,
                    triggered_rules=ctx.triggered_rules,
                    scanner_findings=ctx.scanner_findings,
                    resolved_context=ctx.resolved_context,
                    latency_ms=0.0,
                ),
                policy_pack_id=pack_name,
                required_approvals=approval_cfg.get("required_approvals", 1),
                required_approver_roles=approval_cfg.get("required_approver_roles"),
                ttl_seconds=approval_cfg.get("ttl_seconds", 300),
                callback_url=approval_cfg.get("callback_url"),
                callback_secret=approval_cfg.get("callback_secret"),
            )
            ctx.approval_ticket = ApprovalTicketInfo(
                ticket_id=created_ticket.ticket_id,
                status=created_ticket.status,
                required_approvals=created_ticket.required_approvals,
                expires_at=created_ticket.expires_at,
            )
        except Exception as e:
            logger.warning("hitl_ticket_creation_failed", error=str(e))
            ctx.approval_ticket = ApprovalTicketInfo(
                ticket_id=None,
                status="pending",
                required_approvals=approval_cfg.get("required_approvals", 1),
            )

