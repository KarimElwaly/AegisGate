import time

from core.governance.budgets import BudgetManager
from core.governance.loop_detector import LoopDetector
from core.pipeline.stages.stage_context import PipelineStageContext
from core.schemas.common import DecisionEnum, EffectiveModeEnum, SeverityEnum
from core.schemas.verdicts import BudgetSnapshot, EvaluationVerdict, TriggeredRule


class BudgetCircuitStage:
    """Stage 3: Runaway loop detection and atomic Redis Lua budgets."""

    def __init__(
        self,
        loop_detector: LoopDetector,
        budget_manager: BudgetManager,
    ) -> None:
        self.loop_detector = loop_detector
        self.budget_manager = budget_manager

    async def execute(self, ctx: PipelineStageContext) -> EvaluationVerdict | None:
        req = ctx.request
        pack = ctx.policy_pack

        # 1. Runaway loop check for tool calls and agent handoffs
        if req.stage in ("tool_pre_call", "agent_handoff"):
            loop_cfg = pack.budgets.get("loop_detector", {}) if pack.budgets else {}
            loop_threshold = loop_cfg.get("threshold", 3)
            loop_window = loop_cfg.get("window_seconds", 60)
            is_loop, loop_count, _ = await self.loop_detector.record_and_check(
                tenant_id=req.tenant_id,
                session_id=req.session_id or "global",
                actor_id=req.actor.id,
                action_name=req.action.name if req.action else "default_action",
                parameters=req.action.parameters or {},
                threshold=loop_threshold,
                window_seconds=loop_window,
            )
            if is_loop:
                latency_ms = (time.perf_counter() - ctx.start_time) * 1000.0
                return EvaluationVerdict(
                    decision=DecisionEnum.DENY if ctx.effective_mode == EffectiveModeEnum.ENFORCE else DecisionEnum.ALLOW,
                    effective_mode=ctx.effective_mode,
                    would_have_decided=DecisionEnum.DENY,
                    risk_score=0.9,
                    triggered_rules=[
                        TriggeredRule(
                            rule_id="runaway-loop-circuit-breaker",
                            policy_pack=pack.id,
                            policy_version=pack.version,
                            severity=SeverityEnum.HIGH,
                            reason=f"Runaway loop detected: action '{req.action.name}' called {loop_count} times in {loop_window}s",
                            compliance_tags=["LOOP-PREVENTION", "RESOURCE-EXHAUSTION"],
                        )
                    ],
                    latency_ms=round(latency_ms, 2),
                )

        # 2. Atomic Redis token, cost & tool call budgets
        ctx.budget_snapshot = BudgetSnapshot()
        if pack.budgets:
            budget_limits = pack.budgets
            scope_type = "session" if req.session_id else "tenant"
            scope_id = req.session_id or req.tenant_id
            delta_tokens = req.action.estimated_tokens if req.action else 0
            delta_cost = req.action.estimated_cost_usd if req.action else 0.0
            delta_tool_calls = 1 if req.stage == "tool_pre_call" else 0

            is_ok, status_msg, snapshot = await self.budget_manager.check_and_consume(
                tenant_id=req.tenant_id,
                scope_type=scope_type,
                scope_id=scope_id,
                delta_tokens=delta_tokens,
                delta_cost_usd=delta_cost,
                delta_tool_calls=delta_tool_calls,
                max_tokens=budget_limits.get("max_tokens", 0),
                max_cost_usd=budget_limits.get("max_cost_usd", 0.0),
                max_tool_calls=budget_limits.get("max_tool_calls", 0),
                max_consecutive_failures=budget_limits.get("max_consecutive_failures", 0),
            )
            ctx.budget_snapshot = snapshot
            if not is_ok:
                latency_ms = (time.perf_counter() - ctx.start_time) * 1000.0
                return EvaluationVerdict(
                    decision=DecisionEnum.DENY if ctx.effective_mode == EffectiveModeEnum.ENFORCE else DecisionEnum.ALLOW,
                    effective_mode=ctx.effective_mode,
                    would_have_decided=DecisionEnum.DENY,
                    risk_score=0.8,
                    budget_snapshot=ctx.budget_snapshot,
                    triggered_rules=[
                        TriggeredRule(
                            rule_id="budget-quota-exceeded",
                            policy_pack=pack.id,
                            policy_version=pack.version,
                            severity=SeverityEnum.HIGH,
                            reason=f"Budget quota limit reached: {status_msg}",
                            compliance_tags=["BUDGET-ENFORCEMENT", "COST-CONTROL"],
                        )
                    ],
                    latency_ms=round(latency_ms, 2),
                )

        return None
