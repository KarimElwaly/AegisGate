import time
from typing import Any

from core.governance.budgets import get_budget_manager
from core.governance.delegation import get_delegation_validator
from core.governance.kill_switch import get_kill_switch_service
from core.governance.loop_detector import get_loop_detector
from core.logger import get_logger
from core.pipeline.stages import (
    AuditShadowStage,
    BudgetCircuitStage,
    ContextResolutionStage,
    HITLEscalationStage,
    IdentityDelegationStage,
    KillSwitchStage,
    PipelineStageContext,
    PolicyEvaluationStage,
    TieredScannerStage,
)
from core.policy_engine.yaml_engine import get_yaml_policy_engine
from core.registry.interfaces import BaseScanner, ScannerResult
from core.registry.registry import PluginRegistry, get_plugin_registry
from core.schemas.common import EffectiveModeEnum
from core.schemas.events import EvaluationRequest
from core.schemas.policy import PolicyPackDefinition
from core.schemas.verdicts import EvaluationVerdict

logger = get_logger("core.pipeline")


class PipelineOrchestrator:
    """Tiered Pipeline Orchestrator.
    Decomposed into composable stages under core/pipeline/stages/ while maintaining
    sub-millisecond fast paths, zero domain assumptions, and full backward compatibility.
    """

    def __init__(
        self,
        plugin_registry: PluginRegistry | None = None,
        policy_engine=None,
    ) -> None:
        self.registry = plugin_registry or get_plugin_registry()
        self.policy_engine = policy_engine or get_yaml_policy_engine()
        self.kill_switch = get_kill_switch_service()
        self.budget_manager = get_budget_manager()
        self.loop_detector = get_loop_detector()
        self.delegation_validator = get_delegation_validator()

        # Composable stages
        self.stage_kill_switch = KillSwitchStage(self.kill_switch)
        self.stage_delegation = IdentityDelegationStage(self.delegation_validator)
        self.stage_budget = BudgetCircuitStage(self.loop_detector, self.budget_manager)
        self.stage_context = ContextResolutionStage(self.registry)
        self.stage_scanner = TieredScannerStage(self.registry)
        self.stage_policy = PolicyEvaluationStage(self.policy_engine)
        self.stage_hitl = HITLEscalationStage()
        self.stage_audit = AuditShadowStage(self.policy_engine)

    def _get_typed_config(
        self, scanner: BaseScanner, raw_config: dict[str, Any], pack_id: str, pack_version: str
    ) -> Any:
        """Backward-compatible helper delegated to TieredScannerStage."""
        return self.stage_scanner.get_typed_config(scanner, raw_config, pack_id, pack_version)

    async def _execute_scanner(
        self,
        scanner: BaseScanner,
        request: EvaluationRequest,
        context: dict[str, Any],
        typed_config: Any,
        timeout_ms: int,
        on_timeout: str,
    ) -> ScannerResult:
        """Backward-compatible helper delegated to TieredScannerStage."""
        return await self.stage_scanner.execute_scanner(
            scanner, request, context, typed_config, timeout_ms, on_timeout
        )

    async def _evaluate_shadow(
        self,
        request: EvaluationRequest,
        active_verdict: EvaluationVerdict,
        shadow_pack_id: str,
    ) -> None:
        """Backward-compatible helper delegated to AuditShadowStage."""
        await self.stage_audit.evaluate_shadow(request, active_verdict, shadow_pack_id)

    async def evaluate(self, request: EvaluationRequest) -> EvaluationVerdict:
        start_time = time.perf_counter()

        # -------------------------------------------------------------
        # 1. SUB-MILLISECOND KILL SWITCH CHECK (CHECKED FIRST)
        # -------------------------------------------------------------
        early_kill = await self.stage_kill_switch.execute(request, start_time)
        if early_kill is not None:
            return early_kill

        # -------------------------------------------------------------
        # 2. RESOLVE POLICY PACK & EFFECTIVE MODE
        # -------------------------------------------------------------
        policy_pack = self.policy_engine.get_policy_pack(request.policy_pack_id)
        if not policy_pack:
            policy_pack = PolicyPackDefinition(
                id=request.policy_pack_id or "default",
                name="Default Dynamic Pack",
                version="1.0.0",
                execution_mode="enforce",
            )

        if request.execution_mode_override:
            effective_mode = EffectiveModeEnum(request.execution_mode_override)
        elif policy_pack.execution_mode == "shadow":
            effective_mode = EffectiveModeEnum.SHADOW
        else:
            effective_mode = EffectiveModeEnum.ENFORCE

        # Initialize shared stage context
        ctx = PipelineStageContext(
            request=request,
            start_time=start_time,
            policy_pack=policy_pack,
            effective_mode=effective_mode,
        )

        # -------------------------------------------------------------
        # 3. DELEGATION CHAIN & PRIVILEGE ESCALATION CHECK
        # -------------------------------------------------------------
        early_delegation = await self.stage_delegation.execute(ctx)
        if early_delegation is not None:
            return early_delegation

        # -------------------------------------------------------------
        # 4. RUNAWAY LOOP & ATOMIC BUDGET CHECKS
        # -------------------------------------------------------------
        early_budget = await self.stage_budget.execute(ctx)
        if early_budget is not None:
            return early_budget

        # -------------------------------------------------------------
        # 5. CONTEXT RESOLVERS ENRICHMENT
        # -------------------------------------------------------------
        await self.stage_context.execute(ctx)

        # -------------------------------------------------------------
        # 6. TIERED SCANNERS EXECUTION
        # -------------------------------------------------------------
        await self.stage_scanner.execute(ctx)

        # -------------------------------------------------------------
        # 7. POLICY RULES EVALUATION
        # -------------------------------------------------------------
        rule_mutations = await self.stage_policy.execute(ctx)

        # -------------------------------------------------------------
        # 8. HITL ESCALATION
        # -------------------------------------------------------------
        await self.stage_hitl.execute(ctx, rule_mutations)

        latency_ms = (time.perf_counter() - start_time) * 1000.0

        verdict = EvaluationVerdict(
            decision=ctx.effective_decision,
            effective_mode=ctx.effective_mode,
            would_have_decided=ctx.would_have_decided,
            risk_score=ctx.risk_score,
            mutated_content=ctx.mutated_content_map if ctx.mutated_content_map else None,
            mutated_parameters=ctx.mutated_parameters_map if ctx.mutated_parameters_map else None,
            redaction_map_ref=request.session_id if ctx.redaction_map else None,
            triggered_rules=ctx.triggered_rules,
            scanner_findings=ctx.scanner_findings,
            resolved_context=ctx.resolved_context,
            budget_snapshot=ctx.budget_snapshot,
            approval_ticket=ctx.approval_ticket,
            latency_ms=round(latency_ms, 2),
        )

        # -------------------------------------------------------------
        # 9. TELEMETRY, AUDIT LEDGER & SHADOW DELTAS
        # -------------------------------------------------------------
        await self.stage_audit.execute(ctx, verdict)

        return verdict


default_orchestrator = PipelineOrchestrator()


def get_pipeline_orchestrator() -> PipelineOrchestrator:
    return default_orchestrator
