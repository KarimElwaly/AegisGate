import asyncio

from core.config import get_settings
from core.logger import get_logger
from core.pipeline.stages.stage_context import PipelineStageContext
from core.policy_engine.yaml_engine import YamlPolicyEngine
from core.schemas.common import EffectiveModeEnum
from core.schemas.events import EvaluationRequest
from core.schemas.verdicts import EvaluationVerdict

logger = get_logger("core.pipeline.stages.audit_shadow")


class AuditShadowStage:
    """Stage 8: Prometheus telemetry, cryptographic audit ledger dispatch, and shadow deltas."""

    def __init__(self, policy_engine: YamlPolicyEngine) -> None:
        self.policy_engine = policy_engine

    async def execute(self, ctx: PipelineStageContext, verdict: EvaluationVerdict) -> None:
        req = ctx.request
        pack = ctx.policy_pack

        # 1. Record Prometheus Telemetry
        try:
            from core.telemetry import record_evaluation_metric
            cur_stage = req.stage.value if hasattr(req.stage, "value") else str(req.stage)
            cur_dec = (
                ctx.effective_decision.value
                if hasattr(ctx.effective_decision, "value")
                else str(ctx.effective_decision)
            )
            record_evaluation_metric(
                tenant_id=req.tenant_id,
                stage=cur_stage,
                decision=cur_dec,
                latency_seconds=verdict.latency_ms / 1000.0,
            )
        except Exception:
            pass

        # 2. Cryptographic Audit Ledger Recording
        if getattr(req, "record_audit", True):
            try:
                from core.audit.ledger import AuditLedger
                ledger = AuditLedger()
                pack_name = getattr(pack, "id", getattr(pack, "name", "default")) if pack else "default"
                pack_ver = getattr(pack, "version", "1.0.0") if pack else "1.0.0"
                eff_mode_str = ctx.effective_mode.value if hasattr(ctx.effective_mode, "value") else str(ctx.effective_mode)
                would_dec_str = ctx.would_have_decided.value if hasattr(ctx.would_have_decided, "value") else str(ctx.would_have_decided)

                if getattr(req, "record_audit_sync", False) or get_settings().AEGIS_ENV == "test":
                    await ledger.record_event(
                        request=req,
                        verdict=verdict,
                        policy_pack_id=pack_name,
                        policy_pack_version=pack_ver,
                        effective_mode=eff_mode_str,
                        would_have_decided=would_dec_str,
                    )
                else:
                    asyncio.create_task(
                        ledger.record_event(
                            request=req,
                            verdict=verdict,
                            policy_pack_id=pack_name,
                            policy_pack_version=pack_ver,
                            effective_mode=eff_mode_str,
                            would_have_decided=would_dec_str,
                        )
                    )
            except Exception as e:
                logger.warning("audit_recording_failed", error=str(e))

        # 3. Live Shadow Mode Evaluation
        shadow_pack_id = getattr(req, "shadow_policy_pack_id", None)
        if shadow_pack_id:
            asyncio.create_task(
                self.evaluate_shadow(req, verdict, shadow_pack_id)
            )

    async def evaluate_shadow(
        self,
        request: EvaluationRequest,
        active_verdict: EvaluationVerdict,
        shadow_pack_id: str,
    ) -> None:
        """Asynchronously evaluates candidate shadow policy pack and records deltas."""
        try:
            shadow_pack = self.policy_engine.get_registered_pack(shadow_pack_id)
            if not shadow_pack:
                return

            shadow_decision, risk, triggered, _ = await self.policy_engine.evaluate(
                request=request,
                scanner_findings=active_verdict.scanner_findings,
                resolved_context=active_verdict.resolved_context or {},
                policy_pack=shadow_pack,
            )
            shadow_verdict = EvaluationVerdict(
                decision=shadow_decision,
                effective_mode=EffectiveModeEnum.SHADOW,
                risk_score=risk,
                triggered_rules=triggered,
                scanner_findings=active_verdict.scanner_findings,
                resolved_context=active_verdict.resolved_context,
                latency_ms=0.0,
            )

            active_dec = (
                active_verdict.decision.value
                if hasattr(active_verdict.decision, "value")
                else str(active_verdict.decision)
            )
            shadow_dec = (
                shadow_decision.value
                if hasattr(shadow_decision, "value")
                else str(shadow_decision)
            )

            if active_dec != shadow_dec:
                from core.simulator.shadow import get_shadow_delta_manager
                mgr = get_shadow_delta_manager()
                await mgr.record_delta(
                    tenant_id=request.tenant_id,
                    workspace_id=request.workspace_id,
                    trace_id=request.trace_id,
                    active_pack_id=request.policy_pack_id,
                    active_version="active",
                    shadow_pack_id=shadow_pack_id,
                    shadow_version=getattr(shadow_pack, "version", "1.0.0"),
                    active_verdict=active_verdict,
                    shadow_verdict=shadow_verdict,
                    request_summary={
                        "stage": request.stage.value if hasattr(request.stage, "value") else str(request.stage),
                        "action": request.action.name if hasattr(request.action, "name") else str(request.action),
                    },
                )
        except Exception as e:
            logger.warning("shadow_evaluation_failed", error=str(e))

