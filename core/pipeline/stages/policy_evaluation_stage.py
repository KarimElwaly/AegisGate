from typing import Any

from core.governance.conversation_risk import get_conversation_risk_tracker
from core.governance.taint_tracker import get_taint_tracker
from core.pipeline.stages.stage_context import PipelineStageContext
from core.policy_engine.yaml_engine import YamlPolicyEngine
from core.schemas.common import DecisionEnum, EffectiveModeEnum


class PolicyEvaluationStage:
    """Stage 6: Policy rules evaluation, rule mutations, session taints, and effective mode resolution."""

    def __init__(self, policy_engine: YamlPolicyEngine) -> None:
        self.policy_engine = policy_engine

    async def execute(self, ctx: PipelineStageContext) -> dict[str, Any]:
        req = ctx.request
        pack = ctx.policy_pack

        # Fetch active session taints & conversational risk if session_id is present
        taint_tracker = get_taint_tracker()
        risk_tracker = get_conversation_risk_tracker()
        session_taints: set[str] = set()
        cum_risk = 0.0
        high_risk_turns = 0
        total_turns = 0

        if req.session_id:
            try:
                session_taints = await taint_tracker.get_taints(req.tenant_id, req.session_id)
            except Exception:
                session_taints = set()
            try:
                risk_summary = await risk_tracker.get_session_risk(req.tenant_id, req.session_id)
                cum_risk = risk_summary.cumulative_risk_score
                high_risk_turns = risk_summary.high_risk_turns
                total_turns = risk_summary.total_turns
            except Exception:
                pass

        ctx.resolved_context["taints"] = list(session_taints)
        ctx.resolved_context["session"] = {
            "id": req.session_id,
            "taints": list(session_taints),
            "declared_scope": req.metadata.get("declared_scope") if req.metadata else None,
            "cumulative_risk_score": cum_risk,
            "high_risk_turns": high_risk_turns,
            "total_turns": total_turns,
        }

        rule_decision, risk_score, triggered_rules, rule_mutations = await self.policy_engine.evaluate(
            request=req,
            scanner_findings=ctx.scanner_findings,
            resolved_context=ctx.resolved_context,
            policy_pack=pack,
        )

        ctx.triggered_rules = triggered_rules
        ctx.risk_score = risk_score

        # Record turn risk into session sliding window
        if req.session_id:
            try:
                await risk_tracker.record_turn_risk(
                    tenant_id=req.tenant_id,
                    session_id=req.session_id,
                    turn_risk=ctx.risk_score,
                )
            except Exception:
                pass

        # Persist any newly added taints from matching rules
        if "add_taints" in rule_mutations and req.session_id:
            try:
                await taint_tracker.add_taints(
                    tenant_id=req.tenant_id,
                    session_id=req.session_id,
                    taints=rule_mutations["add_taints"],
                )
            except Exception:
                pass

        if "mutated_content" in rule_mutations:
            ctx.mutated_content_map.update(rule_mutations["mutated_content"])
        if "mutated_parameters" in rule_mutations:
            ctx.mutated_parameters_map.update(rule_mutations["mutated_parameters"])

        has_scanner_block = any(f.status == "block" for f in ctx.scanner_findings)
        if has_scanner_block and rule_decision == DecisionEnum.ALLOW:
            nominal_decision = DecisionEnum.DENY
            if ctx.risk_score < 0.8:
                ctx.risk_score = 0.9
        else:
            nominal_decision = rule_decision

        if (ctx.mutated_content_map or ctx.mutated_parameters_map) and nominal_decision == DecisionEnum.ALLOW:
            nominal_decision = DecisionEnum.MODIFY

        ctx.nominal_decision = nominal_decision

        if ctx.effective_mode == EffectiveModeEnum.SHADOW:
            ctx.effective_decision = DecisionEnum.ALLOW
            ctx.would_have_decided = nominal_decision
        else:
            ctx.effective_decision = nominal_decision
            ctx.would_have_decided = nominal_decision

        return rule_mutations

