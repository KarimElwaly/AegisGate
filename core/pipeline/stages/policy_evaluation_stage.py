from typing import Any

from core.pipeline.stages.stage_context import PipelineStageContext
from core.policy_engine.yaml_engine import YamlPolicyEngine
from core.schemas.common import DecisionEnum, EffectiveModeEnum


class PolicyEvaluationStage:
    """Stage 6: Policy rules evaluation, rule mutations, and effective mode resolution."""

    def __init__(self, policy_engine: YamlPolicyEngine) -> None:
        self.policy_engine = policy_engine

    async def execute(self, ctx: PipelineStageContext) -> dict[str, Any]:
        req = ctx.request
        pack = ctx.policy_pack

        rule_decision, risk_score, triggered_rules, rule_mutations = await self.policy_engine.evaluate(
            request=req,
            scanner_findings=ctx.scanner_findings,
            resolved_context=ctx.resolved_context,
            policy_pack=pack,
        )

        ctx.triggered_rules = triggered_rules
        ctx.risk_score = risk_score

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
