import pytest
from core.pipeline.orchestrator import PipelineOrchestrator
from core.schemas.common import DecisionEnum, EffectiveModeEnum
from core.schemas.events import ActionModel, ActorModel, ContentModel, EvaluationRequest


@pytest.mark.asyncio
async def test_orchestrator_clean_request():
    orchestrator = PipelineOrchestrator()
    req = EvaluationRequest(
        tenant_id="test-tenant",
        policy_pack_id="base-enterprise",
        content=ContentModel(trusted_instructions="Summarize today's system error counts"),
    )
    verdict = await orchestrator.evaluate(req)

    assert verdict.decision == DecisionEnum.ALLOW
    assert verdict.effective_mode == EffectiveModeEnum.ENFORCE
    assert verdict.latency_ms > 0
    assert len(verdict.scanner_findings) > 0


@pytest.mark.asyncio
async def test_orchestrator_blocks_secret_in_prompt():
    orchestrator = PipelineOrchestrator()
    req = EvaluationRequest(
        tenant_id="test-tenant",
        policy_pack_id="base-enterprise",
        content=ContentModel(trusted_instructions="Use AWS key AKIAIOSFODNN7EXAMPLE to fetch bucket"),
    )
    verdict = await orchestrator.evaluate(req)

    assert verdict.decision == DecisionEnum.DENY
    assert verdict.risk_score >= 0.8
    assert any(f.scanner_name == "secrets_scanner" and f.status == "block" for f in verdict.scanner_findings)
    assert any(r.rule_id == "base-block-critical-secrets" for r in verdict.triggered_rules)


@pytest.mark.asyncio
async def test_orchestrator_shadow_mode():
    orchestrator = PipelineOrchestrator()
    req = EvaluationRequest(
        tenant_id="test-tenant",
        policy_pack_id="base-enterprise",
        execution_mode_override="shadow",
        content=ContentModel(trusted_instructions="Use AWS key AKIAIOSFODNN7EXAMPLE to fetch bucket"),
    )
    verdict = await orchestrator.evaluate(req)

    # In shadow mode, decision is ALLOW, but would_have_decided is DENY!
    assert verdict.decision == DecisionEnum.ALLOW
    assert verdict.effective_mode == EffectiveModeEnum.SHADOW
    assert verdict.would_have_decided == DecisionEnum.DENY
    assert len(verdict.triggered_rules) > 0
