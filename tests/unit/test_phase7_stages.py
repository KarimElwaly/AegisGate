import time
import pytest

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
from core.schemas.common import DecisionEnum, EffectiveModeEnum, StageEnum
from core.schemas.events import ActionModel, ActorModel, ContentModel, EvaluationRequest
from core.schemas.policy import PolicyPackDefinition


@pytest.mark.asyncio
async def test_kill_switch_stage(mocker):
    mock_ks = mocker.AsyncMock()
    mock_ks.check_kill_switches.return_value = (True, "agent", "Compromised agent")
    stage = KillSwitchStage(mock_ks)

    req = EvaluationRequest(
        tenant_id="test-tenant",
        actor=ActorModel(id="compromised-agent", role="agent"),
        action=ActionModel(name="test_action"),
    )
    verdict = await stage.execute(req, time.perf_counter())
    assert verdict is not None
    assert verdict.decision == DecisionEnum.DENY
    assert "Compromised agent" in verdict.triggered_rules[0].reason

    # Clean case
    mock_ks.check_kill_switches.return_value = (False, None, None)
    clean_verdict = await stage.execute(req, time.perf_counter())
    assert clean_verdict is None


@pytest.mark.asyncio
async def test_identity_delegation_stage(mocker):
    mock_validator = mocker.Mock()
    mock_validator.validate_delegation.return_value = (False, "Depth exceeded")
    stage = IdentityDelegationStage(mock_validator)

    pack = PolicyPackDefinition(id="test-pack", name="Test Pack", version="1.0.0")
    req = EvaluationRequest(
        tenant_id="test-tenant",
        actor=ActorModel(id="agent-01", role="worker", delegation_depth=5),
        action=ActionModel(name="run_query"),
    )
    ctx = PipelineStageContext(
        request=req,
        start_time=time.perf_counter(),
        policy_pack=pack,
        effective_mode=EffectiveModeEnum.ENFORCE,
    )
    verdict = await stage.execute(ctx)
    assert verdict is not None
    assert verdict.decision == DecisionEnum.DENY
    assert "Depth exceeded" in verdict.triggered_rules[0].reason


@pytest.mark.asyncio
async def test_budget_circuit_stage(mocker):
    mock_loop = mocker.AsyncMock()
    mock_budget = mocker.AsyncMock()
    mock_loop.record_and_check.return_value = (True, 4, "hash123")
    stage = BudgetCircuitStage(mock_loop, mock_budget)

    pack = PolicyPackDefinition(id="test-pack", name="Test Pack", version="1.0.0")
    req = EvaluationRequest(
        tenant_id="test-tenant",
        stage=StageEnum.TOOL_PRE_CALL,
        actor=ActorModel(id="agent-01", role="worker"),
        action=ActionModel(name="duplicate_tool"),
    )
    ctx = PipelineStageContext(
        request=req,
        start_time=time.perf_counter(),
        policy_pack=pack,
        effective_mode=EffectiveModeEnum.ENFORCE,
    )
    verdict = await stage.execute(ctx)
    assert verdict is not None
    assert verdict.decision == DecisionEnum.DENY
    assert "Runaway loop detected" in verdict.triggered_rules[0].reason


@pytest.mark.asyncio
async def test_tiered_scanner_and_policy_stages(mocker):
    from core.registry.registry import get_plugin_registry
    from core.policy_engine.yaml_engine import get_yaml_policy_engine

    registry = get_plugin_registry()
    policy_engine = get_yaml_policy_engine()

    scanner_stage = TieredScannerStage(registry)
    policy_stage = PolicyEvaluationStage(policy_engine)

    pack = PolicyPackDefinition(
        id="test-eval-pack",
        name="Test Eval Pack",
        version="1.0.0",
        execution_mode="enforce",
    )
    req = EvaluationRequest(
        tenant_id="test-tenant",
        stage=StageEnum.LLM_INPUT,
        actor=ActorModel(id="user-01", role="user"),
        content=ContentModel(trusted_instructions="Hello", untrusted_data="clean input"),
    )
    ctx = PipelineStageContext(
        request=req,
        start_time=time.perf_counter(),
        policy_pack=pack,
        effective_mode=EffectiveModeEnum.ENFORCE,
    )

    await scanner_stage.execute(ctx)
    assert isinstance(ctx.scanner_findings, list)

    rule_mutations = await policy_stage.execute(ctx)
    assert ctx.effective_decision == DecisionEnum.ALLOW
    assert ctx.risk_score == 0.0
