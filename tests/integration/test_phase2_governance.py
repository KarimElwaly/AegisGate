import pytest

from core.governance.kill_switch import get_kill_switch_service
from core.pipeline.orchestrator import PipelineOrchestrator
from core.policy_engine.opa_engine import OPAEngineConfig, OPAPolicyEngine
from core.schemas.common import DecisionEnum, StageEnum
from core.schemas.events import ActionModel, ActorModel, ContentModel, EvaluationRequest
from core.schemas.policy import PolicyPackDefinition
from plugins.resolvers.http_resolver import HTTPContextResolver, HTTPContextResolverConfig
from plugins.resolvers.redis_resolver import RedisStateResolver, RedisStateResolverConfig
from plugins.resolvers.static_resolver import StaticLookupResolver, StaticLookupResolverConfig


@pytest.mark.asyncio
async def test_kill_switch_blocking_and_api(api_client):
    service = get_kill_switch_service()
    orchestrator = PipelineOrchestrator()

    tenant_id = "ks-tenant"
    req = EvaluationRequest(
        tenant_id=tenant_id,
        action=ActionModel(name="query_logs"),
        content=ContentModel(trusted_instructions="Show logs"),
    )

    # 1. Normal call passes
    v1 = await orchestrator.evaluate(req)
    assert v1.decision == DecisionEnum.ALLOW

    # 2. Activate tenant kill switch via API
    res_act = await api_client.post(
        "/v1/kill-switch",
        json={"scope": "tenant", "target": tenant_id, "reason": "Compromised tenant"},
    )
    assert res_act.status_code == 200
    assert res_act.json()["status"] == "activated"

    # 3. Request is now blocked immediately in sub-millisecond time
    v2 = await orchestrator.evaluate(req)
    assert v2.decision == DecisionEnum.DENY
    assert v2.risk_score == 1.0
    assert "kill-switch-engaged" in [r.rule_id for r in v2.triggered_rules]
    assert "Compromised tenant" in v2.triggered_rules[0].reason

    # 4. Deactivate kill switch via API
    res_deact = await api_client.request(
        "DELETE",
        "/v1/kill-switch",
        json={"scope": "tenant", "target": tenant_id},
    )
    assert res_deact.status_code == 200
    assert res_deact.json()["status"] == "deactivated"

    # 5. Subsequent request passes again
    v3 = await orchestrator.evaluate(req)
    assert v3.decision == DecisionEnum.ALLOW


@pytest.mark.asyncio
async def test_atomic_budget_cutoff():
    orchestrator = PipelineOrchestrator()
    tenant_id = "budget-tenant"
    session_id = "sess-budget-01"

    # Define a policy pack with tight token and tool call limits
    budget_pack = PolicyPackDefinition(
        id="budget-enforced-pack",
        name="Budget Pack",
        execution_mode="enforce",
        budgets={
            "max_tokens": 1000,
            "max_tool_calls": 2,
        },
    )
    orchestrator.policy_engine.register_policy_pack(budget_pack)

    # Call 1: 600 tokens -> allowed (600 <= 1000)
    req1 = EvaluationRequest(
        tenant_id=tenant_id,
        session_id=session_id,
        policy_pack_id="budget-enforced-pack",
        stage=StageEnum.LLM_INPUT,
        action=ActionModel(name="prompt", estimated_tokens=600),
    )
    v1 = await orchestrator.evaluate(req1)
    assert v1.decision == DecisionEnum.ALLOW
    assert v1.budget_snapshot is not None
    assert v1.budget_snapshot.tokens_used == 600

    # Call 2: another 600 tokens -> total 1200 > 1000 -> DENIED by atomic budget
    req2 = EvaluationRequest(
        tenant_id=tenant_id,
        session_id=session_id,
        policy_pack_id="budget-enforced-pack",
        stage=StageEnum.LLM_INPUT,
        action=ActionModel(name="prompt", estimated_tokens=600),
    )
    v2 = await orchestrator.evaluate(req2)
    assert v2.decision == DecisionEnum.DENY
    assert any(r.rule_id == "budget-quota-exceeded" for r in v2.triggered_rules)


@pytest.mark.asyncio
async def test_loop_circuit_breaker_tripping():
    orchestrator = PipelineOrchestrator()
    tenant_id = "loop-tenant"
    session_id = "loop-sess-99"

    pack = PolicyPackDefinition(
        id="loop-pack",
        name="Loop Pack",
        budgets={
            "loop_detector": {
                "threshold": 3,
                "window_seconds": 60,
            }
        },
    )
    orchestrator.policy_engine.register_policy_pack(pack)

    # Identical tool call parameters
    req = EvaluationRequest(
        tenant_id=tenant_id,
        session_id=session_id,
        policy_pack_id="loop-pack",
        stage=StageEnum.TOOL_PRE_CALL,
        actor=ActorModel(id="agent-loop", role="worker"),
        action=ActionModel(name="fetch_user", parameters={"user_id": "42"}),
    )

    # Call 1 -> ALLOW
    v1 = await orchestrator.evaluate(req)
    assert v1.decision == DecisionEnum.ALLOW

    # Call 2 -> ALLOW
    v2 = await orchestrator.evaluate(req)
    assert v2.decision == DecisionEnum.ALLOW

    # Call 3 -> Tripped! DENY
    v3 = await orchestrator.evaluate(req)
    assert v3.decision == DecisionEnum.DENY
    assert any(r.rule_id == "runaway-loop-circuit-breaker" for r in v3.triggered_rules)


@pytest.mark.asyncio
async def test_privilege_escalation_and_delegation_governance():
    orchestrator = PipelineOrchestrator()

    pack = PolicyPackDefinition(
        id="delegation-pack",
        name="Delegation Pack",
        budgets={
            "delegation": {
                "max_delegation_depth": 2,
                "allowed_role_matrix": {
                    "lead": ["analyst"],
                    "analyst": ["worker"],
                },
                "role_tool_permissions": {
                    "lead": ["read_file", "delete_file"],
                    "analyst": ["read_file"],
                    "worker": ["read_file", "delete_file"],
                },
            }
        },
    )
    orchestrator.policy_engine.register_policy_pack(pack)

    # 1. Depth violation (depth 3 > max 2)
    req_deep = EvaluationRequest(
        policy_pack_id="delegation-pack",
        stage=StageEnum.TOOL_PRE_CALL,
        actor=ActorModel(
            id="worker-01",
            role="worker",
            delegation_chain=["lead", "analyst", "sub_analyst"],
        ),
        action=ActionModel(name="read_file"),
    )
    v_deep = await orchestrator.evaluate(req_deep)
    assert v_deep.decision == DecisionEnum.DENY
    assert "exceeds maximum allowed depth" in v_deep.triggered_rules[0].reason

    # 2. Privilege Escalation Denial:
    # Originator 'analyst' cannot delete files, but delegated 'worker' attempts 'delete_file'
    req_escalation = EvaluationRequest(
        policy_pack_id="delegation-pack",
        stage=StageEnum.TOOL_PRE_CALL,
        actor=ActorModel(
            id="worker-01",
            role="worker",
            delegation_chain=["analyst"],  # Originator is analyst
        ),
        action=ActionModel(name="delete_file"),
    )
    v_esc = await orchestrator.evaluate(req_escalation)
    assert v_esc.decision == DecisionEnum.DENY
    assert "Privilege escalation denied" in v_esc.triggered_rules[0].reason

    # 3. Valid delegation:
    req_valid = EvaluationRequest(
        policy_pack_id="delegation-pack",
        stage=StageEnum.TOOL_PRE_CALL,
        actor=ActorModel(
            id="worker-01",
            role="worker",
            delegation_chain=["lead", "analyst"],
        ),
        action=ActionModel(name="read_file"),
    )
    v_valid = await orchestrator.evaluate(req_valid)
    assert v_valid.decision == DecisionEnum.ALLOW


@pytest.mark.asyncio
async def test_context_resolvers_caching_and_fallbacks(monkeypatch):
    # 1. StaticLookupResolver
    static_res = StaticLookupResolver()
    static_cfg = StaticLookupResolverConfig(
        lookup_field="action.parameters.target_ip",
        lookup_table={
            "10.0.1.50": {"asset_tier": "tier0", "is_dc": True},
            "10.0.1.51": {"asset_tier": "standard", "is_dc": False},
        },
        fallback_response={"asset_tier": "unknown"},
    )
    req_static = EvaluationRequest(
        action=ActionModel(name="query_host", parameters={"target_ip": "10.0.1.50"})
    )
    res_static = await static_res.resolve(req_static, static_cfg)
    assert res_static["asset_tier"] == "tier0"
    assert res_static["is_dc"] is True

    # 2. RedisStateResolver
    from core.redis_client import get_redis_client
    redis = await get_redis_client()
    await redis.set("aegisgate:state:analyst-007", '{"clearance": "top_secret", "dept": "secops"}')

    redis_res = RedisStateResolver()
    redis_cfg = RedisStateResolverConfig(
        key_template="aegisgate:state:{actor_id}",
        data_type="json",
    )
    req_redis = EvaluationRequest(actor=ActorModel(id="analyst-007", role="analyst"))
    res_redis = await redis_res.resolve(req_redis, redis_cfg)
    assert res_redis.get("clearance") == "top_secret"

    # 3. HTTPContextResolver timeout fallback
    http_res = HTTPContextResolver()
    http_cfg = HTTPContextResolverConfig(
        url_template="http://non-existent-cmdb.local/assets/{target_ip}",
        timeout_ms=50,
        fallback_response={"asset_tier": "fallback_standard"},
    )
    res_http = await http_res.resolve(req_static, http_cfg)
    assert res_http["asset_tier"] == "fallback_standard"


@pytest.mark.asyncio
async def test_opa_rego_adapter_fallback():
    # Fail-closed
    opa_engine = OPAPolicyEngine(OPAEngineConfig(opa_url="http://unreachable-opa.local:8181", fail_open=False))
    req = EvaluationRequest(actor=ActorModel(id="u1", role="user"))
    decision, risk, triggered, mutations = await opa_engine.evaluate(req, [], {}, PolicyPackDefinition(id="p", name="p"))
    assert decision == DecisionEnum.DENY
    assert risk == 1.0
    assert any(r.rule_id == "opa-fail-closed" for r in triggered)

    # Fail-open
    opa_open = OPAPolicyEngine(OPAEngineConfig(opa_url="http://unreachable-opa.local:8181", fail_open=True))
    decision_open, risk_open, triggered_open, _ = await opa_open.evaluate(req, [], {}, PolicyPackDefinition(id="p", name="p"))
    assert decision_open == DecisionEnum.ALLOW
    assert risk_open == 0.0

