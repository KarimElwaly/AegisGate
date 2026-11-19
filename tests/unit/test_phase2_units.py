import pytest
from core.governance.budgets import get_budget_manager
from core.governance.kill_switch import get_kill_switch_service
from core.governance.loop_detector import get_loop_detector
from core.policy_engine.opa_engine import OPAEngineConfig, OPAPolicyEngine
from core.schemas.common import DecisionEnum
from core.schemas.events import ActorModel, EvaluationRequest
from core.schemas.policy import PolicyPackDefinition


@pytest.mark.asyncio
async def test_budget_manager_scopes_and_reset():
    mgr = get_budget_manager()
    tenant_id = "unit-budget-tenant"
    scope_type = "agent"
    scope_id = "agent-42"

    # Check and consume tool calls
    ok1, stat1, snap1 = await mgr.check_and_consume(
        tenant_id=tenant_id,
        scope_type=scope_type,
        scope_id=scope_id,
        delta_tool_calls=1,
        max_tool_calls=2,
    )
    assert ok1 is True
    assert snap1.tool_calls_used == 1

    # Read snapshot
    snap2 = await mgr.get_budget_snapshot(tenant_id, scope_type, scope_id)
    assert snap2.tool_calls_used == 1

    # Reset
    await mgr.reset_budget(tenant_id, scope_type, scope_id)
    snap3 = await mgr.get_budget_snapshot(tenant_id, scope_type, scope_id)
    assert snap3.tool_calls_used == 0


@pytest.mark.asyncio
async def test_kill_switch_various_scopes():
    ks = get_kill_switch_service()
    tenant = "ks-unit-tenant"
    ws = "ws-unit"
    agent = "agent-unit"
    tool = "dangerous_tool"

    # Workspace kill switch
    key_ws = await ks.set_kill_switch("workspace", ws, "Workspace quarantined", tenant_id=tenant)
    is_k1, scope1, _ = await ks.check_kill_switches(tenant, ws, agent, "normal_tool")
    assert is_k1 is True
    assert scope1 == "workspace"
    await ks.remove_kill_switch("workspace", ws, tenant_id=tenant)

    # Agent kill switch
    await ks.set_kill_switch("agent", agent, "Agent rogue", tenant_id=tenant)
    is_k2, scope2, _ = await ks.check_kill_switches(tenant, ws, agent, "normal_tool")
    assert is_k2 is True
    assert scope2 == "agent"
    await ks.remove_kill_switch("agent", agent, tenant_id=tenant)

    # Tool kill switch
    await ks.set_kill_switch("tool", tool, "Tool CVE active", tenant_id=tenant)
    is_k3, scope3, _ = await ks.check_kill_switches(tenant, ws, agent, tool)
    assert is_k3 is True
    assert scope3 == "tool"
    await ks.remove_kill_switch("tool", tool, tenant_id=tenant)

    # List active
    active = await ks.list_active_kill_switches()
    assert isinstance(active, list)


@pytest.mark.asyncio
async def test_loop_detector_reset():
    ld = get_loop_detector()
    await ld.reset("tenant-reset", "sess-reset")


@pytest.mark.asyncio
async def test_opa_mock_success(monkeypatch):
    class MockResponse:
        status_code = 200

        def json(self):
            return {
                "result": {
                    "allow": False,
                    "decision": "DENY",
                    "risk_score": 0.85,
                    "triggered_rules": [
                        {
                            "rule_id": "opa-rego-custom",
                            "severity": "high",
                            "reason": "Custom Rego rule denied",
                        }
                    ],
                }
            }

    import httpx
    async def mock_post(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    engine = OPAPolicyEngine()
    req = EvaluationRequest(actor=ActorModel(id="u1", role="user"))
    decision, risk, triggered, mutations = await engine.evaluate(req, [], {}, PolicyPackDefinition(id="p", name="p"))
    assert decision == DecisionEnum.DENY
    assert risk == 0.85
    assert len(triggered) == 1
    assert triggered[0].rule_id == "opa-rego-custom"
