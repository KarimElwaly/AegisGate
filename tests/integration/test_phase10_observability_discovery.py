import asyncio
import pytest
from httpx import AsyncClient

from core.telemetry import (
    QUARANTINED_TOOL_GAUGE,
    record_scanner_violation,
    record_token_metric,
)


@pytest.mark.asyncio
async def test_phase10_extended_telemetry_metrics(api_client: AsyncClient):
    # 1. Record Phase 10 custom metrics
    record_scanner_violation("rag_acl_guard", "fail")
    record_token_metric("tenant-discovery-metrics", "gpt-4o", 250)
    QUARANTINED_TOOL_GAUGE.labels(tenant_id="tenant-discovery-metrics").set(3)

    # 2. Perform an evaluation to trigger pipeline evaluation metric
    eval_payload = {
        "tenant_id": "tenant-discovery-metrics",
        "stage": "tool_pre_call",
        "policy_pack_id": "base-enterprise",
        "actor": {"id": "agent-obs", "role": "test"},
        "action": {"name": "query_inventory", "parameters": {"sku": "123"}},
    }
    eval_res = await api_client.post("/v1/evaluate", json=eval_payload)
    assert eval_res.status_code == 200

    # 3. Verify Prometheus metrics endpoint exports all new Phase 10 metrics
    metrics_res = await api_client.get("/metrics")
    assert metrics_res.status_code == 200
    metrics_text = metrics_res.text

    assert "aegisgate_evaluations_total" in metrics_text
    assert "aegisgate_tokens_used_total" in metrics_text
    assert "aegisgate_scanner_violations_total" in metrics_text
    assert "aegisgate_quarantined_tools_total" in metrics_text
    assert 'tenant-discovery-metrics' in metrics_text


@pytest.mark.asyncio
async def test_shadow_ai_auto_discovery_lifecycle(api_client: AsyncClient):
    tenant_id = "tenant-discovery-test"
    headers = {"X-Aegis-Tenant-Id": tenant_id}

    # 1. Trigger evaluation containing shadow tool and model
    eval_req_1 = {
        "tenant_id": tenant_id,
        "workspace_id": "default",
        "stage": "tool_pre_call",
        "policy_pack_id": "base-enterprise",
        "actor": {"id": "rogue-agent", "role": "agent"},
        "action": {"name": "unapproved_exfil_tool", "parameters": {"url": "http://malicious.internal"}},
    }
    res1 = await api_client.post("/v1/evaluate", json=eval_req_1, headers=headers)
    assert res1.status_code == 200

    eval_req_2 = {
        "tenant_id": tenant_id,
        "workspace_id": "default",
        "stage": "llm_input",
        "policy_pack_id": "base-enterprise",
        "actor": {"id": "rogue-agent", "role": "agent"},
        "action": {"name": "generate_text", "target": "unapproved-shadow-model-v1"},
        "content": {"untrusted_data": "Summarize this data"},
    }
    res2 = await api_client.post("/v1/evaluate", json=eval_req_2, headers=headers)
    assert res2.status_code == 200

    # Give async task a brief tick to persist discovery records
    await asyncio.sleep(0.1)

    # 2. Query discovered assets
    disc_res = await api_client.get("/v1/discovery/assets?workspace_id=default", headers=headers)
    assert disc_res.status_code == 200
    assets = disc_res.json()
    assert len(assets) >= 2

    tool_asset = next((a for a in assets if a["name"] == "unapproved_exfil_tool"), None)
    model_asset = next((a for a in assets if a["name"] == "unapproved-shadow-model-v1"), None)

    assert tool_asset is not None
    assert tool_asset["asset_type"] == "tool"
    assert tool_asset["governance_status"] == "shadow_unapproved"

    assert model_asset is not None
    assert model_asset["asset_type"] == "model"
    assert model_asset["governance_status"] == "shadow_unapproved"

    # 3. Update status of the tool to "governed" (approve it)
    patch_res = await api_client.patch(
        f"/v1/discovery/assets/{tool_asset['id']}",
        json={"governance_status": "governed", "risk_level": "low"},
        headers=headers,
    )
    assert patch_res.status_code == 200
    patch_data = patch_res.json()
    assert patch_data["governance_status"] == "governed"
    assert patch_data["risk_level"] == "low"

    # 4. Filter assets by governance status
    gov_list_res = await api_client.get(
        "/v1/discovery/assets?governance_status=governed",
        headers=headers,
    )
    assert gov_list_res.status_code == 200
    gov_assets = gov_list_res.json()
    assert any(a["name"] == "unapproved_exfil_tool" for a in gov_assets)
    assert not any(a["name"] == "unapproved-shadow-model-v1" for a in gov_assets)

    shadow_list_res = await api_client.get(
        "/v1/discovery/assets?governance_status=shadow_unapproved",
        headers=headers,
    )
    assert shadow_list_res.status_code == 200
    shadow_assets = shadow_list_res.json()
    assert any(a["name"] == "unapproved-shadow-model-v1" for a in shadow_assets)
    assert not any(a["name"] == "unapproved_exfil_tool" for a in shadow_assets)

