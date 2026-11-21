import pytest
from httpx import ASGITransport, AsyncClient

from core.auth.security import create_access_token
from gateways.pdp_api.main import app


@pytest.fixture
def superadmin_headers():
    token = create_access_token({"sub": "admin-1", "username": "admin", "tenant_id": "default", "role": "SuperAdmin"})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def tenant_admin_headers():
    token = create_access_token({"sub": "user-corp", "username": "corp_admin", "tenant_id": "corp-alpha", "role": "TenantAdmin"})
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_tenant_and_workspace_lifecycle(api_client: AsyncClient, superadmin_headers):
    # 1. Create Tenant
    res = await api_client.post(
        "/v1/tenants",
        json={"id": "corp-alpha", "name": "Alpha Corporation"},
        headers=superadmin_headers,
    )
    assert res.status_code == 201
    data = res.json()
    assert data["tenant_id"] == "corp-alpha"
    assert data["name"] == "Alpha Corporation"

    # 2. Get Tenant
    res_get = await api_client.get("/v1/tenants/corp-alpha", headers=superadmin_headers)
    assert res_get.status_code == 200
    assert res_get.json()["id"] == "corp-alpha"

    # 3. Create Workspace
    res_ws = await api_client.post(
        "/v1/tenants/corp-alpha/workspaces",
        json={"id": "ws-secops", "name": "SecOps Prod", "environment": "prod"},
        headers=superadmin_headers,
    )
    assert res_ws.status_code == 201
    assert res_ws.json()["environment"] == "prod"

    # 4. List Workspaces
    res_ws_list = await api_client.get("/v1/tenants/corp-alpha/workspaces", headers=superadmin_headers)
    assert res_ws_list.status_code == 200
    ws_ids = [w["id"] for w in res_ws_list.json()]
    assert "ws-secops" in ws_ids


@pytest.mark.asyncio
async def test_virtual_api_key_lifecycle_and_evaluation(api_client: AsyncClient, superadmin_headers):
    # Setup Tenant
    await api_client.post("/v1/tenants", json={"id": "tenant-beta", "name": "Beta Inc"}, headers=superadmin_headers)

    # 1. Issue Virtual API Key
    res = await api_client.post(
        "/v1/api-keys/virtual",
        json={
            "tenant_id": "tenant-beta",
            "workspace_id": "default",
            "name": "SecOps Agent Key",
            "role": "SuperAdmin",
            "environment": "dev",
            "default_policy_pack_id": "base-enterprise",
            "budget_cap_usd": 50.0,
            "rate_limit_rpm": 300,
        },
        headers=superadmin_headers,
    )
    assert res.status_code == 201
    key_data = res.json()
    key_id = key_data["id"]
    api_key = key_data["api_key"]
    assert api_key.startswith("ag_live_")

    # 2. Authenticate on /v1/evaluate using the Virtual API Key
    eval_payload = {
        "tenant_id": "tenant-beta",
        "stage": "llm_input",
        "actor": {"id": "agent-007", "role": "agent"},
        "action": {"name": "generate"},
        "content": {"trusted_instructions": "Hello", "untrusted_data": "Normal query"},
    }
    res_eval = await api_client.post(
        "/v1/evaluate",
        json=eval_payload,
        headers={"X-Aegis-Api-Key": api_key},
    )
    assert res_eval.status_code == 200
    assert res_eval.json()["decision"] == "ALLOW"

    # 3. Rotate Virtual API Key
    res_rotate = await api_client.post(
        f"/v1/api-keys/virtual/{key_id}/rotate?tenant_id=tenant-beta",
        headers=superadmin_headers,
    )
    assert res_rotate.status_code == 200
    rotate_data = res_rotate.json()
    new_api_key = rotate_data["api_key"]
    assert new_api_key != api_key

    # 4. Old key should now be rejected (401)
    res_old = await api_client.post(
        "/v1/evaluate",
        json=eval_payload,
        headers={"X-Aegis-Api-Key": api_key},
    )
    assert res_old.status_code == 401

    # 5. New key should succeed
    res_new = await api_client.post(
        "/v1/evaluate",
        json=eval_payload,
        headers={"X-Aegis-Api-Key": new_api_key},
    )
    assert res_new.status_code == 200

    # 6. Revoke New Key
    new_key_id = rotate_data["new_key_id"]
    res_revoke = await api_client.post(
        f"/v1/api-keys/virtual/{new_key_id}/revoke?tenant_id=tenant-beta",
        headers=superadmin_headers,
    )
    assert res_revoke.status_code == 200

    # 7. Revoked key immediately fails
    res_revoked = await api_client.post(
        "/v1/evaluate",
        json=eval_payload,
        headers={"X-Aegis-Api-Key": new_api_key},
    )
    assert res_revoked.status_code == 401


@pytest.mark.asyncio
async def test_cross_tenant_isolation(api_client: AsyncClient, superadmin_headers, tenant_admin_headers):
    # Ensure corp-alpha exists
    await api_client.post("/v1/tenants", json={"id": "corp-alpha", "name": "Corp Alpha"}, headers=superadmin_headers)
    await api_client.post("/v1/tenants", json={"id": "corp-omega", "name": "Corp Omega"}, headers=superadmin_headers)

    # TenantAdmin for corp-alpha attempts to access corp-omega
    res = await api_client.get("/v1/tenants/corp-omega", headers=tenant_admin_headers)
    assert res.status_code == 403

    # TenantAdmin attempts to issue key for corp-omega
    res_key = await api_client.post(
        "/v1/api-keys/virtual",
        json={"tenant_id": "corp-omega", "name": "Illicit Key"},
        headers=tenant_admin_headers,
    )
    assert res_key.status_code == 403


@pytest.mark.asyncio
async def test_plugin_dynamic_control_api(api_client: AsyncClient, superadmin_headers):
    # 1. Get Plugin Schemas
    res_schemas = await api_client.get("/v1/plugins/schemas")
    assert res_schemas.status_code == 200
    schemas = res_schemas.json()
    assert "webhook_scanner" in schemas or "secrets_scanner" in schemas

    # 2. Register Dynamic Plugin Instance
    res_inst = await api_client.post(
        "/v1/plugins/instances",
        json={
            "tenant_id": "default",
            "plugin_type": "scanner",
            "name": "custom_sec_webhook",
            "config": {
                "base_plugin": "webhook_scanner",
                "endpoint_url": "http://sec-endpoint.internal/scan",
                "timeout_ms": 300,
            },
        },
        headers=superadmin_headers,
    )
    assert res_inst.status_code == 201
    inst_data = res_inst.json()
    assert inst_data["name"] == "custom_sec_webhook"

    # 3. Patch Plugin Config
    res_patch = await api_client.patch(
        "/v1/plugins/custom_sec_webhook/config",
        json={"config": {"timeout_ms": 450}, "is_enabled": True},
        headers=superadmin_headers,
    )
    assert res_patch.status_code == 200
    assert res_patch.json()["config"]["timeout_ms"] == 450

    # 4. Test Connectivity Ping
    res_test = await api_client.post(
        "/v1/plugins/custom_sec_webhook/test",
        json={"test_payload": {"endpoint_url": "http://127.0.0.1:9999/dummy"}},
        headers=superadmin_headers,
    )
    assert res_test.status_code == 200
    assert "status" in res_test.json()

    # 5. Delete Plugin Instance
    inst_id = inst_data["id"]
    res_del = await api_client.delete(
        f"/v1/plugins/instances/{inst_id}?tenant_id=default",
        headers=superadmin_headers,
    )
    assert res_del.status_code == 200


@pytest.mark.asyncio
async def test_budgets_and_loop_api(api_client: AsyncClient, superadmin_headers):
    # 1. Update Quotas
    res_quota = await api_client.post(
        "/v1/budgets/quotas",
        json={
            "tenant_id": "default",
            "workspace_id": "default",
            "max_tokens": 80000,
            "max_cost_usd": 15.0,
            "max_tool_calls": 40,
        },
        headers=superadmin_headers,
    )
    assert res_quota.status_code == 200
    assert res_quota.json()["max_tokens"] == 80000

    # 2. Get Budget Usage
    res_usage = await api_client.get(
        "/v1/budgets/usage?tenant_id=default",
        headers=superadmin_headers,
    )
    assert res_usage.status_code == 200
    assert "tokens_used" in res_usage.json()

    # 3. Reset Loop Circuit
    res_reset = await api_client.post(
        "/v1/budgets/reset-loop",
        json={
            "tenant_id": "default",
            "session_id": "sess-1",
            "actor_id": "agent-01",
        },
        headers=superadmin_headers,
    )
    assert res_reset.status_code == 200
    assert res_reset.json()["status"] == "reset"
