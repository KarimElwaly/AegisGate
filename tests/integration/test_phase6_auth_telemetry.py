import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_user_registration_and_jwt_login(api_client: AsyncClient):
    # 1. Register initial SuperAdmin user
    register_payload = {
        "tenant_id": "test-tenant-auth",
        "username": "admin_user",
        "email": "admin@tenant-auth.internal",
        "password": "Password123!Secure",
        "role": "SuperAdmin",
    }
    res = await api_client.post("/v1/auth/register", json=register_payload)
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["username"] == "admin_user"
    assert data["role"] == "SuperAdmin"
    assert "hashed_password" not in data

    # 2. Duplicate registration should fail
    dup_res = await api_client.post("/v1/auth/register", json=register_payload)
    assert dup_res.status_code == 400
    assert "already exists" in dup_res.json()["detail"]

    # 3. Login with wrong password fails
    wrong_login = await api_client.post(
        "/v1/auth/login",
        json={
            "tenant_id": "test-tenant-auth",
            "username": "admin_user",
            "password": "WrongPassword123",
        },
    )
    assert wrong_login.status_code == 401

    # 4. Login with correct password succeeds
    login_res = await api_client.post(
        "/v1/auth/login",
        json={
            "tenant_id": "test-tenant-auth",
            "username": "admin_user",
            "password": "Password123!Secure",
        },
    )
    assert login_res.status_code == 200
    token_data = login_res.json()
    assert "access_token" in token_data
    token = token_data["access_token"]
    assert token_data["user"]["role"] == "SuperAdmin"

    # 5. Access /v1/auth/me with Bearer token
    me_res = await api_client.get(
        "/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me_res.status_code == 200
    me_data = me_res.json()
    assert me_data["username"] == "admin_user"
    assert me_data["role"] == "SuperAdmin"
    assert me_data["tenant_id"] == "test-tenant-auth"


@pytest.mark.asyncio
async def test_scoped_api_key_flow(api_client: AsyncClient):
    # 1. Register admin to authorize creating keys
    await api_client.post(
        "/v1/auth/register",
        json={
            "tenant_id": "test-tenant-keys",
            "username": "key_admin",
            "email": "keyadmin@keys.internal",
            "password": "Password123!Secure",
            "role": "SuperAdmin",
        },
    )

    login_res = await api_client.post(
        "/v1/auth/login",
        json={
            "tenant_id": "test-tenant-keys",
            "username": "key_admin",
            "password": "Password123!Secure",
        },
    )
    token = login_res.json()["access_token"]

    # 2. Issue a scoped API key
    key_payload = {
        "tenant_id": "test-tenant-keys",
        "name": "ci-cd-evaluator-key",
        "role": "PolicyAuthor",
    }
    create_key_res = await api_client.post(
        "/v1/auth/api-keys",
        headers={"Authorization": f"Bearer {token}"},
        json=key_payload,
    )
    assert create_key_res.status_code == 200, create_key_res.text
    key_info = create_key_res.json()
    assert "raw_api_key" in key_info
    raw_api_key = key_info["raw_api_key"]
    assert raw_api_key.startswith("aegis_live_")
    assert key_info["role"] == "PolicyAuthor"

    # 3. List API keys
    list_keys_res = await api_client.get(
        "/v1/auth/api-keys?tenant_id=test-tenant-keys",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert list_keys_res.status_code == 200
    keys_list = list_keys_res.json()
    assert len(keys_list) >= 1
    assert any(k["name"] == "ci-cd-evaluator-key" for k in keys_list)

    # 4. Authenticate using X-Aegis-API-Key header
    auth_key_res = await api_client.get(
        "/v1/auth/me",
        headers={"X-Aegis-API-Key": raw_api_key},
    )
    assert auth_key_res.status_code == 200
    actor = auth_key_res.json()
    assert actor["role"] == "PolicyAuthor"
    assert actor["tenant_id"] == "test-tenant-keys"

    # 5. Invalid API key should be rejected with 401
    bad_key_res = await api_client.get(
        "/v1/auth/me",
        headers={"X-Aegis-API-Key": "aegis_live_invalidkey123456789"},
    )
    assert bad_key_res.status_code == 401


@pytest.mark.asyncio
async def test_rbac_role_enforcement(api_client: AsyncClient):
    # Register an Auditor user
    await api_client.post(
        "/v1/auth/register",
        json={
            "tenant_id": "test-tenant-rbac",
            "username": "auditor_user",
            "email": "auditor@rbac.internal",
            "password": "Password123!Secure",
            "role": "Auditor",
        },
    )

    login_res = await api_client.post(
        "/v1/auth/login",
        json={
            "tenant_id": "test-tenant-rbac",
            "username": "auditor_user",
            "password": "Password123!Secure",
        },
    )
    auditor_token = login_res.json()["access_token"]

    # Attempt to create an API key (which requires SuperAdmin or TenantAdmin)
    key_res = await api_client.post(
        "/v1/auth/api-keys",
        headers={"Authorization": f"Bearer {auditor_token}"},
        json={
            "tenant_id": "test-tenant-rbac",
            "name": "unauthorized-key",
            "role": "PolicyAuthor",
        },
    )
    # Auditor cannot create API keys
    assert key_res.status_code == 403
    assert "Forbidden" in key_res.json()["detail"] or "role" in key_res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_prometheus_telemetry_metrics_export(api_client: AsyncClient):
    # Perform an evaluation to produce telemetry
    eval_payload = {
        "tenant_id": "metrics-tenant",
        "stage": "tool_pre_call",
        "policy_pack_id": "base-enterprise",
        "actor": {"id": "agent-metrics", "role": "test"},
        "action": {"name": "test_ping", "parameters": {"msg": "hello"}},
    }
    eval_res = await api_client.post("/v1/evaluate", json=eval_payload)
    assert eval_res.status_code == 200

    # Query /metrics endpoint
    metrics_res = await api_client.get("/metrics")
    assert metrics_res.status_code == 200
    metrics_text = metrics_res.text

    # Verify Prometheus custom metrics are present
    assert "aegisgate_evaluations_total" in metrics_text
    assert "aegisgate_evaluation_latency_seconds" in metrics_text
