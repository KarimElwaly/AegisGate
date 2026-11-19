import pytest


@pytest.mark.asyncio
async def test_health_and_metrics_endpoints(api_client):
    res_health = await api_client.get("/healthz")
    assert res_health.status_code == 200
    assert res_health.json()["status"] == "ok"

    res_ready = await api_client.get("/readyz")
    assert res_ready.status_code == 200
    assert res_ready.json()["status"] == "ready"

    res_metrics = await api_client.get("/metrics")
    assert res_metrics.status_code == 200
    assert b"python_gc_" in res_metrics.content or len(res_metrics.content) > 0


@pytest.mark.asyncio
async def test_plugin_catalog_endpoint(api_client):
    res = await api_client.get("/v1/plugins")
    assert res.status_code == 200
    data = res.json()
    assert "scanners" in data
    scanner_names = [s["name"] for s in data["scanners"]]
    assert "secrets_scanner" in scanner_names
    assert "pii_scanner" in scanner_names
    assert "tool_param_guard" in scanner_names


@pytest.mark.asyncio
async def test_policy_crud_promote_and_rollback(api_client):
    sample_yaml = """
id: dynamic-demo-pack
name: Dynamic Demo Pack
version: 1.0.0
execution_mode: enforce
rules:
  - id: demo-rule-1
    priority: 1
    condition:
      field: actor.role
      operator: eq
      value: unauthorized_role
    action:
      decision: DENY
      reason: Role unauthorized
"""

    # 1. Create policy pack draft
    res_create = await api_client.post(
        "/v1/policies",
        json={
            "yaml_content": sample_yaml,
            "tenant_id": "test-tenant",
            "status": "draft",
        },
    )
    assert res_create.status_code == 200
    assert res_create.json()["status"] == "success"
    assert res_create.json()["pack_id"] == "dynamic-demo-pack"

    # 2. List policies
    res_list = await api_client.get("/v1/policies?tenant_id=test-tenant")
    assert res_list.status_code == 200
    packs = res_list.json()
    assert any(p["pack_id"] == "dynamic-demo-pack" for p in packs)

    # 3. Promote to active
    res_promote = await api_client.post(
        "/v1/policies/dynamic-demo-pack/promote?tenant_id=test-tenant",
        json={"version": "1.0.0", "target_status": "active"},
    )
    assert res_promote.status_code == 200
    assert res_promote.json()["new_status"] == "active"

    # 4. Create version 1.0.1
    sample_yaml_v2 = sample_yaml.replace("version: 1.0.0", "version: 1.0.1")
    res_v2 = await api_client.post(
        "/v1/policies",
        json={
            "yaml_content": sample_yaml_v2,
            "tenant_id": "test-tenant",
            "status": "active",
        },
    )
    assert res_v2.status_code == 200

    # 5. Rollback to version 1.0.0
    res_rollback = await api_client.post(
        "/v1/policies/dynamic-demo-pack/rollback?tenant_id=test-tenant",
        json={"target_version": "1.0.0"},
    )
    assert res_rollback.status_code == 200
    assert res_rollback.json()["active_version"] == "1.0.0"


@pytest.mark.asyncio
async def test_pdp_evaluate_endpoint(api_client):
    # Safe request
    payload_clean = {
        "tenant_id": "test-tenant",
        "policy_pack_id": "base-enterprise",
        "stage": "llm_input",
        "actor": {"id": "user-42", "role": "analyst"},
        "content": {"trusted_instructions": "Give me a summary of log files."},
    }
    res_clean = await api_client.post("/v1/evaluate", json=payload_clean)
    assert res_clean.status_code == 200
    verdict = res_clean.json()
    assert verdict["decision"] == "ALLOW"
    assert verdict["effective_mode"] == "enforce"
    assert verdict["latency_ms"] < 100

    # Request containing AWS secret key
    payload_secret = {
        "tenant_id": "test-tenant",
        "policy_pack_id": "base-enterprise",
        "stage": "llm_input",
        "actor": {"id": "user-42", "role": "analyst"},
        "content": {"trusted_instructions": "My access key is AKIAIOSFODNN7EXAMPLE"},
    }
    res_secret = await api_client.post("/v1/evaluate", json=payload_secret)
    assert res_secret.status_code == 200
    verdict_secret = res_secret.json()
    assert verdict_secret["decision"] == "DENY"
    assert verdict_secret["risk_score"] >= 0.8

    # Shadow override on secret request
    payload_shadow = {
        **payload_secret,
        "execution_mode_override": "shadow",
    }
    res_shadow = await api_client.post("/v1/evaluate", json=payload_shadow)
    assert res_shadow.status_code == 200
    verdict_shadow = res_shadow.json()
    assert verdict_shadow["decision"] == "ALLOW"
    assert verdict_shadow["effective_mode"] == "shadow"
    assert verdict_shadow["would_have_decided"] == "DENY"

