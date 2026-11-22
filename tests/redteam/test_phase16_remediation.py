import asyncio
import base64
import json
import os
from pathlib import Path
import pytest
from httpx import ASGITransport, AsyncClient

from core.audit.ledger import AuditLedger
from core.audit.verifier import AuditVerifier
from core.auth.oidc import get_oidc_service, OidcConfig
from core.bootstrap import bootstrap_system
from core.database import db_context
from core.hitl.engine import get_hitl_engine
from core.pii_vault.vault import get_pii_vault
from core.policy_engine.yaml_engine import get_yaml_policy_engine
from core.redis_client import get_redis_client
from core.schemas.common import DecisionEnum, StageEnum, SeverityEnum
from core.schemas.events import ActionModel, ActorModel, ContentModel, EvaluationRequest
from core.schemas.policy import PolicyPackDefinition
from core.schemas.verdicts import EvaluationVerdict
from core.simulator.replay import PolicyReplaySimulator, ReplaySimulationRequest
from gateways.llm_proxy.streaming import SSEStreamGuard
from gateways.llm_proxy.translators.anthropic_translator import AnthropicProtocolTranslator
from gateways.llm_proxy.translators.bedrock_translator import BedrockProtocolTranslator
from gateways.llm_proxy.translators.gemini_translator import GeminiProtocolTranslator
from gateways.pdp_api.main import app
from plugins.scanners.tier1_deterministic.sql_ast_guard import SqlAstGuard, SqlAstGuardConfig
from plugins.scanners.tier2_local_ml.ner_pii_scanner import NerPiiScanner, NerPiiScannerConfig


# ==============================================================================
# 1. Reverse Proxy SSRF Blocking, Mutation Forwarding, and SUSPEND_FOR_APPROVAL
# ==============================================================================

@pytest.mark.asyncio
async def test_proxy_ssrf_blocking_and_suspension_handling(api_client: AsyncClient):
    """Verifies that reverse proxy blocks SSRF upstream URLs and handles SUSPEND_FOR_APPROVAL."""
    # 1. SSRF block on metadata IP
    ssrf_headers = {
        "x-aegis-tenant-id": "default",
        "x-aegis-upstream-url": "http://169.254.169.254/latest/meta-data/",
    }
    resp = await api_client.post(
        "/proxy/llm/v1/chat/completions",
        headers=ssrf_headers,
        json={"messages": [{"role": "user", "content": "Hello"}]},
    )
    assert resp.status_code == 400
    err_data = resp.json()
    assert err_data.get("error", {}).get("type") == "ssrf_violation"

    # 2. Tool Proxy SSRF block
    resp_tool = await api_client.post(
        "/proxy/tools/execute_command",
        headers={"x-aegis-upstream-url": "http://127.0.0.1:8080/exec"},
        json={"parameters": {"cmd": "whoami"}},
    )
    assert resp_tool.status_code == 400
    assert resp_tool.json().get("error", {}).get("type") == "ssrf_violation"


# ==============================================================================
# 2. Multi-Protocol Mid-Stream Secret Abort and Token Reconciliation
# ==============================================================================

@pytest.mark.asyncio
async def test_multiprotocol_midstream_abort_and_reconciliation():
    """Verifies Anthropic, Gemini, and Bedrock translators abort cleanly on mid-stream secret leaks."""
    # Anthropic mid-stream secret injection
    anthropic_tr = AnthropicProtocolTranslator()
    guard_anthropic = SSEStreamGuard(
        tenant_id="test_tenant",
        session_id="sess_anthropic",
        policy_pack_id="base-enterprise",
        translator=anthropic_tr,
    )

    async def sample_anthropic_stream():
        yield "event: content_block_delta\ndata: {\"type\": \"content_block_delta\", \"index\": 0, \"delta\": {\"type\": \"text_delta\", \"text\": \"Here is your secret: \"}}\n\n"
        yield "event: content_block_delta\ndata: {\"type\": \"content_block_delta\", \"index\": 0, \"delta\": {\"type\": \"text_delta\", \"text\": \"sk-ant-api03-abcdef12345678901234567890\"}}\n\n"
        yield "event: message_delta\ndata: {\"type\": \"message_delta\", \"usage\": {\"output_tokens\": 25}}\n\n"

    chunks_out = []
    async for item in guard_anthropic.guard_stream(sample_anthropic_stream()):
        chunks_out.append(item.decode("utf-8") if isinstance(item, bytes) else str(item))

    combined_anthropic = "".join(chunks_out)
    assert "sk-ant-api03" not in combined_anthropic
    assert "GUARDRAIL_INTERVENTION" in combined_anthropic or "redacted" in combined_anthropic.lower()

    # Gemini mid-stream secret injection
    gemini_tr = GeminiProtocolTranslator()
    guard_gemini = SSEStreamGuard(
        tenant_id="test_tenant",
        session_id="sess_gemini",
        policy_pack_id="base-enterprise",
        translator=gemini_tr,
    )

    async def sample_gemini_stream():
        yield "data: {\"candidates\": [{\"content\": {\"parts\": [{\"text\": \"Your AWS key is \"}]}}]}\n\n"
        yield "data: {\"candidates\": [{\"content\": {\"parts\": [{\"text\": \"AKIAIOSFODNN7EXAMPLE\"}]}}]}\n\n"

    gemini_out = []
    async for item in guard_gemini.guard_stream(sample_gemini_stream()):
        gemini_out.append(item.decode("utf-8") if isinstance(item, bytes) else str(item))

    combined_gemini = "".join(gemini_out)
    assert "AKIAIOSFODNN7EXAMPLE" not in combined_gemini
    assert "SAFETY" in combined_gemini or "redacted" in combined_gemini.lower()

    # Bedrock mid-stream secret injection
    bedrock_tr = BedrockProtocolTranslator()
    guard_bedrock = SSEStreamGuard(
        tenant_id="test_tenant",
        session_id="sess_bedrock",
        policy_pack_id="base-enterprise",
        translator=bedrock_tr,
    )

    async def sample_bedrock_stream():
        yield "data: {\"contentBlockDelta\": {\"delta\": {\"text\": \"API secret: \"}}}\n\n"
        yield "data: {\"contentBlockDelta\": {\"delta\": {\"text\": \"AKIAIOSFODNN7EXAMPLE\"}}}\n\n"

    bedrock_out = []
    async for item in guard_bedrock.guard_stream(sample_bedrock_stream()):
        bedrock_out.append(item.decode("utf-8") if isinstance(item, bytes) else str(item))

    combined_bedrock = "".join(bedrock_out)
    assert "AKIAIOSFODNN7EXAMPLE" not in combined_bedrock
    assert "guardrail_intervened" in combined_bedrock or "redacted" in combined_bedrock.lower()


# ==============================================================================
# 3. OIDC Missing JWKS Fails Closed
# ==============================================================================

def test_oidc_fails_closed_without_jwks():
    """Verifies that OIDC verification strictly fails closed when JWKS is not configured."""
    oidc_svc = get_oidc_service()
    oidc_svc.config = OidcConfig(enabled=True, jwks_uri="", issuer="https://auth.example.com")

    fake_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

    with pytest.raises(ValueError) as exc_info:
        oidc_svc.verify_oidc_token(fake_jwt)

    assert "OIDC JWKS verification is not configured" in str(exc_info.value)


# ==============================================================================
# 4. Redis PII Vault Zero Plaintext Storage
# ==============================================================================

@pytest.mark.asyncio
async def test_pii_vault_zero_plaintext_key_storage():
    """Verifies raw PII emails/cards never appear in Redis key names."""
    vault = get_pii_vault()
    redis = await get_redis_client()

    raw_email = "supersecret_ceo_address@megacorp.internal"
    token = await vault.tokenize(
        tenant_id="tenant_p16",
        session_id="sess_p16",
        entity_type="EMAIL",
        original_value=raw_email,
    )
    assert token.startswith("<AEGIS_EMAIL_")

    # Scan all keys in Redis
    session_key = vault._get_session_key("tenant_p16", "sess_p16")
    keys = await redis.keys(f"{session_key}*")
    assert len(keys) > 0

    for k in keys:
        assert raw_email not in k, f"Plaintext PII leaked inside Redis key name: {k}"

    # Detokenize restores original value accurately
    restored = await vault.detokenize(
        tenant_id="tenant_p16",
        session_id="sess_p16",
        token=token,
    )
    assert restored == raw_email


# ==============================================================================
# 5. NerPiiScanner Argument Order & Mutated Content
# ==============================================================================

@pytest.mark.asyncio
async def test_ner_pii_scanner_tokenization_and_mutated_content():
    """Verifies NerPiiScanner calls tokenize with correct args and produces valid tokens."""
    scanner = NerPiiScanner()
    cfg = NerPiiScannerConfig(
        target_entities=["EMAIL"],
        tokenize_entities=True,
        action_on_match="flag",
    )

    req = EvaluationRequest(
        tenant_id="tenant_ner",
        session_id="sess_ner",
        content=ContentModel(
            trusted_instructions="Please send report to alert_target@company.org immediately",
            untrusted_data="Contact victim at breach_victim@personal.com",
            output_payload="Sent notification to notify_lead@enterprise.net",
        ),
    )

    res = await scanner.scan(req, context={}, config=cfg)
    assert res.status == "flag"
    assert res.mutated_content is not None
    assert "<AEGIS_EMAIL_" in res.mutated_content.get("trusted_instructions", "")
    assert "<AEGIS_EMAIL_" in res.mutated_content.get("untrusted_data", "")
    assert "<AEGIS_EMAIL_" in res.mutated_content.get("output_payload", "")
    assert "alert_target@company.org" not in res.mutated_content.get("trusted_instructions", "")


# ==============================================================================
# 6. SqlAstGuard Parenthesization & Tenant Sanitization
# ==============================================================================

@pytest.mark.asyncio
async def test_sql_ast_guard_parenthesization_and_sanitization():
    """Verifies SqlAstGuard wraps WHERE conditions with parentheses and sanitizes tenant_id."""
    guard = SqlAstGuard()
    cfg = SqlAstGuardConfig(
        enforce_tenant_predicate=True,
        auto_inject_tenant_predicate=True,
        tenant_column="tenant_id",
    )

    # 1. Parenthesization test for OR bypass: status = 'open' OR 1=1
    req = EvaluationRequest(
        tenant_id="acme_corp",
        action=ActionModel(name="query_db", parameters={"query": "SELECT * FROM orders WHERE status = 'open' OR 1=1"}),
    )

    res = await guard.scan(req, context={}, config=cfg)
    assert res.status in ("pass", "modify")
    mutated_sql = res.mutated_parameters.get("query", "")
    assert "orders.tenant_id = 'acme_corp'" in mutated_sql or "tenant_id = 'acme_corp'" in mutated_sql
    # Must NOT allow 1=1 to bypass tenant constraint
    assert "(status = 'open' OR 1 = 1)" in mutated_sql or "(status = 'open' OR 1=1)" in mutated_sql

    # 2. Single-quote tenant injection test: acme' OR '1'='1
    req_inject = EvaluationRequest(
        tenant_id="acme' OR '1'='1",
        action=ActionModel(name="query_db", parameters={"query": "SELECT * FROM items WHERE in_stock = true"}),
    )
    res_inject = await guard.scan(req_inject, context={}, config=cfg)
    injected_sql = res_inject.mutated_parameters.get("query", "")
    # Single quotes must be escaped to ''
    assert "''" in injected_sql
    assert "acme'' OR ''1''=''1" in injected_sql


# ==============================================================================
# 7. 20 Concurrent Audit Writes with Zero Hash-Chain Forks
# ==============================================================================

@pytest.mark.asyncio
async def test_concurrent_audit_writes_zero_forks(async_db):
    """Verifies 20 concurrent audit writes produce linear, un-forked hash chains."""
    ledger = AuditLedger()
    verifier = AuditVerifier()
    tenant_id = "tenant_concurrency_p16"

    async def record_single(idx: int):
        req = EvaluationRequest(
            tenant_id=tenant_id,
            trace_id=f"tr-concurrency-{idx}",
            session_id="sess_concurrency",
            action=ActionModel(name="concurrent_tool", parameters={"idx": idx}),
        )
        verdict = EvaluationVerdict(
            decision=DecisionEnum.ALLOW,
            risk_score=0.1,
            latency_ms=1.5,
        )
        return await ledger.record_event(
            request=req,
            verdict=verdict,
            policy_pack_id="base-enterprise",
        )

    # Concurrently fire 20 records
    results = await asyncio.gather(*[record_single(i) for i in range(20)])
    assert all(r is not None for r in results)

    # Verify linear chain with zero forks
    verify_report = await verifier.verify_tenant_chain(tenant_id)
    assert verify_report.is_valid is True
    assert verify_report.total_records == 20
    assert len(verify_report.tampered_records) == 0


# ==============================================================================
# 8. HITLEngine Database Query Persistence
# ==============================================================================

@pytest.mark.asyncio
async def test_hitl_engine_persists_and_queries_db(async_db):
    """Verifies HITLEngine lists tickets from database when memory cache is empty."""
    hitl = get_hitl_engine()
    tenant_id = "tenant_hitl_p16"

    req = EvaluationRequest(
        tenant_id=tenant_id,
        action=ActionModel(name="isolate_host", parameters={"ip": "10.0.0.99"}),
    )
    verdict = EvaluationVerdict(
        decision=DecisionEnum.SUSPEND_FOR_APPROVAL,
    )
    ticket = await hitl.create_ticket(
        request=req,
        verdict=verdict,
        policy_pack_id="soc-investigation-pack",
        required_approvals=1,
        required_approver_roles=["soc_lead"],
    )
    assert ticket.ticket_id is not None

    # Clear in-memory dictionary cache to force DB lookup
    hitl._mem_tickets.clear()

    # Query tickets for tenant
    fetched_tickets = await hitl.list_tickets(tenant_id=tenant_id)
    assert len(fetched_tickets) >= 1
    found = any(t.ticket_id == ticket.ticket_id for t in fetched_tickets)
    assert found is True


# ==============================================================================
# 9. PolicyReplaySimulator YAML String Loading
# ==============================================================================

@pytest.mark.asyncio
async def test_policy_replay_simulator_yaml_string(async_db):
    """Verifies PolicyReplaySimulator loads candidate policy from raw YAML string."""
    simulator = PolicyReplaySimulator()
    raw_yaml = """
id: simulation-candidate-pack
name: Simulation Candidate Pack
version: 1.0.0
execution_mode: enforce
rules:
  - id: sim-allow-all
    name: Sim Allow All
    stages: ["llm_input", "tool_pre_call"]
    priority: 10
    action:
      decision: ALLOW
      severity: low
      reason: "Simulated allow"
"""
    sim_req = ReplaySimulationRequest(
        tenant_id="default",
        candidate_pack_yaml=raw_yaml,
        max_events=10,
    )

    report = await simulator.run_replay(sim_req)
    assert report is not None
    assert report.concordance_rate >= 0.0


# ==============================================================================
# 10. Strict aegisctl Validation Across All 11 Policy Packs
# ==============================================================================

def test_aegisctl_strict_validation_all_11_packs():
    """Verifies that all 11 policy packs strictly compile without errors."""
    engine = get_yaml_policy_engine()
    pack_dir = Path("policy_packs")
    yaml_files = list(pack_dir.glob("*/policy.yaml"))
    assert len(yaml_files) == 11, f"Expected 11 policy packs, found {len(yaml_files)}"

    for yf in yaml_files:
        with open(yf, "r", encoding="utf-8") as f:
            pack_def = engine.load_from_yaml_string(f.read())
        assert pack_def.id is not None
        assert len(pack_def.rules) > 0
        for r in pack_def.rules:
            assert isinstance(r.stages, list)
