import json
import httpx
import pytest

from core.audit.ledger import AuditLedger
from core.audit.verifier import AuditVerifier
from core.crypto.kms import (
    AWSKMSKeyProvider,
    HashiCorpVaultKeyProvider,
    LocalEnvKeyProvider,
    set_key_provider,
)
from core.database import db_context
from core.pii_vault.vault import PiiVault
from core.schemas.common import DecisionEnum, StageEnum
from core.schemas.events import ActionModel, ActorModel, ContentModel, EvaluationRequest
from core.schemas.verdicts import EvaluationVerdict
from gateways.pdp_api.main import app
from sdks.python.aegisgate.client import AegisClient
from sdks.python.aegisgate.adapters.crewai_guard import CrewAIGuard
from sdks.python.aegisgate.adapters.llamaindex_guard import LlamaIndexGuard


def test_local_kms_envelope_encryption_and_rotation():
    kms = LocalEnvKeyProvider(active_version="v1")
    plaintext = "Sensitive Cardholder Number: 4111-2222-3333-4444"

    # 1. Encrypt with v1
    payload_v1 = kms.encrypt_dek(plaintext)
    assert payload_v1["version"] == "v1"
    assert payload_v1["ciphertext"] != plaintext

    # 2. Decrypt with v1
    decrypted_v1 = kms.decrypt_dek(payload_v1)
    assert decrypted_v1 == plaintext

    # 3. Rotate key to v2
    kms.rotate_key("v2")
    assert kms.current_key_version() == "v2"

    # Encrypt new payload with v2
    payload_v2 = kms.encrypt_dek(plaintext)
    assert payload_v2["version"] == "v2"

    # Both v1 and v2 decrypt successfully
    assert kms.decrypt_dek(payload_v1) == plaintext
    assert kms.decrypt_dek(payload_v2) == plaintext

    # 4. HMAC Sign and Verify
    sig = kms.sign_hmac(plaintext)
    assert sig.startswith("v2:")
    assert kms.verify_hmac(plaintext, sig) is True
    assert kms.verify_hmac("tampered data", sig) is False
    assert kms.verify_hmac(plaintext, "v2:bad_signature") is False


def test_hashicorp_and_aws_kms_providers():
    vault_kms = HashiCorpVaultKeyProvider()
    aws_kms = AWSKMSKeyProvider()

    assert vault_kms.current_key_version() == "vault-v1"
    assert aws_kms.current_key_version() == "aws-kms-v1"

    text = "Secret Data"
    enc = vault_kms.encrypt_dek(text)
    assert vault_kms.decrypt_dek(enc) == text
    sig = aws_kms.sign_hmac(text)
    assert aws_kms.verify_hmac(text, sig) is True


@pytest.mark.asyncio
async def test_kms_backed_pii_vault():
    kms = LocalEnvKeyProvider(active_version="vault-key-1")
    set_key_provider(kms)

    vault = PiiVault()
    tenant_id = "test-kms-tenant"
    session_id = "test-session-kms"

    token = await vault.tokenize(tenant_id, session_id, "EMAIL", "patient@clinic.internal")
    assert "<AEGIS_EMAIL_" in token

    # Rehydrate
    rehydrated = await vault.rehydrate(tenant_id, session_id, f"Results sent to {token}")
    assert rehydrated == "Results sent to patient@clinic.internal"


@pytest.mark.asyncio
async def test_kms_audit_signing_and_verification(async_db):
    kms = LocalEnvKeyProvider(active_version="audit-key-1")
    set_key_provider(kms)

    tenant_id = "test-audit-kms-tenant"
    async with db_context() as session:
        ledger = AuditLedger(session)
        req = EvaluationRequest(
            tenant_id=tenant_id,
            workspace_id="default",
            stage=StageEnum.LLM_INPUT,
            actor=ActorModel(id="auditor-1"),
            action=ActionModel(name="query"),
            content=ContentModel(untrusted_data="test audit"),
        )
        verdict = EvaluationVerdict(
            verdict_id="verdict-kms-1",
            decision=DecisionEnum.ALLOW,
            latency_ms=1.5,
        )
        record = await ledger.record_event(req, verdict, policy_pack_id="base-enterprise", db_session=session)
        assert record.kms_signature is not None
        assert record.kms_signature.startswith("audit-key-1:")

        # Verify chain with signature check
        verifier = AuditVerifier()
        result = await verifier.verify_tenant_chain(tenant_id, db_session=session)
        assert result.is_valid is True
        assert result.total_records >= 1


@pytest.mark.asyncio
async def test_regulatory_compliance_report_endpoint(api_client):
    # Test JSON format
    resp = await api_client.get("/v1/audit/compliance-report?framework=eu-ai-act&format=json&tenant_id=default")
    assert resp.status_code == 200
    data = resp.json()

    assert data["framework"] == "eu-ai-act"
    assert "report_id" in data
    assert "hash_chain_certificate" in data
    assert data["hash_chain_certificate"]["status"] in ("VERIFIED_UNBROKEN", "TAMPERED")
    assert "enforcement_summary" in data

    # Test Markdown format
    resp_md = await api_client.get("/v1/audit/compliance-report?framework=hipaa&format=markdown&tenant_id=default")
    assert resp_md.status_code == 200
    assert "text/markdown" in resp_md.headers["content-type"]
    assert "# AegisGate Regulatory Compliance Audit Report" in resp_md.text
    assert "HIPAA" in resp_md.text


@pytest.mark.asyncio
async def test_crewai_guard_adapter(async_db):
    client = AegisClient(base_url="http://testserver", transport=httpx.ASGITransport(app=app))
    guard = CrewAIGuard(client=client, policy_pack_id="base-enterprise", agent_role="analyst")

    # Clean tool
    def clean_tool(query: str):
        return f"Results for: {query}"

    governed_tool = guard.wrap_tool(clean_tool, tool_name="search_database")
    res = governed_tool(query="quarterly revenue")
    assert "Results for: quarterly revenue" in res

    # Async tool
    async def async_calc(x: int, y: int):
        return x + y

    governed_async = guard.wrap_tool(async_calc, tool_name="calculator")
    calc_res = await governed_async(x=10, y=20)
    assert calc_res == 30


@pytest.mark.asyncio
async def test_llamaindex_guard_adapter(async_db):
    client = AegisClient(base_url="http://testserver", transport=httpx.ASGITransport(app=app))
    guard = LlamaIndexGuard(client=client, policy_pack_id="rag-copilot-pack", actor_role="internal")

    class MockNode:
        def __init__(self, text: str, metadata: dict):
            self.text = text
            self.metadata = metadata

    nodes = [
        MockNode("Public internal guidelines", {"clearance": "internal"}),
        MockNode("Top secret launch keys", {"clearance": "top_secret"}),
    ]

    # Post-retrieval clearance filter should remove the top_secret node for internal role
    filtered = await guard.post_retrieval_filter(nodes, query_str="company docs")
    assert len(filtered) == 1
    assert filtered[0].text == "Public internal guidelines"

    # Post-response guard
    ans = await guard.post_response_guard("The company guidelines are accessible to all internal staff.")
    assert "company guidelines" in ans
