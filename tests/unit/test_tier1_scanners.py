import pytest
from plugins.scanners.tier1_deterministic.entropy_size_guard import (
    EntropySizeGuard,
    EntropySizeGuardConfig,
)
from plugins.scanners.tier1_deterministic.grounding_scanner import (
    EvidenceGroundingConfig,
    EvidenceGroundingScanner,
)
from plugins.scanners.tier1_deterministic.json_schema_scanner import (
    JsonSchemaScanner,
    JsonSchemaScannerConfig,
)
from plugins.scanners.tier1_deterministic.pii_scanner import (
    PiiScanner,
    PiiScannerConfig,
)
from plugins.scanners.tier1_deterministic.secrets_scanner import (
    SecretsScanner,
    SecretsScannerConfig,
)
from plugins.scanners.tier1_deterministic.tool_param_guard import (
    ToolParamGuard,
    ToolParamGuardConfig,
)
from plugins.scanners.webhook_scanner import (
    WebhookScanner,
    WebhookScannerConfig,
)
from core.schemas.events import ActionModel, ContentModel, EvaluationRequest


@pytest.mark.asyncio
async def test_secrets_scanner_detects_aws_and_jwt():
    scanner = SecretsScanner()
    cfg = SecretsScannerConfig(action_on_match="block")

    # Clean request
    req_clean = EvaluationRequest(
        content=ContentModel(trusted_instructions="Summarize system health")
    )
    res_clean = await scanner.scan(req_clean, {}, cfg)
    assert res_clean.status == "pass"

    # AWS Key in input
    req_aws = EvaluationRequest(
        content=ContentModel(trusted_instructions="Use key AKIAIOSFODNN7EXAMPLE to authenticate")
    )
    res_aws = await scanner.scan(req_aws, {}, cfg)
    assert res_aws.status == "block"
    assert res_aws.score == 1.0

    # Masking mode
    cfg_mask = SecretsScannerConfig(action_on_match="mask")
    res_mask = await scanner.scan(req_aws, {}, cfg_mask)
    assert res_mask.status == "flag"
    assert res_mask.mutated_content is not None
    assert "[REDACTED_SECRET]" in res_mask.mutated_content["trusted_instructions"]


@pytest.mark.asyncio
async def test_pii_scanner_reversible_tokenization():
    scanner = PiiScanner()
    cfg = PiiScannerConfig(mode="reversible_tokenize", detect_emails=True, detect_ipv4=True)

    req = EvaluationRequest(
        tenant_id="t1",
        session_id="s1",
        content=ContentModel(
            trusted_instructions="Contact admin@company.com at 192.168.1.10 immediately."
        ),
    )
    res = await scanner.scan(req, {}, cfg)
    assert res.status == "flag"
    assert res.mutated_content is not None
    mutated = res.mutated_content["trusted_instructions"]
    assert "<AEGIS_EMAIL_" in mutated
    assert "<AEGIS_IPV4_" in mutated
    assert "admin@company.com" not in mutated
    assert "192.168.1.10" not in mutated


@pytest.mark.asyncio
async def test_json_schema_scanner():
    scanner = JsonSchemaScanner()
    schema = {
        "type": "object",
        "required": ["report_id", "severity"],
        "properties": {
            "report_id": {"type": "string"},
            "severity": {"type": "string", "enum": ["low", "high"]},
        },
    }
    cfg = JsonSchemaScannerConfig(schema_definition=schema, action_on_error="block")

    # Valid payload
    req_valid = EvaluationRequest(
        content=ContentModel(output_payload={"report_id": "rep-1", "severity": "high"})
    )
    res_valid = await scanner.scan(req_valid, {}, cfg)
    assert res_valid.status == "pass"

    # Invalid payload (missing required field)
    req_invalid = EvaluationRequest(
        content=ContentModel(output_payload={"severity": "high"})
    )
    res_invalid = await scanner.scan(req_invalid, {}, cfg)
    assert res_invalid.status == "block"
    assert "report_id" in res_invalid.message


@pytest.mark.asyncio
async def test_tool_param_guard():
    scanner = ToolParamGuard()
    cfg = ToolParamGuardConfig(
        block_path_traversal=True,
        block_shell_metachars=True,
        enforce_sql_read_only=True,
        protected_ips_or_cidrs=["10.0.0.0/24"],
    )

    # Safe call
    req_safe = EvaluationRequest(
        stage="tool_pre_call",
        action=ActionModel(name="query_db", parameters={"query": "SELECT * FROM users WHERE id=1"}),
    )
    res_safe = await scanner.scan(req_safe, {}, cfg)
    assert res_safe.status == "pass"

    # Path traversal
    req_traversal = EvaluationRequest(
        stage="tool_pre_call",
        action=ActionModel(name="read_file", parameters={"path": "../../etc/passwd"}),
    )
    res_traversal = await scanner.scan(req_traversal, {}, cfg)
    assert res_traversal.status == "block"

    # Shell metacharacters injection
    req_shell = EvaluationRequest(
        stage="tool_pre_call",
        action=ActionModel(name="ping", parameters={"host": "google.com; cat /etc/passwd"}),
    )
    res_shell = await scanner.scan(req_shell, {}, cfg)
    assert res_shell.status == "block"

    # Mutating SQL when read-only enforced
    req_sql = EvaluationRequest(
        stage="tool_pre_call",
        action=ActionModel(name="query_db", parameters={"sql": "DROP TABLE users;"}),
    )
    res_sql = await scanner.scan(req_sql, {}, cfg)
    assert res_sql.status == "block"

    # Targeting protected infrastructure IP
    req_ip = EvaluationRequest(
        stage="tool_pre_call",
        action=ActionModel(name="isolate_host", parameters={"target_ip": "10.0.0.5"}),
    )
    res_ip = await scanner.scan(req_ip, {}, cfg)
    assert res_ip.status == "block"
    assert "protected" in res_ip.message


@pytest.mark.asyncio
async def test_entropy_size_guard():
    scanner = EntropySizeGuard()
    cfg = EntropySizeGuardConfig(
        max_payload_bytes=500,
        check_entropy=True,
        max_shannon_entropy=4.5,
    )

    # Small safe payload
    req_safe = EvaluationRequest(content=ContentModel(trusted_instructions="Normal prompt here."))
    res_safe = await scanner.scan(req_safe, {}, cfg)
    assert res_safe.status == "pass"

    # Payload exceeding max bytes
    req_large = EvaluationRequest(content=ContentModel(untrusted_data="A" * 600))
    res_large = await scanner.scan(req_large, {}, cfg)
    assert res_large.status == "block"

    # High entropy token exfiltration (e.g. encrypted/compressed base64 data)
    high_entropy_token = "K9zXw!8#mQ2$pL0*vR4^yT7&uI1@oB5+zM" * 2
    req_entropy = EvaluationRequest(content=ContentModel(output_payload=high_entropy_token))
    res_entropy = await scanner.scan(req_entropy, {}, cfg)
    assert res_entropy.status == "block"


@pytest.mark.asyncio
async def test_evidence_grounding_scanner():
    scanner = EvidenceGroundingScanner()
    cfg = EvidenceGroundingConfig(action_on_ungrounded="block")

    # Grounded citations
    req_grounded = EvaluationRequest(
        content=ContentModel(
            untrusted_data="Incident alert EVID-9001 on server prod-db-01 observed.",
            citations=["EVID-9001"],
        )
    )
    res_grounded = await scanner.scan(req_grounded, {}, cfg)
    assert res_grounded.status == "pass"

    # Ungrounded hallucinated citation
    req_ungrounded = EvaluationRequest(
        content=ContentModel(
            untrusted_data="Incident alert EVID-9001 on server prod-db-01 observed.",
            citations=["EVID-9001", "HALLUCINATED-EVID-9999"],
        )
    )
    res_ungrounded = await scanner.scan(req_ungrounded, {}, cfg)
    assert res_ungrounded.status == "block"
    assert "HALLUCINATED-EVID-9999" in res_ungrounded.message


@pytest.mark.asyncio
async def test_webhook_scanner_timeout_fallback():
    scanner = WebhookScanner()
    cfg = WebhookScannerConfig(
        endpoint_url="http://non-existent-webhook.local/scan",
        timeout_ms=50,
        on_timeout="flag",
    )

    req = EvaluationRequest(content=ContentModel(trusted_instructions="Test prompt"))
    res = await scanner.scan(req, {}, cfg)
    assert res.status == "flag"
    assert "error" in res.message.lower() or "timeout" in res.message.lower()
