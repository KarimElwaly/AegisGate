import asyncio
import datetime
import json
import pytest
from core.audit.exporter import ComplianceAuditExporter
from core.audit.ledger import AuditLedger, GENESIS_HASH, canonical_json, compute_sha256
from core.audit.verifier import AuditVerifier
from core.hitl.engine import HITLEngine
from core.hitl.schemas import ApprovalDecisionRequest
from core.models.audit import AuditRecord
from core.schemas.common import DecisionEnum, StageEnum
from core.schemas.events import ActionModel, ActorModel, ContentModel, EvaluationRequest
from core.schemas.verdicts import EvaluationVerdict, TriggeredRule
from plugins.notifiers.slack_notifier import SlackNotifier, SlackNotifierConfig
from plugins.notifiers.siem_cef_notifier import SiemCefNotifier, SiemCefNotifierConfig
from plugins.notifiers.webhook_notifier import WebhookNotifier, WebhookNotifierConfig


@pytest.mark.asyncio
async def test_hitl_engine_single_and_dual_approval():
    engine = HITLEngine()

    req = EvaluationRequest(
        tenant_id="tenant-hitl",
        trace_id="trace-hitl-01",
        stage=StageEnum.TOOL_PRE_CALL,
        actor=ActorModel(id="agent-01", role="soc_agent"),
        action=ActionModel(name="isolate_host", parameters={"hostname": "server-tier0", "duration_hours": 24}),
    )

    verdict = EvaluationVerdict(
        decision=DecisionEnum.SUSPEND_FOR_APPROVAL,
        risk_score=0.9,
        triggered_rules=[
            TriggeredRule(
                rule_id="soc-dual-approval",
                policy_pack="soc-investigation-pack",
                policy_version="1.0.0",
                reason="Dual approval required for tier0 host isolation",
                compliance_tags=["SOC2-CC6.3"],
            )
        ],
        latency_ms=1.2,
    )

    # 1. Create dual-approval ticket
    ticket = await engine.create_ticket(
        request=req,
        verdict=verdict,
        policy_pack_id="soc-investigation-pack",
        required_approvals=2,
        required_approver_roles=["security_lead", "soc_manager"],
        ttl_seconds=300,
    )

    assert ticket.ticket_id is not None
    assert ticket.status == "pending"
    assert ticket.required_approvals == 2
    assert ticket.action_name == "isolate_host"

    # 2. Unauthorized role rejected
    with pytest.raises(PermissionError):
        await engine.decide_ticket(
            ticket.ticket_id,
            ApprovalDecisionRequest(
                approver_id="junior-analyst",
                approver_role="junior_analyst",
                decision="approve",
            ),
        )

    # 3. First approver authorizes with parameter override
    updated_1 = await engine.decide_ticket(
        ticket.ticket_id,
        ApprovalDecisionRequest(
            approver_id="lead-alice",
            approver_role="security_lead",
            decision="approve",
            parameter_override={"hostname": "server-tier0", "duration_hours": 4},
            decision_notes="Approved with reduced isolation window to 4 hours.",
        ),
    )
    assert updated_1.status == "pending"  # Needs second approver
    assert updated_1.approved_by == ["lead-alice"]
    assert updated_1.modified_parameters == {"hostname": "server-tier0", "duration_hours": 4}

    # 4. Same approver cannot approve twice
    with pytest.raises(ValueError, match="already approved"):
        await engine.decide_ticket(
            ticket.ticket_id,
            ApprovalDecisionRequest(
                approver_id="lead-alice",
                approver_role="security_lead",
                decision="approve",
            ),
        )

    # 5. Second distinct approver authorizes -> ticket finalized
    updated_2 = await engine.decide_ticket(
        ticket.ticket_id,
        ApprovalDecisionRequest(
            approver_id="manager-bob",
            approver_role="soc_manager",
            decision="approve",
            decision_notes="Confirmed second eyes approval.",
        ),
    )
    assert updated_2.status == "approved"
    assert len(updated_2.approved_by) == 2
    assert updated_2.modified_parameters == {"hostname": "server-tier0", "duration_hours": 4}


@pytest.mark.asyncio
async def test_hitl_ticket_rejection():
    engine = HITLEngine()
    req = EvaluationRequest(
        tenant_id="tenant-hitl",
        trace_id="trace-hitl-02",
        stage=StageEnum.TOOL_PRE_CALL,
        actor=ActorModel(id="agent-01", role="soc_agent"),
        action=ActionModel(name="block_ip", parameters={"ip": "1.2.3.4"}),
    )
    verdict = EvaluationVerdict(decision=DecisionEnum.SUSPEND_FOR_APPROVAL, risk_score=0.7)

    ticket = await engine.create_ticket(request=req, verdict=verdict, policy_pack_id="soc-investigation-pack")
    assert ticket.status == "pending"

    decided = await engine.decide_ticket(
        ticket.ticket_id,
        ApprovalDecisionRequest(
            approver_id="analyst-carol",
            approver_role="security_lead",
            decision="reject",
            decision_notes="Suspected false positive alert.",
        ),
    )
    assert decided.status == "rejected"
    assert decided.rejected_by == "analyst-carol"
    assert decided.decision_notes == "Suspected false positive alert."


@pytest.mark.asyncio
async def test_audit_hash_chain_verification_and_tamper_detection(async_db):
    ledger = AuditLedger()
    verifier = AuditVerifier()
    tenant = "audit-crypto-test"

    # Record 3 events
    recs = []
    for i in range(3):
        req = EvaluationRequest(
            tenant_id=tenant,
            trace_id=f"trace-crypto-{i}",
            stage=StageEnum.LLM_INPUT,
            actor=ActorModel(id=f"user-{i}", role="analyst"),
            action=ActionModel(name="test_action", parameters={"index": i}),
        )
        verdict = EvaluationVerdict(
            decision=DecisionEnum.ALLOW if i < 2 else DecisionEnum.DENY,
            risk_score=0.1 * i,
            triggered_rules=[
                TriggeredRule(
                    rule_id=f"rule-{i}",
                    policy_pack="test-pack",
                    policy_version="1.0.0",
                    reason="Test rule",
                    compliance_tags=["OWASP-LLM01", "SOC2-CC6.1"],
                )
            ],
            latency_ms=1.5,
        )
        rec = await ledger.record_event(
            request=req,
            verdict=verdict,
            policy_pack_id="test-pack",
            compliance_tags=["OWASP-LLM01", "SOC2-CC6.1"],
        )
        recs.append(rec)

    # 1. Verification of legitimate chain passes
    result = await verifier.verify_tenant_chain(tenant)
    assert result.is_valid is True
    assert result.total_records >= 3
    assert len(result.tampered_records) == 0

    # 2. Tampering test: simulate illicit modification of record payload
    tampered_rec = recs[1]
    original_decision = tampered_rec.decision
    tampered_rec.decision = "DENY" if original_decision == "ALLOW" else "ALLOW"

    # Expected recomputed hash will not match stored record_hash
    recomputed = verifier.recompute_record_hash(tampered_rec)
    assert recomputed != tampered_rec.record_hash, "Tampered payload must produce differing hash"

    # Restore
    tampered_rec.decision = original_decision


@pytest.mark.asyncio
async def test_compliance_exporter(async_db):
    ledger = AuditLedger()
    exporter = ComplianceAuditExporter()
    tenant = "audit-export-tenant"

    req = EvaluationRequest(
        tenant_id=tenant,
        trace_id="trace-exp-01",
        stage=StageEnum.LLM_INPUT,
        actor=ActorModel(id="user-1", role="analyst"),
        action=ActionModel(name="test_action", parameters={"index": 1}),
    )
    verdict = EvaluationVerdict(
        decision=DecisionEnum.DENY,
        risk_score=0.9,
        triggered_rules=[
            TriggeredRule(
                rule_id="rule-soc2",
                policy_pack="test-pack",
                policy_version="1.0.0",
                reason="Test rule",
                compliance_tags=["SOC2", "OWASP-LLM01"],
            )
        ],
        latency_ms=1.5,
    )
    await ledger.record_event(
        request=req,
        verdict=verdict,
        policy_pack_id="test-pack",
        compliance_tags=["SOC2", "OWASP-LLM01"],
    )

    # Export JSONL
    jsonl_output = await exporter.export(tenant_id=tenant, export_format="jsonl", compliance_tag="SOC2")
    assert len(jsonl_output.strip()) > 0
    lines = jsonl_output.strip().split("\n")
    assert len(lines) >= 1
    parsed_first = json.loads(lines[0])
    assert "record_hash" in parsed_first
    assert "prev_hash" in parsed_first

    # Export CSV
    csv_output = await exporter.export(tenant_id=tenant, export_format="csv")
    assert "record_hash" in csv_output
    assert "prev_hash" in csv_output


@pytest.mark.asyncio
async def test_notifier_plugins():
    # 1. SiemCefNotifier
    siem = SiemCefNotifier()
    cef_msg = siem.format_cef(
        event_type="policy_violation",
        payload={
            "tenant_id": "corp-tenant",
            "trace_id": "tr-999",
            "decision": "DENY",
            "action": {"name": "rm_rf"},
            "risk_score": 0.95,
        },
    )
    assert "CEF:0|AegisGate|PDP|1.0|policy_violation|PolicyDecision|10|" in cef_msg
    assert "src=corp-tenant" in cef_msg
    assert "act=rm_rf" in cef_msg

    res_siem = await siem.notify("policy_violation", {"decision": "DENY"}, SiemCefNotifierConfig())
    assert res_siem is True

    # 2. SlackNotifier (handles network error gracefully)
    slack = SlackNotifier()
    res_slack = await slack.notify(
        "policy_violation",
        {"decision": "DENY", "trace_id": "tr-123", "risk_score": 0.8},
        SlackNotifierConfig(webhook_url="http://localhost:59999/slack-test"),
    )
    assert res_slack is False  # Safe fail-open / no unhandled crash

    # 3. WebhookNotifier (handles network error gracefully)
    webhook = WebhookNotifier()
    res_wh = await webhook.notify(
        "hitl_alert",
        {"ticket_id": "tick-123"},
        WebhookNotifierConfig(endpoint_url="http://localhost:59999/wh-test", secret="secret123"),
    )
    assert res_wh is False
