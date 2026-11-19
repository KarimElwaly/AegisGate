import uuid

from core.schemas.common import DecisionEnum, EffectiveModeEnum, StageEnum
from core.schemas.events import ActionModel, ActorModel, ContentModel, EvaluationRequest
from core.schemas.policy import ConditionExpression, PolicyPackDefinition, PolicyRule, RuleAction
from core.schemas.verdicts import EvaluationVerdict, ScannerFinding, TriggeredRule


def test_canonical_evaluation_request():
    req = EvaluationRequest(
        tenant_id="tenant-alpha",
        workspace_id="ws-main",
        environment="prod",
        policy_pack_id="base-enterprise",
        stage=StageEnum.LLM_INPUT,
        actor=ActorModel(id="agent-01", role="analyst"),
        action=ActionModel(name="query_db", parameters={"query": "SELECT 1"}),
        content=ContentModel(trusted_instructions="Summarize logs", untrusted_data="raw logs here"),
    )

    assert req.tenant_id == "tenant-alpha"
    assert req.stage == StageEnum.LLM_INPUT
    assert req.actor.id == "agent-01"
    assert req.action.parameters["query"] == "SELECT 1"
    assert uuid.UUID(req.request_id)
    assert uuid.UUID(req.trace_id)


def test_canonical_evaluation_verdict():
    verdict = EvaluationVerdict(
        decision=DecisionEnum.DENY,
        effective_mode=EffectiveModeEnum.ENFORCE,
        would_have_decided=DecisionEnum.DENY,
        risk_score=0.9,
        triggered_rules=[
            TriggeredRule(
                rule_id="r1",
                policy_pack="base-enterprise",
                policy_version="1.0.0",
                severity="critical",
                reason="Secret leak",
                compliance_tags=["OWASP-LLM06"],
            )
        ],
        scanner_findings=[
            ScannerFinding(
                scanner_name="secrets_scanner",
                tier=1,
                status="block",
                score=1.0,
                message="Found AWS key",
            )
        ],
        latency_ms=4.2,
    )

    assert verdict.decision == DecisionEnum.DENY
    assert verdict.risk_score == 0.9
    assert len(verdict.triggered_rules) == 1
    assert verdict.triggered_rules[0].compliance_tags == ["OWASP-LLM06"]
    assert verdict.latency_ms == 4.2


def test_policy_pack_definition():
    rule = PolicyRule(
        id="rule-deny-root",
        name="Deny Root Actor",
        priority=1,
        condition=ConditionExpression(field="actor.role", operator="eq", value="root"),
        action=RuleAction(decision="DENY", severity="critical", reason="Root access blocked"),
    )
    pack = PolicyPackDefinition(
        id="custom-pack",
        name="Custom Policy",
        version="2.0.0",
        rules=[rule],
    )

    assert pack.id == "custom-pack"
    assert len(pack.rules) == 1
    assert pack.rules[0].condition.field == "actor.role"

