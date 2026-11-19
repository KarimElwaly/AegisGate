import pytest

from core.policy_engine.yaml_engine import YamlPolicyEngine
from core.schemas.common import DecisionEnum
from core.schemas.events import ActionModel, ActorModel, EvaluationRequest
from core.schemas.policy import ConditionExpression, PolicyPackDefinition, PolicyRule, RuleAction


@pytest.mark.asyncio
async def test_yaml_engine_rule_evaluation():
    engine = YamlPolicyEngine()

    rule1 = PolicyRule(
        id="block-containment-root",
        priority=10,
        condition=ConditionExpression(
            all=[
                ConditionExpression(field="action.name", operator="in", value=["isolate_host", "disable_user"]),
                ConditionExpression(field="actor.role", operator="neq", value="soc_lead"),
            ]
        ),
        action=RuleAction(
            decision="DENY",
            severity="critical",
            reason="Only soc_lead can execute containment actions",
        ),
    )

    pack = PolicyPackDefinition(
        id="test-pack",
        name="Test Pack",
        rules=[rule1],
    )
    engine.register_policy_pack(pack)

    # Actor is junior_analyst -> blocked
    req_blocked = EvaluationRequest(
        actor=ActorModel(id="u1", role="junior_analyst"),
        action=ActionModel(name="isolate_host", parameters={"target": "10.0.1.5"}),
    )
    decision, risk, triggered, mutations = await engine.evaluate(
        request=req_blocked,
        scanner_findings=[],
        resolved_context={},
        policy_pack=pack,
    )
    assert decision == DecisionEnum.DENY
    assert risk == 1.0
    assert len(triggered) == 1
    assert triggered[0].rule_id == "block-containment-root"

    # Actor is soc_lead -> allowed
    req_allowed = EvaluationRequest(
        actor=ActorModel(id="u2", role="soc_lead"),
        action=ActionModel(name="isolate_host", parameters={"target": "10.0.1.5"}),
    )
    decision2, risk2, triggered2, mutations2 = await engine.evaluate(
        request=req_allowed,
        scanner_findings=[],
        resolved_context={},
        policy_pack=pack,
    )
    assert decision2 == DecisionEnum.ALLOW
    assert len(triggered2) == 0


@pytest.mark.asyncio
async def test_yaml_engine_inheritance():
    engine = YamlPolicyEngine()

    parent_pack = PolicyPackDefinition(
        id="parent-base",
        name="Parent Base",
        version="1.0.0",
        rules=[
            PolicyRule(
                id="base-rule-1",
                priority=100,
                condition=ConditionExpression(field="stage", operator="eq", value="memory_write"),
                action=RuleAction(decision="DENY", reason="No memory writes allowed"),
            )
        ],
    )
    engine.register_policy_pack(parent_pack)

    child_pack = PolicyPackDefinition(
        id="child-sub",
        name="Child Sub",
        version="1.1.0",
        extends="parent-base",
        rules=[
            PolicyRule(
                id="child-rule-1",
                priority=10,
                condition=ConditionExpression(field="actor.role", operator="eq", value="guest"),
                action=RuleAction(decision="DENY", reason="Guest blocked"),
            )
        ],
    )
    engine.register_policy_pack(child_pack)

    resolved = engine.resolve_inheritance(child_pack)
    assert len(resolved.rules) == 2
    # Check rule priority ordering: priority 10 before priority 100
    assert resolved.rules[0].id == "child-rule-1"
    assert resolved.rules[1].id == "base-rule-1"

