import os
import pytest
from pydantic import BaseModel
from core.config import Settings, get_settings
from core.logger import configure_logging
from core.pii_vault.vault import PiiVault
from core.pipeline.orchestrator import PipelineOrchestrator
from core.policy_engine.yaml_engine import YamlPolicyEngine
from core.registry.interfaces import BaseContextResolver, BaseNotifier, BaseScanner, DefaultPluginConfig, ScannerResult
from core.registry.registry import PluginRegistry
from core.schemas.common import DecisionEnum, StageEnum
from core.schemas.events import ActionModel, ActorModel, ContentModel, EvaluationRequest
from core.schemas.policy import ConditionExpression, PolicyPackDefinition, PolicyRule, ResolverBinding, RuleAction, ScannerConfig
from core.schemas.verdicts import ScannerFinding


class DummyResolver(BaseContextResolver):
    name = "dummy_resolver"
    version = "1.0.0"
    config_schema = DefaultPluginConfig

    async def resolve(self, request: EvaluationRequest, config: BaseModel) -> dict:
        return {"asset_tier": "tier0", "is_dc": True}


class FailingResolver(BaseContextResolver):
    name = "failing_resolver"
    version = "1.0.0"
    config_schema = DefaultPluginConfig

    async def resolve(self, request: EvaluationRequest, config: BaseModel) -> dict:
        raise RuntimeError("Resolver network error")


class DummyNotifier(BaseNotifier):
    name = "dummy_notifier"
    version = "1.0.0"
    config_schema = DefaultPluginConfig

    async def notify(self, event_type: str, payload: dict, config: BaseModel) -> bool:
        return True


class SlowScanner(BaseScanner):
    name = "slow_scanner"
    version = "1.0.0"
    tier = 1
    config_schema = DefaultPluginConfig

    async def scan(self, request: EvaluationRequest, context: dict, config: BaseModel) -> ScannerResult:
        import asyncio
        await asyncio.sleep(0.2)
        return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")


class ExplodingScanner(BaseScanner):
    name = "exploding_scanner"
    version = "1.0.0"
    tier = 1
    config_schema = DefaultPluginConfig

    async def scan(self, request: EvaluationRequest, context: dict, config: BaseModel) -> ScannerResult:
        raise ValueError("Simulated crash")


@pytest.mark.asyncio
async def test_plugin_registry_full_coverage(tmp_path):
    reg = PluginRegistry()

    # Resolvers
    resolver = DummyResolver()
    reg.register_resolver(resolver)
    assert reg.get_resolver("dummy_resolver") is resolver
    assert "dummy_resolver" in reg.get_all_resolvers()

    # Notifiers
    notifier = DummyNotifier()
    reg.register_notifier(notifier)
    assert reg.get_notifier("dummy_notifier") is notifier
    assert "dummy_notifier" in reg.get_all_notifiers()

    # Type errors
    with pytest.raises(TypeError):
        reg.register_resolver("not_a_resolver")  # type: ignore
    with pytest.raises(TypeError):
        reg.register_notifier("not_a_notifier")  # type: ignore

    # Validate plugin config
    validated_res = reg.validate_plugin_config("resolver", "dummy_resolver", {})
    assert isinstance(validated_res, BaseModel)
    validated_not = reg.validate_plugin_config("notifier", "dummy_notifier", {})
    assert isinstance(validated_not, BaseModel)

    with pytest.raises(KeyError):
        reg.validate_plugin_config("scanner", "non_existent", {})

    # Catalog includes resolvers and notifiers
    catalog = reg.get_plugin_catalog()
    assert len(catalog["resolvers"]) == 1
    assert len(catalog["notifiers"]) == 1

    # Dynamic file discovery test
    plugin_dir = tmp_path / "mock_plugins"
    plugin_dir.mkdir()
    (plugin_dir / "__init__.py").write_text("", encoding="utf-8")
    (plugin_dir / "mock_scanner.py").write_text(
        """from core.registry.interfaces import BaseScanner, ScannerResult, DefaultPluginConfig
class DiscoveredScanner(BaseScanner):
    name = "discovered_scanner"
    tier = 1
    config_schema = DefaultPluginConfig
    async def scan(self, request, context, config):
        return ScannerResult(scanner_name=self.name, tier=1)
""",
        encoding="utf-8",
    )
    import sys
    sys.path.insert(0, str(tmp_path))
    reg.discover_and_register_plugins(str(plugin_dir), "mock_plugins")
    assert reg.get_scanner("discovered_scanner") is not None


@pytest.mark.asyncio
async def test_yaml_engine_all_operators():
    engine = YamlPolicyEngine()

    rules = [
        PolicyRule(
            id="rule_not_in",
            priority=1,
            condition=ConditionExpression(field="actor.role", operator="not_in", value=["admin", "lead"]),
            action=RuleAction(decision="DENY", reason="Not privileged"),
        ),
        PolicyRule(
            id="rule_contains",
            priority=2,
            condition=ConditionExpression(field="content.trusted_instructions", operator="contains", value="forbidden"),
            action=RuleAction(decision="DENY", reason="Forbidden word"),
        ),
        PolicyRule(
            id="rule_regex",
            priority=3,
            condition=ConditionExpression(field="action.parameters.cmd", operator="regex", value=r"^sudo\s+"),
            action=RuleAction(decision="DENY", severity="high", reason="Sudo blocked"),
        ),
        PolicyRule(
            id="rule_comparisons",
            priority=4,
            condition=ConditionExpression(
                all=[
                    ConditionExpression(field="action.estimated_tokens", operator="gt", value=100),
                    ConditionExpression(field="action.estimated_tokens", operator="gte", value=200),
                    ConditionExpression(field="action.estimated_cost_usd", operator="lt", value=5.0),
                    ConditionExpression(field="action.estimated_cost_usd", operator="lte", value=1.0),
                    ConditionExpression(field="metadata.session_token", operator="exists"),
                    ConditionExpression(field="metadata.missing_field", operator="is_null"),
                ]
            ),
            action=RuleAction(decision="ALLOW", reason="Passed numbers"),
        ),
    ]

    pack = PolicyPackDefinition(id="op-pack", name="Operator Pack", rules=rules)
    engine.register_policy_pack(pack)

    req = EvaluationRequest(
        actor=ActorModel(id="u1", role="intern"),
        action=ActionModel(name="run", parameters={"cmd": "sudo reboot"}, estimated_tokens=250, estimated_cost_usd=0.5),
        content=ContentModel(trusted_instructions="This has forbidden content"),
        metadata={"session_token": "xyz123"},
    )

    decision, risk, triggered, mutations = await engine.evaluate(req, [], {}, pack)
    assert decision == DecisionEnum.DENY
    triggered_ids = [r.rule_id for r in triggered]
    assert "rule_not_in" in triggered_ids
    assert "rule_contains" in triggered_ids
    assert "rule_regex" in triggered_ids
    assert "rule_comparisons" in triggered_ids


@pytest.mark.asyncio
async def test_orchestrator_timeouts_errors_and_suspend():
    reg = PluginRegistry()
    slow = SlowScanner()
    exploding = ExplodingScanner()
    resolver = DummyResolver()
    failing_resolver = FailingResolver()

    reg.register_scanner(slow)
    reg.register_scanner(exploding)
    reg.register_resolver(resolver)
    reg.register_resolver(failing_resolver)

    engine = YamlPolicyEngine()
    pack = PolicyPackDefinition(
        id="edge-pack",
        name="Edge Pack",
        scanners=[
            ScannerConfig(name="slow_scanner", enabled=True, timeout_ms=50, on_timeout="deny"),
            ScannerConfig(name="exploding_scanner", enabled=True, timeout_ms=200, on_timeout="flag"),
        ],
        resolvers=[
            ResolverBinding(name="dummy_resolver", enabled=True, timeout_ms=200),
            ResolverBinding(name="failing_resolver", enabled=True, timeout_ms=200),
        ],
        rules=[
            PolicyRule(
                id="suspend-rule",
                priority=1,
                condition=ConditionExpression(field="resolved_context.asset_tier", operator="eq", value="tier0"),
                action=RuleAction(
                    decision="SUSPEND_FOR_APPROVAL",
                    severity="high",
                    reason="Requires dual approval",
                    approval_config={"required_approvals": 2},
                ),
            )
        ],
    )
    engine.register_policy_pack(pack)

    orch = PipelineOrchestrator(plugin_registry=reg, policy_engine=engine)
    req = EvaluationRequest(
        policy_pack_id="edge-pack",
        stage=StageEnum.LLM_INPUT,
        content=ContentModel(trusted_instructions="Hello test"),
    )

    verdict = await orch.evaluate(req)

    # Slow scanner timed out and had on_timeout: deny -> so decision is DENY
    assert any(f.scanner_name == "slow_scanner" and f.status == "block" for f in verdict.scanner_findings)
    assert any(f.scanner_name == "exploding_scanner" for f in verdict.scanner_findings)
    assert verdict.resolved_context.get("asset_tier") == "tier0"


@pytest.mark.asyncio
async def test_logger_prod_mode(monkeypatch):
    monkeypatch.setenv("AEGIS_ENV", "prod")
    get_settings.cache_clear()
    configure_logging()
    monkeypatch.setenv("AEGIS_ENV", "test")
    get_settings.cache_clear()
    configure_logging()
