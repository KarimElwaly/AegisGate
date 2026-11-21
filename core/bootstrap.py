from pathlib import Path

from core.logger import get_logger
from core.policy_engine.yaml_engine import get_yaml_policy_engine
from core.registry.registry import get_plugin_registry
from plugins.notifiers.siem_cef_notifier import SiemCefNotifier
from plugins.notifiers.slack_notifier import SlackNotifier
from plugins.notifiers.webhook_notifier import WebhookNotifier
from plugins.resolvers.http_resolver import HTTPContextResolver
from plugins.resolvers.redis_resolver import RedisStateResolver
from plugins.resolvers.static_resolver import StaticLookupResolver
from plugins.scanners.tier1_deterministic.entropy_size_guard import EntropySizeGuard
from plugins.scanners.tier1_deterministic.grounding_scanner import EvidenceGroundingScanner
from plugins.scanners.tier1_deterministic.json_schema_scanner import JsonSchemaScanner
from plugins.scanners.tier1_deterministic.memory_poison_guard import MemoryPoisonGuardScanner
from plugins.scanners.tier1_deterministic.pii_scanner import PiiScanner
from plugins.scanners.tier1_deterministic.rag_acl_guard import RagAclGuardScanner
from plugins.scanners.tier1_deterministic.secrets_scanner import SecretsScanner
from plugins.scanners.tier1_deterministic.tool_param_guard import ToolParamGuard
from plugins.scanners.tier2_local_ml.ner_pii_scanner import NerPiiScanner
from plugins.scanners.tier2_local_ml.onnx_classifier import ONNXInjectionClassifier
from plugins.scanners.tier2_local_ml.safety_toxicity_scanner import SafetyToxicityScanner
from plugins.scanners.tier2_local_ml.topic_guard import TopicGuardScanner
from plugins.scanners.tier3_llm_judge.judge_scanner import LLMJudgeScanner
from plugins.scanners.webhook_scanner import WebhookScanner

logger = get_logger("core.bootstrap")

_bootstrapped = False


def bootstrap_system() -> None:
    """Bootstraps the plugin registry and loads default policy packs."""
    global _bootstrapped
    if _bootstrapped:
        return

    registry = get_plugin_registry()
    policy_engine = get_yaml_policy_engine()

    # 1. Register Tier-1 Deterministic Scanners
    registry.register_scanner(SecretsScanner())
    registry.register_scanner(PiiScanner())
    registry.register_scanner(JsonSchemaScanner())
    registry.register_scanner(ToolParamGuard())
    registry.register_scanner(EntropySizeGuard())
    registry.register_scanner(EvidenceGroundingScanner())
    registry.register_scanner(RagAclGuardScanner())
    registry.register_scanner(MemoryPoisonGuardScanner())
    registry.register_scanner(WebhookScanner())

    # 2. Register Tier-2 Local ML Classifiers
    registry.register_scanner(ONNXInjectionClassifier())
    registry.register_scanner(NerPiiScanner())
    registry.register_scanner(TopicGuardScanner())
    registry.register_scanner(SafetyToxicityScanner())

    # 3. Register Tier-3 Semantic LLM Judge
    registry.register_scanner(LLMJudgeScanner())

    # 4. Register Context Resolvers
    registry.register_resolver(HTTPContextResolver())
    registry.register_resolver(RedisStateResolver())
    registry.register_resolver(StaticLookupResolver())

    # 5. Register Notifiers
    registry.register_notifier(WebhookNotifier())
    registry.register_notifier(SlackNotifier())
    registry.register_notifier(SiemCefNotifier())

    # 6. Auto-load all policy packs in policy_packs/ directory
    packs_dir = Path("policy_packs")
    if packs_dir.exists():
        for pack_file in packs_dir.glob("*/policy.yaml"):
            try:
                with open(pack_file, "r", encoding="utf-8") as f:
                    content = f.read()
                    policy_engine.load_from_yaml_string(content)
                    logger.info("Loaded policy pack", path=str(pack_file))
            except Exception as e:
                logger.error("Failed to load policy pack", path=str(pack_file), error=str(e))

    _bootstrapped = True
