import os
from pathlib import Path
from core.logger import get_logger
from core.policy_engine.yaml_engine import get_yaml_policy_engine
from core.registry.registry import get_plugin_registry
from plugins.scanners.tier1_deterministic.entropy_size_guard import EntropySizeGuard
from plugins.scanners.tier1_deterministic.grounding_scanner import EvidenceGroundingScanner
from plugins.scanners.tier1_deterministic.json_schema_scanner import JsonSchemaScanner
from plugins.scanners.tier1_deterministic.pii_scanner import PiiScanner
from plugins.scanners.tier1_deterministic.secrets_scanner import SecretsScanner
from plugins.scanners.tier1_deterministic.tool_param_guard import ToolParamGuard
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

    # 1. Register Built-in Tier-1 Scanners
    registry.register_scanner(SecretsScanner())
    registry.register_scanner(PiiScanner())
    registry.register_scanner(JsonSchemaScanner())
    registry.register_scanner(ToolParamGuard())
    registry.register_scanner(EntropySizeGuard())
    registry.register_scanner(EvidenceGroundingScanner())
    registry.register_scanner(WebhookScanner())

    # 2. Auto-load base-enterprise policy pack if present on filesystem
    base_pack_path = Path("policy_packs/base-enterprise/policy.yaml")
    if base_pack_path.exists():
        try:
            with open(base_pack_path, "r", encoding="utf-8") as f:
                content = f.read()
                policy_engine.load_from_yaml_string(content)
                logger.info("Loaded base-enterprise policy pack")
        except Exception as e:
            logger.error("Failed to load base-enterprise policy pack", error=str(e))

    _bootstrapped = True
