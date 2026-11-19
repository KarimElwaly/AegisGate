import pytest
from pydantic import BaseModel

from core.registry.interfaces import BaseScanner, ScannerResult
from core.registry.registry import PluginRegistry
from core.schemas.events import EvaluationRequest


class DummyConfig(BaseModel):
    max_count: int = 10
    tag: str = "test"


class DummyScanner(BaseScanner):
    name = "dummy_scanner"
    version = "1.0.0"
    tier = 1
    supported_stages = ["llm_input", "tool_pre_call"]
    config_schema = DummyConfig

    async def scan(self, request: EvaluationRequest, context: dict, config: BaseModel) -> ScannerResult:
        return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")


def test_registry_registration_and_lookup():
    reg = PluginRegistry()
    scanner = DummyScanner()
    reg.register_scanner(scanner)

    assert reg.get_scanner("dummy_scanner") is scanner
    assert "dummy_scanner" in reg.get_all_scanners()

    # Stage filter
    assert len(reg.get_scanners_for_stage("llm_input")) == 1
    assert len(reg.get_scanners_for_stage("llm_output")) == 0

    # Config validation
    validated = reg.validate_plugin_config("scanner", "dummy_scanner", {"max_count": 5, "tag": "custom"})
    assert isinstance(validated, DummyConfig)
    assert validated.max_count == 5

    # Catalog schema extraction
    catalog = reg.get_plugin_catalog()
    assert len(catalog["scanners"]) == 1
    assert catalog["scanners"][0]["name"] == "dummy_scanner"
    assert "properties" in catalog["scanners"][0]["config_schema"]

    # Unregister
    reg.unregister_scanner("dummy_scanner")
    assert reg.get_scanner("dummy_scanner") is None


def test_registry_type_safety():
    reg = PluginRegistry()
    with pytest.raises(TypeError):
        reg.register_scanner("not_a_scanner")  # type: ignore

