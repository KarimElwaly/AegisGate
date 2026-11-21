import json
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from core.registry.interfaces import BaseScanner, ScannerResult
from core.schemas.events import EvaluationRequest

TOXICITY_PATTERNS: dict[str, list[re.Pattern]] = {
    "harassment_threats": [
        re.compile(r"\b(i\s+will|gonna)\s+(kill|destroy|murder|hunt)\s+you\b", re.IGNORECASE),
        re.compile(r"\byou\s+deserve\s+to\s+die\b", re.IGNORECASE),
    ],
    "self_harm": [
        re.compile(r"\bhow\s+to\s+(commit\s+suicide|kill\s+myself|end\s+my\s+life)\b", re.IGNORECASE),
        re.compile(r"\bways\s+to\s+cut\s+myself\b", re.IGNORECASE),
    ],
    "hate_speech": [
        re.compile(r"\b(inferior|subhuman)\s+(race|people|religion)\b", re.IGNORECASE),
        re.compile(r"\ball\s+[a-z]+\s+must\s+be\s+eliminated\b", re.IGNORECASE),
    ],
}


class SafetyToxicityConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    enabled: bool = True
    categories: list[str] = Field(
        default_factory=lambda: ["harassment_threats", "self_harm", "hate_speech"]
    )
    action_on_toxic: str = "block"  # "block" | "flag"


class SafetyToxicityScanner(BaseScanner):
    name = "safety_toxicity_scanner"
    version = "1.0.0"
    tier = 2
    supported_stages = ["llm_input", "llm_output", "agent_handoff"]
    config_schema = SafetyToxicityConfig

    async def scan(
        self,
        request: EvaluationRequest,
        context: dict[str, Any],
        config: BaseModel,
    ) -> ScannerResult:
        cfg = (
            config
            if isinstance(config, SafetyToxicityConfig)
            else SafetyToxicityConfig(**config.model_dump())
        )
        if not cfg.enabled:
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        text_to_scan = ""
        if request.content.trusted_instructions:
            text_to_scan += request.content.trusted_instructions + " "
        if request.content.untrusted_data:
            text_to_scan += (
                json.dumps(request.content.untrusted_data)
                if isinstance(request.content.untrusted_data, (dict, list))
                else str(request.content.untrusted_data)
            ) + " "
        if request.content.output_payload:
            text_to_scan += str(request.content.output_payload)

        if not text_to_scan.strip():
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        matched_violations: dict[str, list[str]] = {}
        for category, patterns in TOXICITY_PATTERNS.items():
            if category not in cfg.categories:
                continue
            for pat in patterns:
                hit = pat.search(text_to_scan)
                if hit:
                    matched_violations.setdefault(category, []).append(hit.group(0))

        if matched_violations:
            return ScannerResult(
                scanner_name=self.name,
                tier=self.tier,
                status=cfg.action_on_toxic,
                score=0.95,
                details={"categories": matched_violations},
                message=f"Safety Toxicity Scanner: Toxic/harmful content detected ({list(matched_violations.keys())})",
            )

        return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

