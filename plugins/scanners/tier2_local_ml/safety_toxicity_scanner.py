import json
import re
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field

from core.logger import get_logger
from core.registry.interfaces import BaseScanner, ScannerResult
from core.schemas.events import EvaluationRequest

logger = get_logger("plugins.scanners.safety_toxicity_scanner")

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
    "sexual_content": [
        re.compile(r"\b(child\s+sexual|underage\s+explicit|non-consensual\s+sexual)\b", re.IGNORECASE),
    ],
    "violence": [
        re.compile(r"\b(build\s+a\s+bomb|synthesize\s+explosives|mass\s+shooting\s+plan)\b", re.IGNORECASE),
    ],
    "code_interpreter_abuse": [
        re.compile(r"\b(reverse\s+shell|payload\s+delivery|buffer\s+overflow\s+exploit|rm\s+-rf\s+/)\b", re.IGNORECASE),
    ],
    "cbrn": [
        re.compile(r"\b(weaponize\s+anthrax|dirty\s+bomb\s+enrichment|sarin\s+gas\s+formula)\b", re.IGNORECASE),
    ],
}


class SafetyToxicityConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    enabled: bool = True
    backend: str = "heuristic"  # "heuristic" | "llama_guard" | "onnx"
    endpoint_url: str | None = None
    model_path: str | None = None
    categories: list[str] = Field(
        default_factory=lambda: [
            "harassment_threats",
            "self_harm",
            "hate_speech",
            "sexual_content",
            "violence",
            "code_interpreter_abuse",
            "cbrn",
        ]
    )
    action_on_toxic: str = "block"  # "block" | "flag"


class SafetyToxicityScanner(BaseScanner):
    name = "safety_toxicity_scanner"
    version = "1.1.0"
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

        # 1. Llama Guard endpoint check (if configured and running)
        if cfg.backend == "llama_guard" and cfg.endpoint_url:
            try:
                async with httpx.AsyncClient(timeout=3.0) as client:
                    resp = await client.post(
                        cfg.endpoint_url,
                        json={"prompt": text_to_scan},
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        if data.get("is_unsafe", False):
                            matched_violations["llama_guard_violation"] = data.get("categories", ["unsafe"])
            except Exception as err:
                logger.debug("Llama Guard endpoint unreachable, falling back to heuristics", error=str(err))

        # 2. Heuristic taxonomy patterns
        if not matched_violations:
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
                details={"backend": cfg.backend, "categories": matched_violations},
                message=f"Safety Toxicity Scanner ({cfg.backend}): Prohibited harmful content detected: {list(matched_violations.keys())}",
            )

        return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")
