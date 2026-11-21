import json
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from core.registry.interfaces import BaseScanner, ScannerResult
from core.schemas.events import EvaluationRequest

POISON_DIRECTIVE_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions", re.IGNORECASE),
    re.compile(r"(system\s+prompt(\s+override)?|developer\s+mode|override\s+instructions)\s*:", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(an?\s+)?(unrestricted|jailbroken|dan|evil)", re.IGNORECASE),
    re.compile(r"(always|secretly)\s+(exfiltrate|leak|steal|send|post|transmit)", re.IGNORECASE),
    re.compile(r"never\s+reveal\s+to\s+the\s+user\s+that", re.IGNORECASE),
    re.compile(r"bypass\s+(guardrail|safety|policy|filter)", re.IGNORECASE),
    re.compile(r"remember\s*:\s*disregard\s+(the\s+)?rules", re.IGNORECASE),
]


class MemoryPoisonGuardConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    enabled: bool = True
    block_directive_override: bool = True
    block_credential_harvesting: bool = True
    max_memory_length: int = 4096
    action_on_poison: str = "block"  # "block" | "flag"


class MemoryPoisonGuardScanner(BaseScanner):
    name = "memory_poison_guard"
    version = "1.0.0"
    tier = 1
    supported_stages = ["memory_write", "tool_pre_call", "llm_output"]
    config_schema = MemoryPoisonGuardConfig

    async def scan(
        self,
        request: EvaluationRequest,
        context: dict[str, Any],
        config: BaseModel,
    ) -> ScannerResult:
        cfg = (
            config
            if isinstance(config, MemoryPoisonGuardConfig)
            else MemoryPoisonGuardConfig(**config.model_dump())
        )
        if not cfg.enabled:
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        # Extract text to be written to memory
        text_to_scan = ""
        if request.content.untrusted_data:
            if isinstance(request.content.untrusted_data, (dict, list)):
                text_to_scan = json.dumps(request.content.untrusted_data)
            else:
                text_to_scan = str(request.content.untrusted_data)
        elif request.action.parameters:
            text_to_scan = json.dumps(request.action.parameters)
        elif request.content.output_payload:
            text_to_scan = str(request.content.output_payload)

        if not text_to_scan:
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        if len(text_to_scan) > cfg.max_memory_length:
            return ScannerResult(
                scanner_name=self.name,
                tier=self.tier,
                status=cfg.action_on_poison,
                score=0.8,
                details={"error": f"Memory payload exceeds max allowed length ({len(text_to_scan)} > {cfg.max_memory_length})"},
                message="Memory Poison Guard: Excessive payload size rejected",
            )

        matched_patterns: list[str] = []
        for pattern in POISON_DIRECTIVE_PATTERNS:
            match = pattern.search(text_to_scan)
            if match:
                matched_patterns.append(match.group(0))

        if matched_patterns:
            return ScannerResult(
                scanner_name=self.name,
                tier=self.tier,
                status=cfg.action_on_poison,
                score=0.95,
                details={"matched_directives": matched_patterns},
                message=f"Memory Poison Guard: Persistent instruction override/poison directive detected ({matched_patterns[0]})",
            )

        return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")
