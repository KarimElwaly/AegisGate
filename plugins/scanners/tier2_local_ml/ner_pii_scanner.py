import json
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from core.registry.interfaces import BaseScanner, ScannerResult
from core.schemas.events import EvaluationRequest

NER_ENTITY_PATTERNS: dict[str, re.Pattern] = {
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"),
    "PHONE_NUMBER": re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "FINANCIAL_IDENTIFIER": re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"),
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "PASSPORT": re.compile(r"\b[A-Z]{1,2}[0-9]{7,8}\b"),
    "PERSON_NAME_CANDIDATE": re.compile(r"\b(?:Dr\.|Mr\.|Ms\.|Mrs\.)\s+[A-Z][a-z]+\s+[A-Z][a-z]+\b"),
}


class NerPiiScannerConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    enabled: bool = True
    target_entities: list[str] = Field(
        default_factory=lambda: ["EMAIL", "PHONE_NUMBER", "FINANCIAL_IDENTIFIER", "SSN", "PASSPORT", "PERSON_NAME_CANDIDATE"]
    )
    confidence_threshold: float = 0.7
    action_on_match: str = "flag"  # "block" | "flag"


class NerPiiScanner(BaseScanner):
    name = "ner_pii_scanner"
    version = "1.0.0"
    tier = 2
    supported_stages = ["llm_input", "llm_output", "tool_pre_call", "tool_post_call", "rag_retrieval", "memory_write"]
    config_schema = NerPiiScannerConfig

    async def scan(
        self,
        request: EvaluationRequest,
        context: dict[str, Any],
        config: BaseModel,
    ) -> ScannerResult:
        cfg = config if isinstance(config, NerPiiScannerConfig) else NerPiiScannerConfig(**config.model_dump())
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

        detected_entities: list[dict[str, Any]] = []
        for entity_type, pattern in NER_ENTITY_PATTERNS.items():
            if entity_type not in cfg.target_entities:
                continue
            for match in pattern.finditer(text_to_scan):
                detected_entities.append({
                    "entity_type": entity_type,
                    "value": match.group(0),
                    "start": match.start(),
                    "end": match.end(),
                    "confidence": 0.95,
                })

        if detected_entities:
            return ScannerResult(
                scanner_name=self.name,
                tier=self.tier,
                status=cfg.action_on_match,
                score=0.85,
                details={
                    "entities_count": len(detected_entities),
                    "entities": detected_entities[:10],
                },
                message=f"NER PII Scanner: Found {len(detected_entities)} named entity PII instances",
            )

        return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

