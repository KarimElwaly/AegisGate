import json
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from core.logger import get_logger
from core.pii_vault.vault import get_pii_vault
from core.registry.interfaces import BaseScanner, ScannerResult
from core.schemas.events import EvaluationRequest

logger = get_logger("plugins.scanners.ner_pii_scanner")

NER_ENTITY_PATTERNS: dict[str, re.Pattern] = {
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,12}\b"),
    "PHONE_NUMBER": re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "FINANCIAL_IDENTIFIER": re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"),
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "PASSPORT": re.compile(r"\b[A-Z]{1,2}[0-9]{7,8}\b"),
    "PERSON_NAME_CANDIDATE": re.compile(r"\b(?:Dr\.|Mr\.|Ms\.|Mrs\.)\s+[A-Z][a-z]+\s+[A-Z][a-z]+\b"),
}


class NerPiiScannerConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    enabled: bool = True
    backend: str = "regex"  # "regex" | "presidio" | "onnx"
    target_entities: list[str] = Field(
        default_factory=lambda: [
            "EMAIL",
            "PHONE_NUMBER",
            "FINANCIAL_IDENTIFIER",
            "SSN",
            "PASSPORT",
            "PERSON_NAME_CANDIDATE",
        ]
    )
    confidence_threshold: float = 0.7
    action_on_match: str = "flag"  # "block" | "flag"
    tokenize_entities: bool = False


class NerPiiScanner(BaseScanner):
    name = "ner_pii_scanner"
    version = "1.1.0"
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

        # 1. Presidio runtime backend (if configured and installed)
        if cfg.backend == "presidio":
            try:
                from presidio_analyzer import AnalyzerEngine  # type: ignore

                analyzer = AnalyzerEngine()
                results = analyzer.analyze(text=text_to_scan, language="en")
                for r in results:
                    if r.score >= cfg.confidence_threshold:
                        detected_entities.append(
                            {
                                "entity_type": r.entity_type,
                                "value": text_to_scan[r.start : r.end],
                                "start": r.start,
                                "end": r.end,
                                "confidence": r.score,
                            }
                        )
            except Exception as err:
                logger.debug("Presidio analyzer unavailable, falling back to regex patterns", error=str(err))

        # 2. Regex fallback / default backend
        if not detected_entities:
            for entity_type, pattern in NER_ENTITY_PATTERNS.items():
                if entity_type not in cfg.target_entities:
                    continue
                for match in pattern.finditer(text_to_scan):
                    detected_entities.append(
                        {
                            "entity_type": entity_type,
                            "value": match.group(0),
                            "start": match.start(),
                            "end": match.end(),
                            "confidence": 0.95,
                        }
                    )

        if detected_entities:
            # Reversible tokenization if requested
            if cfg.tokenize_entities and request.session_id:
                try:
                    vault = get_pii_vault()
                    for ent in detected_entities:
                        await vault.tokenize(request.tenant_id, request.session_id, ent["value"], ent["entity_type"])
                except Exception as vault_err:
                    logger.warning("Failed to tokenize detected NER PII in vault", error=str(vault_err))

            return ScannerResult(
                scanner_name=self.name,
                tier=self.tier,
                status=cfg.action_on_match,
                score=0.85,
                details={
                    "backend_used": cfg.backend,
                    "entities_count": len(detected_entities),
                    "entities": detected_entities[:10],
                },
                message=f"NER PII Scanner ({cfg.backend}): Found {len(detected_entities)} named entity PII instances",
            )

        return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")
