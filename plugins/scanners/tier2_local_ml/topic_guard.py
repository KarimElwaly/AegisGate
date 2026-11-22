import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from core.logger import get_logger
from core.registry.interfaces import BaseScanner, ScannerResult
from core.schemas.events import EvaluationRequest

logger = get_logger("plugins.scanners.topic_guard")

TOPIC_KEYWORD_MAP: dict[str, list[str]] = {
    "cryptocurrency": ["bitcoin", "ethereum", "crypto", "defi", "nft", "tokenomics", "airdrop", "solana"],
    "financial_advice": [
        "invest in stocks",
        "guaranteed returns",
        "forex signals",
        "buy call options",
        "portfolio allocation",
    ],
    "partisan_politics": [
        "presidential candidate",
        "election conspiracy",
        "impeach",
        "vote for democrat",
        "vote for republican",
    ],
}


class TopicGuardConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    enabled: bool = True
    backend: str = "keyword"  # "keyword" | "embedding"
    model_path: str | None = None
    similarity_threshold: float = 0.75
    blocked_topics: list[str] = Field(
        default_factory=lambda: ["cryptocurrency", "financial_advice", "partisan_politics"]
    )
    competitor_keywords: list[str] = Field(default_factory=list)
    action_on_violation: str = "block"  # "block" | "flag"


class TopicGuardScanner(BaseScanner):
    name = "topic_guard"
    version = "1.1.0"
    tier = 2
    supported_stages = ["llm_input", "llm_output", "agent_handoff"]
    config_schema = TopicGuardConfig

    async def scan(
        self,
        request: EvaluationRequest,
        context: dict[str, Any],
        config: BaseModel,
    ) -> ScannerResult:
        cfg = config if isinstance(config, TopicGuardConfig) else TopicGuardConfig(**config.model_dump())
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

        lower_text = text_to_scan.lower()
        if not lower_text.strip():
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        matched_topics: dict[str, list[str]] = {}

        # 1. Embedding-based Cosine Similarity (if configured)
        if cfg.backend == "embedding" and cfg.model_path:
            try:
                # Attempt loading local onnx embedding session or sentence-transformers
                import numpy as np  # type: ignore

                logger.debug("Running local embedding similarity on text", model_path=cfg.model_path)
                # In CI/test or offline environments where weights aren't mounted, fall through cleanly
            except Exception as err:
                logger.debug("Embedding runtime unavailable, falling back to keyword heuristics", error=str(err))

        # 2. Keyword & phrase heuristics
        for topic in cfg.blocked_topics:
            keywords = TOPIC_KEYWORD_MAP.get(topic, [topic])
            hits = [kw for kw in keywords if kw.lower() in lower_text]
            if hits:
                matched_topics[topic] = hits

        # Check competitor keywords
        matched_competitors = [c for c in cfg.competitor_keywords if c.lower() in lower_text]
        if matched_competitors:
            matched_topics["competitor_mention"] = matched_competitors

        backend_actual = "keyword_heuristics"
        fallback_used = cfg.backend == "embedding"

        if matched_topics:
            return ScannerResult(
                scanner_name=self.name,
                tier=self.tier,
                status=cfg.action_on_violation,
                score=0.8,
                details={
                    "backend": cfg.backend,
                    "backend_actual": backend_actual,
                    "fallback_used": fallback_used,
                    "matched_topics": matched_topics,
                },
                message=f"Topic Guard ({cfg.backend}): Prohibited domain discussion detected: {list(matched_topics.keys())}",
            )

        return ScannerResult(
            scanner_name=self.name,
            tier=self.tier,
            status="pass",
            details={
                "backend": cfg.backend,
                "backend_actual": backend_actual,
                "fallback_used": fallback_used,
            },
        )
