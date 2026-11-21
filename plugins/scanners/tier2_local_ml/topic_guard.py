import json
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from core.registry.interfaces import BaseScanner, ScannerResult
from core.schemas.events import EvaluationRequest

TOPIC_KEYWORD_MAP: dict[str, list[str]] = {
    "cryptocurrency": ["bitcoin", "ethereum", "crypto", "defi", "nft", "tokenomics", "airdrop", "solana"],
    "financial_advice": ["invest in stocks", "guaranteed returns", "forex signals", "buy call options", "portfolio allocation"],
    "partisan_politics": ["presidential candidate", "election conspiracy", "impeach", "vote for democrat", "vote for republican"],
}


class TopicGuardConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    enabled: bool = True
    blocked_topics: list[str] = Field(
        default_factory=lambda: ["cryptocurrency", "financial_advice", "partisan_politics"]
    )
    competitor_keywords: list[str] = Field(default_factory=list)
    action_on_violation: str = "block"  # "block" | "flag"


class TopicGuardScanner(BaseScanner):
    name = "topic_guard"
    version = "1.0.0"
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

        # Check blocked topic keywords
        matched_topics: dict[str, list[str]] = {}
        for topic in cfg.blocked_topics:
            keywords = TOPIC_KEYWORD_MAP.get(topic, [topic])
            hits = [kw for kw in keywords if kw.lower() in lower_text]
            if hits:
                matched_topics[topic] = hits

        # Check competitor keywords
        matched_competitors = [c for c in cfg.competitor_keywords if c.lower() in lower_text]
        if matched_competitors:
            matched_topics["competitor_mention"] = matched_competitors

        if matched_topics:
            return ScannerResult(
                scanner_name=self.name,
                tier=self.tier,
                status=cfg.action_on_violation,
                score=0.8,
                details={"matched_topics": matched_topics},
                message=f"Topic Guard: Off-topic or prohibited domain discussion detected: {list(matched_topics.keys())}",
            )

        return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

