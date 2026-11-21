import json
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from core.logger import get_logger
from core.registry.interfaces import BaseScanner, ScannerResult
from core.schemas.events import EvaluationRequest

logger = get_logger("plugins.scanners.nli_faithfulness_scanner")

STOP_WORDS = {
    "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for", "of", "with", "by",
    "is", "are", "was", "were", "be", "been", "being", "have", "has", "had", "do", "does", "did",
    "that", "this", "these", "those", "it", "its", "they", "them", "their", "we", "us", "our",
}


def _extract_factual_keywords(sentence: str) -> set[str]:
    words = re.findall(r"\b[A-Za-z0-9_-]{3,}\b", sentence.lower())
    return {w for w in words if w not in STOP_WORDS}


class NliFaithfulnessConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    enabled: bool = True
    backend: str = "lexical"  # "lexical" | "cross_encoder_onnx"
    model_path: str | None = None
    min_faithfulness_score: float = 0.50
    action_on_hallucination: str = "block"  # "block" | "flag"


class NliFaithfulnessScanner(BaseScanner):
    """Tier-2 Local Scanner verifying groundedness of output claims against retrieved context chunks (RAG)."""

    name = "nli_faithfulness_scanner"
    version = "1.0.0"
    tier = 2
    supported_stages = ["llm_output", "rag_retrieval"]
    config_schema = NliFaithfulnessConfig

    async def scan(
        self,
        request: EvaluationRequest,
        context: dict[str, Any],
        config: BaseModel,
    ) -> ScannerResult:
        cfg = (
            config
            if isinstance(config, NliFaithfulnessConfig)
            else NliFaithfulnessConfig(**config.model_dump())
        )
        if not cfg.enabled:
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        output_payload = request.content.output_payload
        if not output_payload or not str(output_payload).strip():
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        output_text = str(output_payload).strip()

        # Context source: untrusted_data (which holds retrieved chunks in RAG) or context.get("rag_chunks")
        context_text = ""
        if request.content.untrusted_data:
            context_text = (
                json.dumps(request.content.untrusted_data)
                if isinstance(request.content.untrusted_data, (dict, list))
                else str(request.content.untrusted_data)
            )
        if context.get("rag_chunks"):
            context_text += " " + " ".join(str(c) for c in context["rag_chunks"])

        if not context_text.strip():
            # If no context was retrieved or passed, groundedness check does not apply
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        # Split output into sentences/claims
        sentences = [s.strip() for s in re.split(r"[.!?\n]+", output_text) if len(s.strip()) > 10]
        if not sentences:
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        # Context vocabulary
        context_keywords = _extract_factual_keywords(context_text)

        supported_claims = 0
        unsupported_claims: list[str] = []

        for sent in sentences:
            claim_kws = _extract_factual_keywords(sent)
            if not claim_kws:
                supported_claims += 1
                continue

            overlap = claim_kws & context_keywords
            overlap_ratio = len(overlap) / max(len(claim_kws), 1)

            # A claim is grounded if at least 35% of its factual keywords or >= 2 significant keywords appear in context
            if overlap_ratio >= 0.35 or len(overlap) >= 2:
                supported_claims += 1
            else:
                unsupported_claims.append(sent)

        faithfulness_score = supported_claims / len(sentences)

        if faithfulness_score < cfg.min_faithfulness_score:
            return ScannerResult(
                scanner_name=self.name,
                tier=self.tier,
                status=cfg.action_on_hallucination,
                score=round(1.0 - faithfulness_score, 2),
                details={
                    "faithfulness_score": round(faithfulness_score, 2),
                    "total_claims": len(sentences),
                    "supported_claims": supported_claims,
                    "unsupported_claims": unsupported_claims[:5],
                },
                message=(
                    f"NLI Faithfulness Scanner: Output contains ungrounded/hallucinated claims not supported by retrieved context "
                    f"({round(faithfulness_score * 100, 1)}% grounded, threshold {round(cfg.min_faithfulness_score * 100, 1)}%)"
                ),
            )

        return ScannerResult(
            scanner_name=self.name,
            tier=self.tier,
            status="pass",
            score=round(faithfulness_score, 2),
            details={
                "faithfulness_score": round(faithfulness_score, 2),
                "total_claims": len(sentences),
                "supported_claims": supported_claims,
            },
        )

