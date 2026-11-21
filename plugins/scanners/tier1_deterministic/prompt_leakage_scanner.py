import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from core.logger import get_logger
from core.registry.interfaces import BaseScanner, ScannerResult
from core.schemas.events import EvaluationRequest

logger = get_logger("plugins.scanners.prompt_leakage_scanner")


def _get_ngrams(text: str, n: int = 4) -> set[tuple[str, ...]]:
    words = [w.lower() for w in re.findall(r"\b\w+\b", text)]
    if len(words) < n:
        return {tuple(words)} if words else set()
    return {tuple(words[i : i + n]) for i in range(len(words) - n + 1)}


class PromptLeakageConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    enabled: bool = True
    max_leakage_ratio: float = 0.65
    min_ngram_length: int = 4
    registered_system_prompts: list[str] = Field(default_factory=list)
    action_on_leak: str = "block"  # "block" | "flag"


class PromptLeakageScanner(BaseScanner):
    """Tier-1 Deterministic Scanner detecting extraction or leakage of confidential system prompts in outputs."""

    name = "prompt_leakage_scanner"
    version = "1.0.0"
    tier = 1
    supported_stages = ["llm_output"]
    config_schema = PromptLeakageConfig

    async def scan(
        self,
        request: EvaluationRequest,
        context: dict[str, Any],
        config: BaseModel,
    ) -> ScannerResult:
        cfg = (
            config
            if isinstance(config, PromptLeakageConfig)
            else PromptLeakageConfig(**config.model_dump())
        )
        if not cfg.enabled:
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        output_payload = request.content.output_payload
        if not output_payload or not str(output_payload).strip():
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        output_str = str(output_payload).strip()
        output_ngrams = _get_ngrams(output_str, cfg.min_ngram_length)
        if not output_ngrams:
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        # Reference targets: request's own trusted_instructions + registered prompts
        candidate_prompts: list[str] = list(cfg.registered_system_prompts)
        if request.content.trusted_instructions and len(request.content.trusted_instructions.strip()) > 30:
            candidate_prompts.append(request.content.trusted_instructions.strip())

        max_containment = 0.0
        leaked_sample = ""

        for ref_prompt in candidate_prompts:
            if not ref_prompt.strip():
                continue
            ref_ngrams = _get_ngrams(ref_prompt, cfg.min_ngram_length)
            if not ref_ngrams:
                continue

            shared = ref_ngrams & output_ngrams
            containment = len(shared) / max(len(ref_ngrams), 1)

            if containment > max_containment:
                max_containment = containment
                if shared:
                    leaked_sample = " ".join(next(iter(shared)))

        if max_containment >= cfg.max_leakage_ratio:
            return ScannerResult(
                scanner_name=self.name,
                tier=self.tier,
                status=cfg.action_on_leak,
                score=round(max_containment, 2),
                details={
                    "leakage_ratio": round(max_containment, 2),
                    "threshold": cfg.max_leakage_ratio,
                    "leaked_ngram_sample": leaked_sample,
                },
                message=(
                    f"System Prompt Leakage Guard: Output contains {round(max_containment * 100, 1)}% of confidential "
                    f"system prompt instructions (threshold {round(cfg.max_leakage_ratio * 100, 1)}%)"
                ),
            )

        return ScannerResult(
            scanner_name=self.name,
            tier=self.tier,
            status="pass",
            score=round(max_containment, 2),
            details={"leakage_ratio": round(max_containment, 2)},
        )

