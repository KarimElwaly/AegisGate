import math
import re
from typing import Any

from pydantic import BaseModel, ConfigDict

from core.registry.interfaces import BaseScanner, ScannerResult
from core.schemas.events import EvaluationRequest


class EntropySizeGuardConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    enabled: bool = True
    max_payload_bytes: int = 1_048_576  # 1 MB
    max_estimated_tokens: int = 32_768
    check_entropy: bool = True
    max_shannon_entropy: float = 4.8  # Normal English text is ~3.5-4.2; base64/compressed/encrypted is >4.7
    min_token_length_for_entropy: int = 30
    action_on_violation: str = "block"  # "block" | "flag"


class EntropySizeGuard(BaseScanner):
    name = "entropy_size_guard"
    version = "1.0.0"
    tier = 1
    supported_stages = [
        "llm_input",
        "llm_output",
        "tool_pre_call",
        "tool_post_call",
        "memory_write",
    ]
    config_schema = EntropySizeGuardConfig

    TOKEN_REGEX = re.compile(r"\S{30,}")

    @staticmethod
    def calculate_shannon_entropy(data: str) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        freqs = {}
        for char in data:
            freqs[char] = freqs.get(char, 0) + 1
        for count in freqs.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    async def scan(
        self,
        request: EvaluationRequest,
        context: dict[str, Any],
        config: BaseModel,
    ) -> ScannerResult:
        cfg = config if isinstance(config, EntropySizeGuardConfig) else EntropySizeGuardConfig(**config.model_dump())
        if not cfg.enabled:
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        violations: list[dict[str, Any]] = []

        # 1. Total payload size check
        total_size_bytes = 0
        texts: list[str] = []

        if request.content.trusted_instructions:
            s = str(request.content.trusted_instructions)
            total_size_bytes += len(s.encode("utf-8"))
            texts.append(s)
        if request.content.untrusted_data:
            s = str(request.content.untrusted_data)
            total_size_bytes += len(s.encode("utf-8"))
            texts.append(s)
        if request.content.output_payload:
            s = str(request.content.output_payload)
            total_size_bytes += len(s.encode("utf-8"))
            texts.append(s)
        if request.action.parameters:
            s = str(request.action.parameters)
            total_size_bytes += len(s.encode("utf-8"))
            texts.append(s)

        if total_size_bytes > cfg.max_payload_bytes:
            violations.append({
                "type": "payload_size_exceeded",
                "bytes": total_size_bytes,
                "limit": cfg.max_payload_bytes,
            })

        # 2. Token estimate check (approx 4 chars per token)
        estimated_tokens = max(request.action.estimated_tokens, total_size_bytes // 4)
        if estimated_tokens > cfg.max_estimated_tokens:
            violations.append({
                "type": "tokens_exceeded",
                "estimated_tokens": estimated_tokens,
                "limit": cfg.max_estimated_tokens,
            })

        # 3. High entropy secret exfiltration check
        if cfg.check_entropy:
            for text in texts:
                for match in self.TOKEN_REGEX.finditer(text):
                    candidate = match.group(0)
                    if len(candidate) >= cfg.min_token_length_for_entropy:
                        entropy = self.calculate_shannon_entropy(candidate)
                        if entropy >= cfg.max_shannon_entropy:
                            violations.append({
                                "type": "high_entropy_string",
                                "sample": candidate[:12] + "...",
                                "entropy": round(entropy, 3),
                                "threshold": cfg.max_shannon_entropy,
                            })
                            break
                if violations:
                    break

        if not violations:
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        status = cfg.action_on_violation
        return ScannerResult(
            scanner_name=self.name,
            tier=self.tier,
            status=status,
            score=0.9 if status == "block" else 0.4,
            details={"violations_count": len(violations), "violations": violations},
            message=f"Entropy & Size Guard triggered: {violations[0]['type']}",
        )
