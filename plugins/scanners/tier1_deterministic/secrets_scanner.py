import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from core.config import get_settings
from core.registry.interfaces import BaseScanner, ScannerResult
from core.schemas.events import EvaluationRequest


class SecretsScannerConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    enabled: bool = True
    action_on_match: str = "block"  # "block" | "mask" | "flag"
    detect_jwt: bool = True
    detect_aws_keys: bool = True
    detect_private_keys: bool = True
    detect_generic_api_keys: bool = True
    custom_patterns: list[str] = Field(default_factory=list)


class SecretsScanner(BaseScanner):
    name = "secrets_scanner"
    version = "1.0.0"
    tier = 1
    supported_stages = ["llm_input", "llm_output", "tool_pre_call", "tool_post_call", "memory_write"]
    config_schema = SecretsScannerConfig

    PATTERNS = {
        "pem_private_key": re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", re.MULTILINE
        ),
        "aws_access_key": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "aws_secret_key": re.compile(
            r"(?i)\b(?:aws_secret_access_key|aws_secret_key|secret_key)\s*[:=]\s*([A-Za-z0-9/+=]{40})\b"
        ),
        "jwt_token": re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9_-]+\b"),
        "bearer_token": re.compile(r"(?i)\bBearer\s+([A-Za-z0-9_\-\.~+/=]{20,})\b"),
        "generic_api_key": re.compile(
            r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?\b"
        ),
        "openai_api_key": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    }

    async def scan(
        self,
        request: EvaluationRequest,
        context: dict[str, Any],
        config: BaseModel,
    ) -> ScannerResult:
        cfg = config if isinstance(config, SecretsScannerConfig) else SecretsScannerConfig(**config.model_dump())
        if not cfg.enabled:
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        # Collect text candidates from request
        texts_to_check: list[tuple[str, str]] = []
        if request.content.trusted_instructions:
            texts_to_check.append(("trusted_instructions", str(request.content.trusted_instructions)))
        if request.content.untrusted_data:
            texts_to_check.append(("untrusted_data", str(request.content.untrusted_data)))
        if request.content.output_payload:
            texts_to_check.append(("output_payload", str(request.content.output_payload)))
        if request.action.parameters:
            texts_to_check.append(("parameters", str(request.action.parameters)))

        matches_found: list[dict[str, Any]] = []
        mutated_text_map: dict[str, str] = {}

        for source_name, text in texts_to_check:
            current_text = text
            scan_text = text[:get_settings().MAX_PAYLOAD_SCAN_BYTES]
            for pattern_name, regex in self.PATTERNS.items():
                if pattern_name == "pem_private_key" and not cfg.detect_private_keys:
                    continue
                if (pattern_name in ("aws_access_key", "aws_secret_key")) and not cfg.detect_aws_keys:
                    continue
                if pattern_name in ("jwt_token", "bearer_token") and not cfg.detect_jwt:
                    continue
                if pattern_name == "generic_api_key" and not cfg.detect_generic_api_keys:
                    continue

                for match in regex.finditer(scan_text):
                    secret_val = match.group(0)
                    matches_found.append({
                        "source": source_name,
                        "type": pattern_name,
                        "matched_prefix": secret_val[:8] + "...",
                    })
                    if cfg.action_on_match == "mask":
                        current_text = current_text.replace(secret_val, "[REDACTED_SECRET]")

            for custom_pat in cfg.custom_patterns:
                try:
                    c_regex = re.compile(custom_pat)
                    for match in c_regex.finditer(text):
                        secret_val = match.group(0)
                        matches_found.append({
                            "source": source_name,
                            "type": "custom_pattern",
                            "matched_prefix": secret_val[:8] + "...",
                        })
                        if cfg.action_on_match == "mask":
                            current_text = current_text.replace(secret_val, "[REDACTED_SECRET]")
                except re.error:
                    continue

            if current_text != text:
                mutated_text_map[source_name] = current_text

        if not matches_found:
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        if cfg.action_on_match == "block":
            status = "block"
        elif cfg.action_on_match == "mask":
            status = "flag"
        else:
            status = "flag"

        return ScannerResult(
            scanner_name=self.name,
            tier=self.tier,
            status=status,
            score=1.0 if status == "block" else 0.5,
            details={"findings_count": len(matches_found), "findings": matches_found},
            message=f"Detected {len(matches_found)} potential secret(s)",
            mutated_content=mutated_text_map if mutated_text_map else None,
        )

