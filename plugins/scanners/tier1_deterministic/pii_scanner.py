import hashlib
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from core.config import get_settings
from core.pii_vault.vault import get_pii_vault
from core.registry.interfaces import BaseScanner, ScannerResult
from core.schemas.events import EvaluationRequest


class PiiScannerConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    enabled: bool = True
    mode: str = "reversible_tokenize"  # "reversible_tokenize" | "mask" | "hash" | "block"
    detect_emails: bool = True
    detect_phone_numbers: bool = True
    detect_credit_cards: bool = True
    detect_ssn: bool = True
    detect_ipv4: bool = True
    detect_ipv6: bool = False
    custom_patterns: list[str] = Field(default_factory=list)


class PiiScanner(BaseScanner):
    name = "pii_scanner"
    version = "1.0.0"
    tier = 1
    supported_stages = [
        "llm_input",
        "llm_output",
        "tool_pre_call",
        "tool_post_call",
        "memory_write",
        "rag_retrieval",
    ]
    config_schema = PiiScannerConfig

    PII_REGEXES = {
        "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        "PHONE": re.compile(
            r"\b(?:\+\d{1,3}[-. ]?)?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}\b"
        ),
        "CREDIT_CARD": re.compile(
            r"\b(?:\d{4}[ -]?){3}\d{4}\b"
        ),
        "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "IPV4": re.compile(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        ),
        "IPV6": re.compile(
            r"\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b", re.IGNORECASE
        ),
    }

    async def scan(
        self,
        request: EvaluationRequest,
        context: dict[str, Any],
        config: BaseModel,
    ) -> ScannerResult:
        cfg = config if isinstance(config, PiiScannerConfig) else PiiScannerConfig(**config.model_dump())
        if not cfg.enabled:
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        vault = get_pii_vault()
        findings: list[dict[str, Any]] = []
        redactions: dict[str, str] = {}

        # Scan text in trusted_instructions, untrusted_data, output_payload
        # For PII, we typically mutate the text
        mutated_trusted = request.content.trusted_instructions
        mutated_untrusted = request.content.untrusted_data
        mutated_output = request.content.output_payload

        active_checks = []
        if cfg.detect_emails:
            active_checks.append(("EMAIL", self.PII_REGEXES["EMAIL"]))
        if cfg.detect_phone_numbers:
            active_checks.append(("PHONE", self.PII_REGEXES["PHONE"]))
        if cfg.detect_credit_cards:
            active_checks.append(("CREDIT_CARD", self.PII_REGEXES["CREDIT_CARD"]))
        if cfg.detect_ssn:
            active_checks.append(("SSN", self.PII_REGEXES["SSN"]))
        if cfg.detect_ipv4:
            active_checks.append(("IPV4", self.PII_REGEXES["IPV4"]))
        if cfg.detect_ipv6:
            active_checks.append(("IPV6", self.PII_REGEXES["IPV6"]))

        async def process_text(text: str) -> str:
            nonlocal findings, redactions
            if not text or not isinstance(text, str):
                return text

            # Bound scan size to prevent memory exhaustion / ReDoS
            max_len = get_settings().MAX_PAYLOAD_SCAN_BYTES
            scan_chunk = text[:max_len]
            tail_chunk = text[max_len:]

            new_text = scan_chunk
            for entity_type, regex in active_checks:
                for match in regex.finditer(scan_chunk):
                    val = match.group(0)
                    findings.append({
                        "entity_type": entity_type,
                        "value_prefix": val[:4] + "...",
                    })

                    replacement = val
                    if cfg.mode == "mask":
                        replacement = f"[REDACTED_{entity_type}]"
                    elif cfg.mode == "hash":
                        replacement = hashlib.sha256(val.encode()).hexdigest()[:12]
                    elif cfg.mode == "reversible_tokenize":
                        replacement = await vault.tokenize(
                            tenant_id=request.tenant_id,
                            session_id=request.session_id or "default_session",
                            entity_type=entity_type,
                            original_value=val,
                        )
                        redactions[replacement] = val

                    new_text = new_text.replace(val, replacement)
            return new_text + tail_chunk

        if isinstance(mutated_trusted, str):
            mutated_trusted = await process_text(mutated_trusted)
        if isinstance(mutated_untrusted, str):
            mutated_untrusted = await process_text(mutated_untrusted)
        if isinstance(mutated_output, str):
            mutated_output = await process_text(mutated_output)

        if not findings:
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        if cfg.mode == "block":
            status = "block"
        else:
            status = "flag"

        mutated_content_dict: dict[str, Any] = {}
        if mutated_trusted != request.content.trusted_instructions:
            mutated_content_dict["trusted_instructions"] = mutated_trusted
        if mutated_untrusted != request.content.untrusted_data:
            mutated_content_dict["untrusted_data"] = mutated_untrusted
        if mutated_output != request.content.output_payload:
            mutated_content_dict["output_payload"] = mutated_output

        return ScannerResult(
            scanner_name=self.name,
            tier=self.tier,
            status=status,
            score=0.8 if status == "block" else 0.4,
            details={"findings_count": len(findings), "entities": [f["entity_type"] for f in findings]},
            message=f"PII detected: {len(findings)} occurrence(s)",
            mutated_content=mutated_content_dict if mutated_content_dict else None,
            redaction_map=redactions if redactions else None,
        )

