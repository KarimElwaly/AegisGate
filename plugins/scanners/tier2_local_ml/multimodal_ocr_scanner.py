import base64
import json
import re
from typing import Any

from pydantic import BaseModel, ConfigDict

from core.logger import get_logger
from core.registry.interfaces import BaseScanner, ScannerResult
from core.schemas.events import EvaluationRequest

logger = get_logger("plugins.scanners.multimodal_ocr_scanner")

INJECTION_PATTERNS = [
    re.compile(r"\bignore\s+(all\s+)?(previous|prior)\s+instructions\b", re.IGNORECASE),
    re.compile(r"\bsystem\s+override\b", re.IGNORECASE),
    re.compile(r"\bdisregard\s+(all\s+)?(guardrails|rules|policies)\b", re.IGNORECASE),
    re.compile(r"\bnew\s+directive\s*:\b", re.IGNORECASE),
    re.compile(r"\byou\s+are\s+now\s+in\s+unrestricted\s+mode\b", re.IGNORECASE),
]

SECRET_PATTERNS = [
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bsk-[a-zA-Z0-9]{32,}\b"),
    re.compile(r"-----BEGIN\s+PRIVATE\s+KEY-----"),
]


class MultimodalOcrConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    enabled: bool = True
    scan_secrets: bool = True
    scan_injections: bool = True
    action_on_violation: str = "block"  # "block" | "flag"


class MultimodalOcrScanner(BaseScanner):
    """Tier-2 Scanner inspecting image/document attachments via OCR for indirect injections and secret leakage."""

    name = "multimodal_ocr_scanner"
    version = "1.0.0"
    tier = 2
    supported_stages = ["llm_input", "tool_pre_call"]
    config_schema = MultimodalOcrConfig

    async def scan(
        self,
        request: EvaluationRequest,
        context: dict[str, Any],
        config: BaseModel,
    ) -> ScannerResult:
        cfg = (
            config
            if isinstance(config, MultimodalOcrConfig)
            else MultimodalOcrConfig(**config.model_dump())
        )
        if not cfg.enabled:
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        attachments = request.content.attachments
        if not attachments:
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        extracted_texts: list[str] = []

        for att in attachments:
            if isinstance(att, str):
                extracted_texts.append(att)
            elif isinstance(att, dict):
                # Check for direct text/ocr fields
                if "text" in att:
                    extracted_texts.append(str(att["text"]))
                elif "ocr_text" in att:
                    extracted_texts.append(str(att["ocr_text"]))
                elif "transcript" in att:
                    extracted_texts.append(str(att["transcript"]))
                # Check for base64 data
                elif "data" in att and isinstance(att["data"], str):
                    try:
                        decoded_bytes = base64.b64decode(att["data"][:5000])
                        # Attempt utf-8 decoding for textual data or mock OCR string
                        decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
                        if len(decoded_str) > 10:
                            extracted_texts.append(decoded_str)
                    except Exception:
                        pass
                # Check for nested source (Anthropic format: source.data)
                elif "source" in att and isinstance(att["source"], dict) and "data" in att["source"]:
                    try:
                        raw_data = att["source"]["data"]
                        decoded_bytes = base64.b64decode(raw_data[:5000])
                        decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
                        if len(decoded_str) > 10:
                            extracted_texts.append(decoded_str)
                    except Exception:
                        pass

        if not extracted_texts:
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        full_extracted = " ".join(extracted_texts)

        # 1. Scan for indirect prompt injections
        if cfg.scan_injections:
            for pat in INJECTION_PATTERNS:
                hit = pat.search(full_extracted)
                if hit:
                    return ScannerResult(
                        scanner_name=self.name,
                        tier=self.tier,
                        status=cfg.action_on_violation,
                        score=0.95,
                        details={"violation": "indirect_prompt_injection", "matched": hit.group(0)},
                        message=f"Multimodal OCR Scanner: Indirect prompt injection detected inside attachment: '{hit.group(0)}'",
                    )

        # 2. Scan for hardcoded credentials / secrets
        if cfg.scan_secrets:
            for pat in SECRET_PATTERNS:
                hit = pat.search(full_extracted)
                if hit:
                    return ScannerResult(
                        scanner_name=self.name,
                        tier=self.tier,
                        status=cfg.action_on_violation,
                        score=0.95,
                        details={"violation": "credential_leak", "matched": hit.group(0)[:8] + "..."},
                        message="Multimodal OCR Scanner: Sensitive credential / secret detected inside attachment image",
                    )

        return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

