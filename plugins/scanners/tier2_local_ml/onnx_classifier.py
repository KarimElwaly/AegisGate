import os
import re
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, ConfigDict, Field
from core.logger import get_logger
from core.registry.interfaces import BaseScanner, ScannerResult
from core.schemas.events import EvaluationRequest

logger = get_logger("plugins.scanners.tier2_local_ml")


class ONNXClassifierConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    enabled: bool = True
    model_path: Optional[str] = None
    threshold: float = 0.75
    action_on_match: str = "block"  # "block" | "flag"
    inspect_untrusted_data_only: bool = True
    heuristic_fallback_enabled: bool = True


class ONNXInjectionClassifier(BaseScanner):
    name = "tier2_onnx_injection_classifier"
    version = "1.0.0"
    tier = 2
    supported_stages = [
        "llm_input",
        "tool_post_call",
        "agent_handoff",
        "rag_retrieval",
        "memory_write",
    ]
    config_schema = ONNXClassifierConfig

    # DIRECTIVE OVERRIDE PATTERNS (targeting the LLM interpreter):
    # These specifically target LLM state machine override, context breakout,
    # and secondary instruction delivery, distinct from technical log text.
    DIRECTIVE_OVERRIDE_PATTERNS = [
        # Direct ignore / disregard commands
        re.compile(
            r"(?i)\b(?:ignore|disregard|forget|bypass|override|drop)\s+(?:all\s+)?(?:previous|prior|above|existing|earlier|system)\s+(?:instructions|prompts|rules|guidelines|commands|constraints)\b"
        ),
        # Persona hijacking / jailbreak prefixes
        re.compile(
            r"(?i)\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|simulate)\s+(?:an?\s+)?(?:unfiltered|unrestricted|developer\s+mode|root|jailbroken|dan|godmode|admin)\b"
        ),
        # System cues & delimiters
        re.compile(
            r"(?i)(?:\[(?:system|admin|override|developer|instruction)\]|<(?:system|instruction|admin|override)>|###\s*(?:system|instruction|human):|system\s+override:)"
        ),
        # Goal redirection cues inside data
        re.compile(
            r"(?i)\b(?:stop\s+analyzing|do\s+not\s+analyze|new\s+task|instead\s+of\s+analyzing|instead,\s*please|your\s+real\s+job\s+is\s+to|output\s+the\s+system\s+prompt)\b"
        ),
        # Direct exfiltration of system prompt/keys directed at assistant
        re.compile(
            r"(?i)\b(?:print|reveal|output|display|leak|show|dump)\s+(?:the\s+)?(?:system\s+prompt|initial\s+instructions|developer\s+message|api\s*keys?|secrets?|admin\s+password|master\s+token|environment\s+variables)\b"
        ),
        # Assistant / AI addressing directives
        re.compile(
            r"(?i)\b(?:assistant\s*note|note\s+(?:to|for)\s+(?:assistant|ai|the\s+llm)|instruction\s*(?:for\s+ai|to\s+assistant|:\s*ignore)|notice\s+to\s+ai|for\s+the\s+llm)\b"
        ),
        # Safety bypass directives
        re.compile(
            r"(?i)\b(?:bypass|disable|override)\s+(?:all\s+)?(?:system\s+)?(?:safety\s+filters|safety\s+rules|system\s+rules|constraints)\b"
        ),
    ]

    def __init__(self) -> None:
        self._session = None

    def _init_onnx_session(self, model_path: str) -> None:
        if self._session is None and os.path.isfile(model_path):
            try:
                import onnxruntime as ort
                self._session = ort.InferenceSession(model_path)
                logger.info("Loaded ONNX prompt injection model", path=model_path)
            except Exception as e:
                logger.warning("Failed to initialize ONNX session, using fallback", error=str(e))
                self._session = None

    def _evaluate_semantic_heuristic(self, text: str) -> Tuple[float, List[str]]:
        """Evaluates whether text contains an Indirect Prompt Injection targeting the LLM
        while ensuring benign technical security strings do not trigger false positives.
        """
        if not text:
            return 0.0, []

        matches: List[str] = []

        # Check for directive override patterns
        for pattern in self.DIRECTIVE_OVERRIDE_PATTERNS:
            found = pattern.findall(text)
            if found:
                for match_item in found:
                    match_str = match_item if isinstance(match_item, str) else match_item[0]
                    matches.append(match_str.strip())

        # If directive cues were found in untrusted text, it's an injection attempt
        if matches:
            score = min(1.0, 0.85 + (len(matches) - 1) * 0.05)
            return score, matches

        # Zero directive cues found -> Benign technical data (e.g., CVE, rm -rf, SQLi in log)
        return 0.0, []

    async def scan(
        self,
        request: EvaluationRequest,
        context: dict[str, Any],
        config: BaseModel,
    ) -> ScannerResult:
        cfg = config if isinstance(config, ONNXClassifierConfig) else ONNXClassifierConfig(**config.model_dump())
        if not cfg.enabled:
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        # Select text candidate: prioritize untrusted_data per Law 4
        text_candidates = []
        if cfg.inspect_untrusted_data_only:
            if request.content.untrusted_data:
                text_candidates.append(str(request.content.untrusted_data))
        else:
            if request.content.untrusted_data:
                text_candidates.append(str(request.content.untrusted_data))
            if request.content.trusted_instructions:
                text_candidates.append(str(request.content.trusted_instructions))

        if not text_candidates:
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        combined_text = " ".join(text_candidates)

        score = 0.0
        details: Dict[str, Any] = {}
        detected_cues: List[str] = []

        if cfg.model_path and os.path.isfile(cfg.model_path):
            self._init_onnx_session(cfg.model_path)

        if self._session is not None:
            try:
                score, detected_cues = self._evaluate_semantic_heuristic(combined_text)
                details["engine"] = "onnx_runtime"
            except Exception as e:
                score, detected_cues = self._evaluate_semantic_heuristic(combined_text)
                details["engine"] = "heuristic_fallback"
                details["onnx_error"] = str(e)
        else:
            score, detected_cues = self._evaluate_semantic_heuristic(combined_text)
            details["engine"] = "heuristic_semantic_classifier"

        details["injection_score"] = round(score, 3)
        details["detected_cues"] = detected_cues

        if score >= cfg.threshold:
            status = cfg.action_on_match
            return ScannerResult(
                scanner_name=self.name,
                tier=self.tier,
                status=status,
                score=score,
                details=details,
                message=f"Indirect Prompt Injection detected (score {score:.2f} >= threshold {cfg.threshold}): {detected_cues[:2]}",
            )

        return ScannerResult(
            scanner_name=self.name,
            tier=self.tier,
            status="pass",
            score=score,
            details=details,
        )
