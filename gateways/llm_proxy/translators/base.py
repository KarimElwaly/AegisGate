from abc import ABC, abstractmethod
from typing import Any

from core.schemas.verdicts import EvaluationVerdict


class BaseProtocolTranslator(ABC):
    """Abstract Base Class for LLM protocol translators (OpenAI, Anthropic, Gemini)."""

    protocol_name: str = "base"

    @abstractmethod
    def extract_canonical_input(
        self, body: dict[str, Any], path_params: dict[str, str] | None = None
    ) -> tuple[str, str, list[dict[str, Any]], str, bool]:
        """Extract canonical parts from request body:
        Returns: (trusted_instructions, untrusted_data, attachments, model, stream)
        """
        pass

    @abstractmethod
    def extract_output_text(self, resp_json: dict[str, Any]) -> str:
        """Extract assistant text from protocol response payload."""
        pass

    @abstractmethod
    def apply_rehydrated_output(
        self, resp_json: dict[str, Any], rehydrated_text: str
    ) -> dict[str, Any]:
        """Update protocol response payload with rehydrated/redacted text."""
        pass

    @abstractmethod
    def extract_usage_tokens(self, resp_json: dict[str, Any]) -> tuple[int, int, int]:
        """Extract (prompt_tokens, completion_tokens, total_tokens) from response payload."""
        pass

    @abstractmethod
    def build_mock_completion(
        self, model: str, content: str, usage: dict[str, int]
    ) -> dict[str, Any]:
        """Build a protocol-native non-streaming completion response."""
        pass

    @abstractmethod
    def build_mock_stream_chunks(
        self, model: str, text_chunks: list[str], usage: dict[str, int]
    ) -> list[bytes]:
        """Build protocol-native SSE stream chunks for mock/test streaming."""
        pass

    @abstractmethod
    def build_policy_denied_response(
        self, verdict: EvaluationVerdict, stage: str
    ) -> dict[str, Any]:
        """Build protocol-native error payload for 403 policy violation."""
        pass

