import json
from typing import Any

from core.schemas.verdicts import EvaluationVerdict
from gateways.llm_proxy.translators.base import BaseProtocolTranslator


class OpenAIProtocolTranslator(BaseProtocolTranslator):
    """Protocol translator for OpenAI-compatible Chat Completions API."""

    protocol_name: str = "openai"

    def extract_canonical_input(
        self, body: dict[str, Any], path_params: dict[str, str] | None = None
    ) -> tuple[str, str, list[dict[str, Any]], str, bool]:
        messages = body.get("messages", [])
        stream = bool(body.get("stream", False))
        model = body.get("model", "default-model")
        attachments = list(body.get("attachments", []))

        trusted = []
        untrusted = []
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if isinstance(content, list):
                text_parts = []
                for c in content:
                    if isinstance(c, dict):
                        if c.get("type") == "text":
                            text_parts.append(c.get("text", ""))
                        elif c.get("type") == "image_url":
                            attachments.append(c)
                content = " ".join(text_parts)
            content_str = str(content)

            if role in ("system", "developer"):
                trusted.append(content_str)
            else:
                untrusted.append(content_str)

        return "\n".join(trusted), "\n".join(untrusted), attachments, model, stream

    def extract_output_text(self, resp_json: dict[str, Any]) -> str:
        choices = resp_json.get("choices", [])
        if choices:
            msg = choices[0].get("message", {})
            return msg.get("content", "") or ""
        return ""

    def apply_rehydrated_output(
        self, resp_json: dict[str, Any], rehydrated_text: str
    ) -> dict[str, Any]:
        choices = resp_json.get("choices", [])
        if choices and "message" in choices[0]:
            choices[0]["message"]["content"] = rehydrated_text
        return resp_json

    def extract_usage_tokens(self, resp_json: dict[str, Any]) -> tuple[int, int, int]:
        usage = resp_json.get("usage", {})
        prompt = usage.get("prompt_tokens", 0)
        completion = usage.get("completion_tokens", 0)
        total = usage.get("total_tokens", prompt + completion)
        return prompt, completion, total

    def build_mock_completion(
        self, model: str, content: str, usage: dict[str, int]
    ) -> dict[str, Any]:
        prompt_tokens = usage.get("prompt_tokens", 15)
        completion_tokens = usage.get("completion_tokens", 12)
        total_tokens = usage.get("total_tokens", prompt_tokens + completion_tokens)
        return {
            "id": "chatcmpl-mock-aegis",
            "object": "chat.completion",
            "created": 1700000000,
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": content,
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": total_tokens,
            },
        }

    def build_mock_stream_chunks(
        self, model: str, text_chunks: list[str], usage: dict[str, int]
    ) -> list[bytes]:
        chunks: list[bytes] = []
        for text in text_chunks:
            payload = {"choices": [{"delta": {"content": text}}]}
            chunks.append(f"data: {json.dumps(payload)}\n\n".encode("utf-8"))

        prompt_tokens = usage.get("prompt_tokens", 15)
        completion_tokens = usage.get("completion_tokens", 10)
        total_tokens = usage.get("total_tokens", prompt_tokens + completion_tokens)

        usage_payload = {
            "choices": [],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": total_tokens,
            },
        }
        chunks.append(f"data: {json.dumps(usage_payload)}\n\n".encode("utf-8"))
        chunks.append(b"data: [DONE]\n\n")
        return chunks

    def build_policy_denied_response(
        self, verdict: EvaluationVerdict, stage: str
    ) -> dict[str, Any]:
        reason = (
            verdict.triggered_rules[0].reason
            if verdict.triggered_rules
            else "Policy Denied"
        )
        return {
            "error": {
                "message": f"AegisGate Policy Denied: {reason}",
                "type": "aegisgate_policy_violation",
                "code": f"{stage}_policy_denied",
                "verdict_id": verdict.verdict_id,
                "triggered_rules": [r.model_dump() for r in verdict.triggered_rules],
            }
        }

    def apply_input_mutations(
        self, body: dict[str, Any], mutated_untrusted: str, mutated_trusted: str = ""
    ) -> dict[str, Any]:
        new_body = dict(body)
        messages = [dict(m) for m in new_body.get("messages", [])]
        # Update user messages and system messages
        user_updated = False
        for i in range(len(messages) - 1, -1, -1):
            role = messages[i].get("role", "user")
            if role in ("system", "developer") and mutated_trusted:
                messages[i]["content"] = mutated_trusted
            elif role == "user" and not user_updated and mutated_untrusted:
                messages[i]["content"] = mutated_untrusted
                user_updated = True
        new_body["messages"] = messages
        return new_body

    def extract_stream_delta(self, chunk_obj: dict[str, Any]) -> str | None:
        choices = chunk_obj.get("choices", [])
        if choices:
            delta = choices[0].get("delta", {})
            return delta.get("content")
        return None

    def replace_stream_delta(self, chunk_obj: dict[str, Any], new_text: str) -> dict[str, Any]:
        choices = chunk_obj.get("choices", [])
        if choices:
            delta = choices[0].get("delta", {})
            delta["content"] = new_text
        return chunk_obj

    def extract_stream_usage(self, chunk_obj: dict[str, Any]) -> dict[str, int] | None:
        usage = chunk_obj.get("usage")
        if usage and isinstance(usage, dict):
            return {
                "prompt_tokens": usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0),
                "total_tokens": usage.get("total_tokens", 0),
            }
        return None

    def build_stream_abort_chunk(self, reason: str) -> dict[str, Any]:
        return {
            "choices": [
                {
                    "delta": {
                        "content": f"\n[STREAM ABORTED BY AEGISGATE: {reason}]"
                    },
                    "finish_reason": "content_filter",
                }
            ]
        }

