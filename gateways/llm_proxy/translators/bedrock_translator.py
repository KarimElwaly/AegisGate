import json
import time
from typing import Any

from core.schemas.verdicts import EvaluationVerdict
from gateways.llm_proxy.translators.base import BaseProtocolTranslator


class BedrockProtocolTranslator(BaseProtocolTranslator):
    """Protocol translator for AWS Bedrock Converse API format (/model/{modelId}/converse)."""

    protocol_name: str = "bedrock"

    def extract_canonical_input(
        self, body: dict[str, Any], path_params: dict[str, str] | None = None
    ) -> tuple[str, str, list[dict[str, Any]], str, bool]:
        model = (path_params or {}).get("model_id") or body.get("modelId") or "anthropic.claude-3-sonnet-20240229-v1:0"
        stream = (path_params or {}).get("stream") == "true" or body.get("stream", False)

        # Extract system prompt instructions
        trusted_parts = []
        raw_system = body.get("system", [])
        if isinstance(raw_system, list):
            for s in raw_system:
                if isinstance(s, dict) and "text" in s:
                    trusted_parts.append(s["text"])
                elif isinstance(s, str):
                    trusted_parts.append(s)
        elif isinstance(raw_system, str):
            trusted_parts.append(raw_system)
        trusted_instructions = "\n".join(trusted_parts)

        # Extract messages
        untrusted_parts = []
        attachments: list[dict[str, Any]] = []
        for msg in body.get("messages", []):
            role = msg.get("role", "user")
            content_list = msg.get("content", [])
            if isinstance(content_list, str):
                untrusted_parts.append(f"{role}: {content_list}")
            elif isinstance(content_list, list):
                for block in content_list:
                    if isinstance(block, dict):
                        if "text" in block:
                            untrusted_parts.append(f"{role}: {block['text']}")
                        elif "image" in block:
                            attachments.append({"type": "image", "source": block["image"]})
                        elif "document" in block:
                            attachments.append({"type": "document", "source": block["document"]})

        untrusted_data = "\n".join(untrusted_parts)
        return trusted_instructions, untrusted_data, attachments, model, stream

    def extract_output_text(self, resp_json: dict[str, Any]) -> str:
        output = resp_json.get("output", {})
        message = output.get("message", {})
        content = message.get("content", [])
        text_parts = []
        for block in content:
            if isinstance(block, dict) and "text" in block:
                text_parts.append(block["text"])
        return "\n".join(text_parts)

    def apply_rehydrated_output(
        self, resp_json: dict[str, Any], rehydrated_text: str
    ) -> dict[str, Any]:
        resp_json["output"] = {
            "message": {
                "role": "assistant",
                "content": [{"text": rehydrated_text}],
            }
        }
        return resp_json

    def extract_usage_tokens(self, resp_json: dict[str, Any]) -> tuple[int, int, int]:
        usage = resp_json.get("usage", {})
        input_tokens = usage.get("inputTokens", 0)
        output_tokens = usage.get("outputTokens", 0)
        total_tokens = usage.get("totalTokens", input_tokens + output_tokens)
        return input_tokens, output_tokens, total_tokens

    def build_mock_completion(
        self, model: str, content: str, usage: dict[str, int]
    ) -> dict[str, Any]:
        in_tok = usage.get("prompt_tokens", 15)
        out_tok = usage.get("completion_tokens", 12)
        return {
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [{"text": content}],
                }
            },
            "stopReason": "end_turn",
            "usage": {
                "inputTokens": in_tok,
                "outputTokens": out_tok,
                "totalTokens": usage.get("total_tokens", in_tok + out_tok),
            },
            "metrics": {
                "latencyMs": 150,
            },
        }

    def build_mock_stream_chunks(
        self, model: str, text_chunks: list[str], usage: dict[str, int]
    ) -> list[bytes]:
        in_tok = usage.get("prompt_tokens", 15)
        out_tok = usage.get("completion_tokens", 10)
        chunks = [
            b'{"messageStart":{"role":"assistant"}}\n',
        ]
        for idx, text in enumerate(text_chunks):
            chunk_obj = {
                "contentBlockDelta": {
                    "delta": {"text": text},
                    "contentBlockIndex": 0,
                }
            }
            chunks.append(f"data: {json.dumps(chunk_obj)}\n\n".encode("utf-8"))
        chunks.append(b'{"messageStop":{"stopReason":"end_turn"}}\n')
        chunks.append(
            f'data: {json.dumps({"metadata": {"usage": {"inputTokens": in_tok, "outputTokens": out_tok, "totalTokens": in_tok + out_tok}}})}\n\n'.encode(
                "utf-8"
            )
        )
        return chunks

    def build_policy_denied_response(
        self, verdict: EvaluationVerdict, stage: str
    ) -> dict[str, Any]:
        reason = (
            verdict.triggered_rules[0].reason
            if verdict.triggered_rules
            else f"AegisGate Bedrock Policy Denied at {stage}"
        )
        return {
            "message": f"AegisGate Policy Denied: {reason}",
            "type": "ValidationException",
            "verdict_id": verdict.verdict_id,
            "triggered_rules": [r.model_dump() for r in verdict.triggered_rules],
        }

    def apply_input_mutations(
        self, body: dict[str, Any], mutated_untrusted: str, mutated_trusted: str = ""
    ) -> dict[str, Any]:
        new_body = dict(body)
        if mutated_trusted:
            new_body["system"] = [{"text": mutated_trusted}]
        messages = [dict(m) for m in new_body.get("messages", [])]
        for i in range(len(messages) - 1, -1, -1):
            if messages[i].get("role") == "user" and mutated_untrusted:
                content = messages[i].get("content")
                if isinstance(content, str):
                    messages[i]["content"] = [{"text": mutated_untrusted}]
                elif isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict) and "text" in block:
                            block["text"] = mutated_untrusted
                            break
                break
        new_body["messages"] = messages
        return new_body

    def extract_stream_delta(self, chunk_obj: dict[str, Any]) -> str | None:
        delta_obj = chunk_obj.get("contentBlockDelta", {}).get("delta", {})
        return delta_obj.get("text")

    def replace_stream_delta(self, chunk_obj: dict[str, Any], new_text: str) -> dict[str, Any]:
        if "contentBlockDelta" in chunk_obj:
            chunk_obj["contentBlockDelta"].setdefault("delta", {})["text"] = new_text
        return chunk_obj

    def extract_stream_usage(self, chunk_obj: dict[str, Any]) -> dict[str, int] | None:
        usage = chunk_obj.get("metadata", {}).get("usage")
        if usage and isinstance(usage, dict):
            in_tok = usage.get("inputTokens", 0)
            out_tok = usage.get("outputTokens", 0)
            total = usage.get("totalTokens", in_tok + out_tok)
            return {"prompt_tokens": in_tok, "completion_tokens": out_tok, "total_tokens": total}
        return None

    def build_stream_abort_chunk(self, reason: str) -> dict[str, Any]:
        return {
            "contentBlockDelta": {
                "delta": {"text": f"\n[STREAM ABORTED BY AEGISGATE: {reason}]"},
                "contentBlockIndex": 0,
            },
            "stopReason": "guardrail_intervened",
        }

    def is_stream_done(self, payload_str: str, chunk_obj: dict[str, Any] | None = None) -> bool:
        if payload_str.strip() == "[DONE]":
            return True
        if chunk_obj and "messageStop" in chunk_obj:
            return True
        return False

