import json
import uuid
from typing import Any

from core.schemas.verdicts import EvaluationVerdict
from gateways.llm_proxy.translators.base import BaseProtocolTranslator


class AnthropicProtocolTranslator(BaseProtocolTranslator):
    """Protocol translator for Anthropic Messages API (/proxy/anthropic/v1/messages)."""

    protocol_name: str = "anthropic"

    def extract_canonical_input(
        self, body: dict[str, Any], path_params: dict[str, str] | None = None
    ) -> tuple[str, str, list[dict[str, Any]], str, bool]:
        system_val = body.get("system", "")
        trusted = []
        if isinstance(system_val, str):
            if system_val.strip():
                trusted.append(system_val)
        elif isinstance(system_val, list):
            for block in system_val:
                if isinstance(block, dict) and block.get("type") == "text":
                    trusted.append(block.get("text", ""))

        messages = body.get("messages", [])
        stream = bool(body.get("stream", False))
        model = body.get("model", "claude-3-5-sonnet-20241022")
        attachments = list(body.get("attachments", []))

        untrusted = []
        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, str):
                untrusted.append(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict):
                        btype = block.get("type")
                        if btype == "text":
                            untrusted.append(block.get("text", ""))
                        elif btype == "image":
                            attachments.append(block)
                        elif btype == "tool_use":
                            untrusted.append(f"tool_use:{block.get('name')}:{json.dumps(block.get('input', {}))}")
                        elif btype == "tool_result":
                            untrusted.append(f"tool_result:{block.get('content', '')}")

        return "\n".join(trusted), "\n".join(untrusted), attachments, model, stream

    def extract_output_text(self, resp_json: dict[str, Any]) -> str:
        contents = resp_json.get("content", [])
        texts = []
        for c in contents:
            if isinstance(c, dict) and c.get("type") == "text":
                texts.append(c.get("text", ""))
        return " ".join(texts)

    def apply_rehydrated_output(
        self, resp_json: dict[str, Any], rehydrated_text: str
    ) -> dict[str, Any]:
        contents = resp_json.get("content", [])
        # Replace or update first text block
        updated = False
        for c in contents:
            if isinstance(c, dict) and c.get("type") == "text":
                c["text"] = rehydrated_text
                updated = True
                break
        if not updated:
            resp_json["content"] = [{"type": "text", "text": rehydrated_text}]
        return resp_json

    def extract_usage_tokens(self, resp_json: dict[str, Any]) -> tuple[int, int, int]:
        usage = resp_json.get("usage", {})
        prompt = usage.get("input_tokens", 0)
        completion = usage.get("output_tokens", 0)
        total = prompt + completion
        return prompt, completion, total

    def build_mock_completion(
        self, model: str, content: str, usage: dict[str, int]
    ) -> dict[str, Any]:
        prompt_tokens = usage.get("prompt_tokens", 15)
        completion_tokens = usage.get("completion_tokens", 12)
        return {
            "id": f"msg_{uuid.uuid4().hex[:20]}",
            "type": "message",
            "role": "assistant",
            "content": [
                {
                    "type": "text",
                    "text": content,
                }
            ],
            "model": model,
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "usage": {
                "input_tokens": prompt_tokens,
                "output_tokens": completion_tokens,
            },
        }

    def build_mock_stream_chunks(
        self, model: str, text_chunks: list[str], usage: dict[str, int]
    ) -> list[bytes]:
        msg_id = f"msg_{uuid.uuid4().hex[:20]}"
        prompt_tokens = usage.get("prompt_tokens", 15)
        completion_tokens = usage.get("completion_tokens", 10)

        chunks: list[bytes] = []

        # 1. message_start
        m_start = {
            "type": "message_start",
            "message": {
                "id": msg_id,
                "type": "message",
                "role": "assistant",
                "content": [],
                "model": model,
                "stop_reason": None,
                "stop_sequence": None,
                "usage": {"input_tokens": prompt_tokens, "output_tokens": 1},
            },
        }
        chunks.append(f"event: message_start\ndata: {json.dumps(m_start)}\n\n".encode("utf-8"))

        # 2. content_block_start
        cb_start = {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}
        chunks.append(f"event: content_block_start\ndata: {json.dumps(cb_start)}\n\n".encode("utf-8"))

        # 3. content_block_delta for each text piece
        for text in text_chunks:
            delta = {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": text},
            }
            chunks.append(f"event: content_block_delta\ndata: {json.dumps(delta)}\n\n".encode("utf-8"))

        # 4. content_block_stop
        cb_stop = {"type": "content_block_stop", "index": 0}
        chunks.append(f"event: content_block_stop\ndata: {json.dumps(cb_stop)}\n\n".encode("utf-8"))

        # 5. message_delta with usage
        m_delta = {
            "type": "message_delta",
            "delta": {"stop_reason": "end_turn", "stop_sequence": None},
            "usage": {"output_tokens": completion_tokens},
        }
        chunks.append(f"event: message_delta\ndata: {json.dumps(m_delta)}\n\n".encode("utf-8"))

        # 6. message_stop
        m_stop = {"type": "message_stop"}
        chunks.append(f"event: message_stop\ndata: {json.dumps(m_stop)}\n\n".encode("utf-8"))

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
            "type": "error",
            "error": {
                "type": "permission_error",
                "message": f"AegisGate Policy Denied: {reason}",
                "verdict_id": verdict.verdict_id,
                "code": f"{stage}_policy_denied",
            },
        }

