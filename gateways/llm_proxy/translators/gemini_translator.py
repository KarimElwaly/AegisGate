import json
from typing import Any

from core.schemas.verdicts import EvaluationVerdict
from gateways.llm_proxy.translators.base import BaseProtocolTranslator


class GeminiProtocolTranslator(BaseProtocolTranslator):
    """Protocol translator for Google Gemini API (/proxy/gemini/v1beta/models/{model}:generateContent)."""

    protocol_name: str = "gemini"

    def extract_canonical_input(
        self, body: dict[str, Any], path_params: dict[str, str] | None = None
    ) -> tuple[str, str, list[dict[str, Any]], str, bool]:
        model = "gemini-1.5-flash"
        if path_params and "model" in path_params:
            model = path_params["model"]
        elif "model" in body:
            model = body["model"]

        # 1. systemInstruction -> trusted_instructions
        trusted = []
        sys_inst = body.get("systemInstruction", {})
        if isinstance(sys_inst, dict):
            parts = sys_inst.get("parts", [])
            for p in parts:
                if isinstance(p, dict) and "text" in p:
                    trusted.append(p["text"])
        elif isinstance(sys_inst, str):
            trusted.append(sys_inst)

        # 2. contents -> untrusted_data + attachments
        contents = body.get("contents", [])
        untrusted = []
        attachments = list(body.get("attachments", []))

        for entry in contents:
            if not isinstance(entry, dict):
                continue
            parts = entry.get("parts", [])
            for p in parts:
                if not isinstance(p, dict):
                    continue
                if "text" in p:
                    untrusted.append(p["text"])
                elif "inlineData" in p:
                    attachments.append(p["inlineData"])
                elif "fileData" in p:
                    attachments.append(p["fileData"])
                elif "functionCall" in p:
                    untrusted.append(f"functionCall:{json.dumps(p['functionCall'])}")
                elif "functionResponse" in p:
                    untrusted.append(f"functionResponse:{json.dumps(p['functionResponse'])}")

        stream = bool(body.get("stream", False))
        return "\n".join(trusted), "\n".join(untrusted), attachments, model, stream

    def extract_output_text(self, resp_json: dict[str, Any]) -> str:
        candidates = resp_json.get("candidates", [])
        texts = []
        for cand in candidates:
            content = cand.get("content", {})
            parts = content.get("parts", [])
            for p in parts:
                if isinstance(p, dict) and "text" in p:
                    texts.append(p["text"])
        return " ".join(texts)

    def apply_rehydrated_output(
        self, resp_json: dict[str, Any], rehydrated_text: str
    ) -> dict[str, Any]:
        candidates = resp_json.get("candidates", [])
        if candidates:
            content = candidates[0].get("content", {})
            content["parts"] = [{"text": rehydrated_text}]
        else:
            resp_json["candidates"] = [
                {"content": {"parts": [{"text": rehydrated_text}], "role": "model"}, "finishReason": "STOP"}
            ]
        return resp_json

    def extract_usage_tokens(self, resp_json: dict[str, Any]) -> tuple[int, int, int]:
        usage = resp_json.get("usageMetadata", {})
        prompt = usage.get("promptTokenCount", 0)
        completion = usage.get("candidatesTokenCount", 0)
        total = usage.get("totalTokenCount", prompt + completion)
        return prompt, completion, total

    def build_mock_completion(
        self, model: str, content: str, usage: dict[str, int]
    ) -> dict[str, Any]:
        prompt_tokens = usage.get("prompt_tokens", 15)
        completion_tokens = usage.get("completion_tokens", 10)
        total_tokens = usage.get("total_tokens", prompt_tokens + completion_tokens)
        return {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "text": content,
                            }
                        ],
                        "role": "model",
                    },
                    "finishReason": "STOP",
                    "index": 0,
                }
            ],
            "usageMetadata": {
                "promptTokenCount": prompt_tokens,
                "candidatesTokenCount": completion_tokens,
                "totalTokenCount": total_tokens,
            },
        }

    def build_mock_stream_chunks(
        self, model: str, text_chunks: list[str], usage: dict[str, int]
    ) -> list[bytes]:
        prompt_tokens = usage.get("prompt_tokens", 15)
        completion_tokens = usage.get("completion_tokens", 10)
        total_tokens = usage.get("total_tokens", prompt_tokens + completion_tokens)

        chunks: list[bytes] = []
        for i, text in enumerate(text_chunks):
            is_last = i == len(text_chunks) - 1
            payload: dict[str, Any] = {
                "candidates": [
                    {
                        "content": {
                            "parts": [{"text": text}],
                            "role": "model",
                        },
                        "finishReason": "STOP" if is_last else None,
                    }
                ]
            }
            if is_last:
                payload["usageMetadata"] = {
                    "promptTokenCount": prompt_tokens,
                    "candidatesTokenCount": completion_tokens,
                    "totalTokenCount": total_tokens,
                }
            chunks.append(f"data: {json.dumps(payload)}\n\n".encode("utf-8"))

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
                "code": 403,
                "message": f"AegisGate Policy Denied: {reason}",
                "status": "PERMISSION_DENIED",
                "details": [
                    {
                        "@type": "type.googleapis.com/aegisgate.PolicyViolation",
                        "verdict_id": verdict.verdict_id,
                        "stage": stage,
                        "triggered_rules": [r.model_dump() for r in verdict.triggered_rules],
                    }
                ],
            }
        }

    def apply_input_mutations(
        self, body: dict[str, Any], mutated_untrusted: str, mutated_trusted: str = ""
    ) -> dict[str, Any]:
        new_body = dict(body)
        if mutated_trusted:
            new_body["systemInstruction"] = {"parts": [{"text": mutated_trusted}]}
        contents = [dict(c) for c in new_body.get("contents", [])]
        for i in range(len(contents) - 1, -1, -1):
            if contents[i].get("role") in ("user", None) and mutated_untrusted:
                parts = contents[i].get("parts", [])
                for p in parts:
                    if isinstance(p, dict) and "text" in p:
                        p["text"] = mutated_untrusted
                        break
                break
        new_body["contents"] = contents
        return new_body

    def extract_stream_delta(self, chunk_obj: dict[str, Any]) -> str | None:
        candidates = chunk_obj.get("candidates", [])
        if candidates:
            content = candidates[0].get("content", {})
            parts = content.get("parts", [])
            for p in parts:
                if isinstance(p, dict) and "text" in p:
                    return p.get("text")
        return None

    def replace_stream_delta(self, chunk_obj: dict[str, Any], new_text: str) -> dict[str, Any]:
        candidates = chunk_obj.get("candidates", [])
        if candidates:
            content = candidates[0].get("content", {})
            parts = content.get("parts", [])
            for p in parts:
                if isinstance(p, dict) and "text" in p:
                    p["text"] = new_text
                    break
        return chunk_obj

    def extract_stream_usage(self, chunk_obj: dict[str, Any]) -> dict[str, int] | None:
        usage = chunk_obj.get("usageMetadata")
        if usage and isinstance(usage, dict):
            prompt = usage.get("promptTokenCount", 0)
            comp = usage.get("candidatesTokenCount", 0)
            total = usage.get("totalTokenCount", prompt + comp)
            return {"prompt_tokens": prompt, "completion_tokens": comp, "total_tokens": total}
        return None

    def build_stream_abort_chunk(self, reason: str) -> dict[str, Any]:
        return {
            "candidates": [
                {
                    "content": {
                        "parts": [{"text": f"\n[STREAM ABORTED BY AEGISGATE: {reason}]"}],
                        "role": "model",
                    },
                    "finishReason": "SAFETY",
                }
            ]
        }

