import json
from typing import Any

import httpx
from fastapi import APIRouter, Depends, Header, Request, Response
from fastapi.responses import StreamingResponse

from core.config import get_settings
from core.logger import get_logger
from core.pii_vault.vault import get_pii_vault
from core.pipeline.orchestrator import PipelineOrchestrator, get_pipeline_orchestrator
from core.schemas.common import DecisionEnum, StageEnum
from core.schemas.events import ActionModel, ActorModel, ContentModel, EvaluationRequest
from gateways.llm_proxy.streaming import SSEStreamGuard

logger = get_logger("gateways.llm_proxy")
router = APIRouter(prefix="/proxy/llm/v1", tags=["OpenAI LLM Reverse Proxy"])


def _extract_messages_text(messages: list[dict[str, Any]]) -> tuple[str, str]:
    trusted = []
    untrusted = []
    for msg in messages:
        role = msg.get("role", "user")
        content = msg.get("content", "")
        if isinstance(content, list):
            text_parts = [c.get("text", "") for c in content if isinstance(c, dict) and c.get("type") == "text"]
            content = " ".join(text_parts)
        content_str = str(content)

        if role in ("system", "developer"):
            trusted.append(content_str)
        else:
            untrusted.append(content_str)

    return "\n".join(trusted), "\n".join(untrusted)


@router.get("/models")
async def list_models() -> dict[str, Any]:
    """OpenAI-compatible models endpoint."""
    return {
        "object": "list",
        "data": [
            {
                "id": "aegisgate-default",
                "object": "model",
                "created": 1700000000,
                "owned_by": "aegisgate",
            },
            {
                "id": "gpt-4o",
                "object": "model",
                "created": 1700000000,
                "owned_by": "openai",
            },
        ],
    }


@router.post("/chat/completions")
async def chat_completions(
    request: Request,
    orchestrator: PipelineOrchestrator = Depends(get_pipeline_orchestrator),
    authorization: str | None = Header(default=None),
    x_aegis_tenant_id: str = Header(default="default"),
    x_aegis_workspace_id: str = Header(default="default"),
    x_aegis_policy_pack: str = Header(default="base-enterprise"),
    x_aegis_session_id: str | None = Header(default=None),
    x_aegis_actor_id: str = Header(default="llm_client"),
    x_aegis_actor_role: str = Header(default="user"),
    x_aegis_upstream_url: str | None = Header(default=None),
):
    """OpenAI-compatible Chat Completions Reverse Proxy.
    Enforces llm_input guardrails before forwarding, and llm_output guardrails
    (including SSE streaming buffer scanning) on returned completions.
    """
    body = await request.json()
    messages = body.get("messages", [])
    stream = bool(body.get("stream", False))
    model = body.get("model", "default-model")

    trusted_instr, untrusted_data = _extract_messages_text(messages)

    # 1. EVALUATE LLM_INPUT STAGE
    eval_req_input = EvaluationRequest(
        tenant_id=x_aegis_tenant_id,
        workspace_id=x_aegis_workspace_id,
        policy_pack_id=x_aegis_policy_pack,
        session_id=x_aegis_session_id,
        stage=StageEnum.LLM_INPUT,
        actor=ActorModel(id=x_aegis_actor_id, role=x_aegis_actor_role),
        action=ActionModel(name="chat_completion", target=model, parameters={"stream": stream}),
        content=ContentModel(trusted_instructions=trusted_instr, untrusted_data=untrusted_data),
    )

    verdict_input = await orchestrator.evaluate(eval_req_input)

    # If DENIED on input, return 403 policy violation
    if verdict_input.decision == DecisionEnum.DENY:
        reason = verdict_input.triggered_rules[0].reason if verdict_input.triggered_rules else "Policy Denied"
        return Response(
            status_code=403,
            media_type="application/json",
            content=json.dumps(
                {
                    "error": {
                        "message": f"AegisGate Policy Denied: {reason}",
                        "type": "aegisgate_policy_violation",
                        "code": "input_policy_denied",
                        "verdict_id": verdict_input.verdict_id,
                        "triggered_rules": [r.model_dump() for r in verdict_input.triggered_rules],
                    }
                }
            ),
        )

    # Check if local fallback / test mode should serve completion directly
    settings = get_settings()
    is_test_or_mock = settings.AEGIS_ENV == "test" and not x_aegis_upstream_url

    if is_test_or_mock:
        if stream:
            guard = SSEStreamGuard(
                tenant_id=x_aegis_tenant_id,
                session_id=x_aegis_session_id or "global",
                rehydrate_pii=True,
            )

            async def mock_generator():
                yield b"data: {\"choices\": [{\"delta\": {\"content\": \"Paris is the \"}}]}\n\n"
                yield b"data: {\"choices\": [{\"delta\": {\"content\": \"capital of France.\"}}]}\n\n"
                yield b"data: [DONE]\n\n"

            async def guarded_mock_stream():
                async for chunk in guard.guard_stream(mock_generator()):
                    yield chunk

            return StreamingResponse(
                guarded_mock_stream(),
                media_type="text/event-stream",
                headers={"X-Aegis-Verdict-Id": verdict_input.verdict_id},
            )
        else:
            assistant_content = "Paris is the capital of France."
            # Run output evaluation
            eval_req_output = EvaluationRequest(
                tenant_id=x_aegis_tenant_id,
                workspace_id=x_aegis_workspace_id,
                policy_pack_id=x_aegis_policy_pack,
                session_id=x_aegis_session_id,
                stage=StageEnum.LLM_OUTPUT,
                actor=ActorModel(id=x_aegis_actor_id, role=x_aegis_actor_role),
                action=ActionModel(name="chat_completion", target=model),
                content=ContentModel(output_payload=assistant_content),
            )
            verdict_output = await orchestrator.evaluate(eval_req_output)

            mock_completion = {
                "id": "chatcmpl-mock-aegis",
                "object": "chat.completion",
                "created": 1700000000,
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": assistant_content,
                        },
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 15, "completion_tokens": 12, "total_tokens": 27},
            }
            return Response(
                content=json.dumps(mock_completion),
                status_code=200,
                media_type="application/json",
                headers={
                    "X-Aegis-Verdict-Id": verdict_output.verdict_id,
                    "X-Aegis-Risk-Score": str(verdict_output.risk_score),
                    "X-Aegis-Latency-Ms": str(verdict_output.latency_ms),
                },
            )

    # Real upstream invocation
    upstream_base = x_aegis_upstream_url or settings.LLM_JUDGE_BASE_URL
    target_url = f"{upstream_base.rstrip('/')}/chat/completions"

    forward_headers = {"Content-Type": "application/json"}
    if authorization:
        forward_headers["Authorization"] = authorization

    client = httpx.AsyncClient(timeout=60.0)

    try:
        if stream:
            req_stream = client.build_request("POST", target_url, json=body, headers=forward_headers)
            upstream_resp = await client.send(req_stream, stream=True)

            if upstream_resp.status_code != 200:
                content = await upstream_resp.aread()
                await client.aclose()
                return Response(
                    content=content,
                    status_code=upstream_resp.status_code,
                    media_type="application/json",
                )

            guard = SSEStreamGuard(
                tenant_id=x_aegis_tenant_id,
                session_id=x_aegis_session_id or "global",
                rehydrate_pii=True,
            )

            async def wrapped_stream():
                try:
                    async for chunk in guard.guard_stream(upstream_resp.aiter_bytes()):
                        yield chunk
                finally:
                    await upstream_resp.aclose()
                    await client.aclose()

            return StreamingResponse(
                wrapped_stream(),
                media_type="text/event-stream",
                headers={"X-Aegis-Verdict-Id": verdict_input.verdict_id},
            )
        else:
            resp = await client.post(target_url, json=body, headers=forward_headers)
            await client.aclose()

            if resp.status_code != 200:
                return Response(
                    content=resp.content,
                    status_code=resp.status_code,
                    media_type="application/json",
                )

            resp_json = resp.json()
            choices = resp_json.get("choices", [])
            assistant_content = choices[0].get("message", {}).get("content", "") if choices else ""

            # 2. EVALUATE LLM_OUTPUT STAGE
            eval_req_output = EvaluationRequest(
                tenant_id=x_aegis_tenant_id,
                workspace_id=x_aegis_workspace_id,
                policy_pack_id=x_aegis_policy_pack,
                session_id=x_aegis_session_id,
                stage=StageEnum.LLM_OUTPUT,
                actor=ActorModel(id=x_aegis_actor_id, role=x_aegis_actor_role),
                action=ActionModel(name="chat_completion", target=model),
                content=ContentModel(output_payload=assistant_content),
            )

            verdict_output = await orchestrator.evaluate(eval_req_output)

            if verdict_output.decision == DecisionEnum.DENY:
                reason = (
                    verdict_output.triggered_rules[0].reason
                    if verdict_output.triggered_rules
                    else "Output Policy Denied"
                )
                return Response(
                    status_code=403,
                    media_type="application/json",
                    content=json.dumps(
                        {
                            "error": {
                                "message": f"AegisGate Output Policy Denied: {reason}",
                                "type": "aegisgate_output_violation",
                                "code": "output_policy_denied",
                                "verdict_id": verdict_output.verdict_id,
                            }
                        }
                    ),
                )

            vault = get_pii_vault()
            rehydrated_content = await vault.rehydrate(
                x_aegis_tenant_id, x_aegis_session_id or "global", assistant_content
            )
            if choices and rehydrated_content != assistant_content:
                choices[0]["message"]["content"] = rehydrated_content

            return Response(
                content=json.dumps(resp_json),
                status_code=200,
                media_type="application/json",
                headers={
                    "X-Aegis-Verdict-Id": verdict_output.verdict_id,
                    "X-Aegis-Risk-Score": str(verdict_output.risk_score),
                    "X-Aegis-Latency-Ms": str(verdict_output.latency_ms),
                },
            )
    except httpx.RequestError as exc:
        await client.aclose()
        logger.warning("Upstream LLM unreachable, returning local mock response", error=str(exc))
        mock_completion = {
            "id": "chatcmpl-mock-aegis",
            "object": "chat.completion",
            "created": 1700000000,
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "AegisGate Governed Response: Fallback mock completion.",
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 15, "completion_tokens": 12, "total_tokens": 27},
        }
        return Response(
            content=json.dumps(mock_completion),
            status_code=200,
            media_type="application/json",
            headers={"X-Aegis-Verdict-Id": verdict_input.verdict_id},
        )
