import json
from typing import Any

import httpx
from fastapi import Request, Response
from fastapi.responses import StreamingResponse

from core.config import get_settings
from core.governance.budgets import get_budget_manager
from core.governance.taint_tracker import get_taint_tracker
from core.logger import get_logger
from core.pii_vault.vault import get_pii_vault
from core.pipeline.orchestrator import PipelineOrchestrator
from core.schemas.common import DecisionEnum, StageEnum
from core.schemas.events import ActionModel, ActorModel, ContentModel, EvaluationRequest
from core.telemetry import record_proxy_request
from gateways.llm_proxy.streaming import SSEStreamGuard
from gateways.llm_proxy.translators.base import BaseProtocolTranslator

logger = get_logger("gateways.llm_proxy.core_handler")


async def execute_proxy_request(
    request: Request,
    body: dict[str, Any],
    translator: BaseProtocolTranslator,
    orchestrator: PipelineOrchestrator,
    authorization: str | None = None,
    x_aegis_tenant_id: str = "default",
    x_aegis_workspace_id: str = "default",
    x_aegis_policy_pack: str = "base-enterprise",
    x_aegis_session_id: str | None = None,
    x_aegis_actor_id: str = "llm_client",
    x_aegis_actor_role: str = "user",
    x_aegis_upstream_url: str | None = None,
    path_params: dict[str, str] | None = None,
    force_stream: bool = False,
) -> Response:
    """Universal execution handler for any LLM protocol (OpenAI, Anthropic, Gemini)."""
    trusted_instr, untrusted_data, attachments, model, stream = translator.extract_canonical_input(
        body, path_params
    )
    if force_stream:
        stream = True

    # 1. EVALUATE LLM_INPUT STAGE
    eval_req_input = EvaluationRequest(
        tenant_id=x_aegis_tenant_id,
        workspace_id=x_aegis_workspace_id,
        policy_pack_id=x_aegis_policy_pack,
        session_id=x_aegis_session_id,
        stage=StageEnum.LLM_INPUT,
        actor=ActorModel(id=x_aegis_actor_id, role=x_aegis_actor_role),
        action=ActionModel(name="chat_completion", target=model, parameters={"stream": stream}),
        content=ContentModel(
            trusted_instructions=trusted_instr,
            untrusted_data=untrusted_data,
            attachments=attachments,
        ),
    )

    verdict_input = await orchestrator.evaluate(eval_req_input)

    # Check session sovereignty requirements
    session_taints: set[str] = set()
    if x_aegis_session_id:
        try:
            session_taints = await get_taint_tracker().get_taints(x_aegis_tenant_id, x_aegis_session_id)
        except Exception:
            pass

    is_sovereign = (
        "local_only" in session_taints
        or "confidential_pii" in session_taints
        or request.headers.get("x-aegis-route-tier") == "local_only"
        or any("route_to_tier: local_only" in (r.reason or "") for r in verdict_input.triggered_rules)
    )
    routed_provider = "local-sovereign" if is_sovereign else "upstream-cloud"

    # If DENIED on input, return 403 protocol-native error
    if verdict_input.decision == DecisionEnum.DENY:
        record_proxy_request(translator.protocol_name, "denied")
        denied_payload = translator.build_policy_denied_response(verdict_input, "input")
        return Response(
            status_code=403,
            media_type="application/json",
            content=json.dumps(denied_payload),
            headers={"X-Aegis-Verdict-Id": verdict_input.verdict_id},
        )

    settings = get_settings()
    is_test_or_mock = settings.AEGIS_ENV == "test" and not x_aegis_upstream_url

    if is_test_or_mock:
        if stream:
            guard = SSEStreamGuard(
                tenant_id=x_aegis_tenant_id,
                session_id=x_aegis_session_id or "global",
                rehydrate_pii=True,
                estimated_prompt_tokens=eval_req_input.action.estimated_tokens,
                actor_id=x_aegis_actor_id,
                actor_role=x_aegis_actor_role,
                model=model,
                policy_pack_id=x_aegis_policy_pack,
            )

            mock_chunks = translator.build_mock_stream_chunks(
                model=model,
                text_chunks=["Paris is the ", "capital of France."],
                usage={"prompt_tokens": 15, "completion_tokens": 10},
            )

            async def mock_generator():
                for c in mock_chunks:
                    yield c

            async def guarded_mock_stream():
                async for chunk in guard.guard_stream(mock_generator()):
                    yield chunk

            return StreamingResponse(
                guarded_mock_stream(),
                media_type="text/event-stream",
                headers={
                    "X-Aegis-Verdict-Id": verdict_input.verdict_id,
                    "X-Aegis-Routed-Provider": routed_provider,
                },
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

            if verdict_output.decision == DecisionEnum.DENY:
                record_proxy_request(translator.protocol_name, "denied")
                denied_payload = translator.build_policy_denied_response(verdict_output, "output")
                return Response(
                    status_code=403,
                    media_type="application/json",
                    content=json.dumps(denied_payload),
                    headers={"X-Aegis-Verdict-Id": verdict_output.verdict_id},
                )

            vault = get_pii_vault()
            rehydrated_content = await vault.rehydrate(
                x_aegis_tenant_id, x_aegis_session_id or "global", assistant_content
            )

            mock_resp = translator.build_mock_completion(
                model=model,
                content=rehydrated_content,
                usage={"prompt_tokens": 15, "completion_tokens": 12, "total_tokens": 27},
            )
            actual_prompt, actual_comp, actual_tokens = translator.extract_usage_tokens(mock_resp)

            if actual_tokens > 0 and x_aegis_session_id:
                try:
                    await get_budget_manager().reconcile_tokens(
                        x_aegis_tenant_id,
                        "session",
                        x_aegis_session_id,
                        actual_tokens - eval_req_input.action.estimated_tokens,
                    )
                except Exception:
                    pass

            record_proxy_request(translator.protocol_name, "success")
            return Response(
                content=json.dumps(mock_resp),
                status_code=200,
                media_type="application/json",
                headers={
                    "X-Aegis-Verdict-Id": verdict_output.verdict_id,
                    "X-Aegis-Risk-Score": str(verdict_output.risk_score),
                    "X-Aegis-Latency-Ms": str(verdict_output.latency_ms),
                    "X-Aegis-Routed-Provider": routed_provider,
                    "X-Aegis-Reconciled-Tokens": str(actual_tokens),
                },
            )

    # Real upstream forwarding with failover
    candidate_urls: list[str] = []
    if is_sovereign:
        candidate_urls = [f"{settings.LLM_JUDGE_BASE_URL.rstrip('/')}/chat/completions"]
    elif x_aegis_upstream_url:
        candidate_urls = [u.strip() for u in x_aegis_upstream_url.split(",") if u.strip()]
    else:
        candidate_urls = [f"{settings.LLM_JUDGE_BASE_URL.rstrip('/')}/chat/completions"]

    forward_headers = {"Content-Type": "application/json"}
    if authorization:
        forward_headers["Authorization"] = authorization

    client = httpx.AsyncClient(timeout=60.0)
    try:
        if stream:
            if translator.protocol_name == "openai" and "stream_options" not in body:
                body["stream_options"] = {"include_usage": True}

            upstream_resp = None
            last_err = None
            for target_url in candidate_urls:
                try:
                    req_stream = client.build_request("POST", target_url, json=body, headers=forward_headers)
                    resp_cand = await client.send(req_stream, stream=True)
                    if resp_cand.status_code in (429, 500, 502, 503, 504) and len(candidate_urls) > 1:
                        await resp_cand.aclose()
                        continue
                    upstream_resp = resp_cand
                    break
                except (httpx.RequestError, httpx.TimeoutException) as err:
                    last_err = err
                    continue

            if upstream_resp is None:
                await client.aclose()
                raise last_err or httpx.ConnectError("All upstream streaming providers failed")

            if upstream_resp.status_code != 200:
                content = await upstream_resp.aread()
                await client.aclose()
                return Response(content=content, status_code=upstream_resp.status_code, media_type="application/json")

            guard = SSEStreamGuard(
                tenant_id=x_aegis_tenant_id,
                session_id=x_aegis_session_id or "global",
                rehydrate_pii=True,
                estimated_prompt_tokens=eval_req_input.action.estimated_tokens,
                actor_id=x_aegis_actor_id,
                actor_role=x_aegis_actor_role,
                model=model,
                policy_pack_id=x_aegis_policy_pack,
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
                headers={
                    "X-Aegis-Verdict-Id": verdict_input.verdict_id,
                    "X-Aegis-Routed-Provider": routed_provider,
                },
            )
        else:
            resp = None
            last_err = None
            for target_url in candidate_urls:
                try:
                    resp = await client.post(target_url, json=body, headers=forward_headers)
                    if resp.status_code in (429, 500, 502, 503, 504) and len(candidate_urls) > 1:
                        continue
                    break
                except (httpx.RequestError, httpx.TimeoutException) as err:
                    last_err = err
                    continue

            await client.aclose()
            if resp is None:
                raise last_err or httpx.ConnectError("All upstream providers failed")

            if resp.status_code != 200:
                return Response(content=resp.content, status_code=resp.status_code, media_type="application/json")

            resp_json = resp.json()
            assistant_content = translator.extract_output_text(resp_json)

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
                denied_payload = translator.build_policy_denied_response(verdict_output, "output")
                return Response(
                    status_code=403,
                    media_type="application/json",
                    content=json.dumps(denied_payload),
                    headers={"X-Aegis-Verdict-Id": verdict_output.verdict_id},
                )

            vault = get_pii_vault()
            rehydrated_content = await vault.rehydrate(
                x_aegis_tenant_id, x_aegis_session_id or "global", assistant_content
            )
            if rehydrated_content != assistant_content:
                resp_json = translator.apply_rehydrated_output(resp_json, rehydrated_content)

            _, _, actual_tokens = translator.extract_usage_tokens(resp_json)
            if actual_tokens > 0 and x_aegis_session_id:
                try:
                    await get_budget_manager().reconcile_tokens(
                        x_aegis_tenant_id,
                        "session",
                        x_aegis_session_id,
                        actual_tokens - eval_req_input.action.estimated_tokens,
                    )
                except Exception:
                    pass

            return Response(
                content=json.dumps(resp_json),
                status_code=200,
                media_type="application/json",
                headers={
                    "X-Aegis-Verdict-Id": verdict_output.verdict_id,
                    "X-Aegis-Risk-Score": str(verdict_output.risk_score),
                    "X-Aegis-Latency-Ms": str(verdict_output.latency_ms),
                    "X-Aegis-Routed-Provider": routed_provider,
                    "X-Aegis-Reconciled-Tokens": str(actual_tokens),
                },
            )
    except httpx.RequestError as exc:
        await client.aclose()
        logger.warning("Upstream LLM unreachable, returning local mock response", error=str(exc))
        mock_resp = translator.build_mock_completion(
            model=model,
            content="AegisGate Governed Response: Fallback mock completion.",
            usage={"prompt_tokens": 15, "completion_tokens": 12, "total_tokens": 27},
        )
        return Response(
            content=json.dumps(mock_resp),
            status_code=200,
            media_type="application/json",
            headers={"X-Aegis-Verdict-Id": verdict_input.verdict_id},
        )

