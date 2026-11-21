from typing import Any

from fastapi import APIRouter, Depends, Header, Request, Response

from core.pipeline.orchestrator import PipelineOrchestrator, get_pipeline_orchestrator
from gateways.llm_proxy.core_handler import execute_proxy_request
from gateways.llm_proxy.translators.gemini_translator import GeminiProtocolTranslator

router = APIRouter(prefix="/proxy/gemini/v1beta", tags=["Google Gemini API Reverse Proxy"])
_translator = GeminiProtocolTranslator()


@router.post("/models/{model}:generateContent")
async def gemini_generate_content(
    model: str,
    request: Request,
    orchestrator: PipelineOrchestrator = Depends(get_pipeline_orchestrator),
    x_goog_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
    x_aegis_tenant_id: str = Header(default="default"),
    x_aegis_workspace_id: str = Header(default="default"),
    x_aegis_policy_pack: str = Header(default="base-enterprise"),
    x_aegis_session_id: str | None = Header(default=None),
    x_aegis_actor_id: str = Header(default="gemini_client"),
    x_aegis_actor_role: str = Header(default="user"),
    x_aegis_upstream_url: str | None = Header(default=None),
) -> Response:
    """Google Gemini generateContent Reverse Proxy.
    Enforces llm_input guardrails, sovereignty routing, token budgets, and output scanning.
    """
    body = await request.json()
    auth_header = authorization or (f"Bearer {x_goog_api_key}" if x_goog_api_key else None)
    return await execute_proxy_request(
        request=request,
        body=body,
        translator=_translator,
        orchestrator=orchestrator,
        authorization=auth_header,
        x_aegis_tenant_id=x_aegis_tenant_id,
        x_aegis_workspace_id=x_aegis_workspace_id,
        x_aegis_policy_pack=x_aegis_policy_pack,
        x_aegis_session_id=x_aegis_session_id,
        x_aegis_actor_id=x_aegis_actor_id,
        x_aegis_actor_role=x_aegis_actor_role,
        x_aegis_upstream_url=x_aegis_upstream_url,
        path_params={"model": model},
        force_stream=False,
    )


@router.post("/models/{model}:streamGenerateContent")
async def gemini_stream_generate_content(
    model: str,
    request: Request,
    orchestrator: PipelineOrchestrator = Depends(get_pipeline_orchestrator),
    x_goog_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
    x_aegis_tenant_id: str = Header(default="default"),
    x_aegis_workspace_id: str = Header(default="default"),
    x_aegis_policy_pack: str = Header(default="base-enterprise"),
    x_aegis_session_id: str | None = Header(default=None),
    x_aegis_actor_id: str = Header(default="gemini_client"),
    x_aegis_actor_role: str = Header(default="user"),
    x_aegis_upstream_url: str | None = Header(default=None),
) -> Response:
    """Google Gemini streamGenerateContent Reverse Proxy with SSE streaming guard."""
    body = await request.json()
    auth_header = authorization or (f"Bearer {x_goog_api_key}" if x_goog_api_key else None)
    return await execute_proxy_request(
        request=request,
        body=body,
        translator=_translator,
        orchestrator=orchestrator,
        authorization=auth_header,
        x_aegis_tenant_id=x_aegis_tenant_id,
        x_aegis_workspace_id=x_aegis_workspace_id,
        x_aegis_policy_pack=x_aegis_policy_pack,
        x_aegis_session_id=x_aegis_session_id,
        x_aegis_actor_id=x_aegis_actor_id,
        x_aegis_actor_role=x_aegis_actor_role,
        x_aegis_upstream_url=x_aegis_upstream_url,
        path_params={"model": model},
        force_stream=True,
    )

