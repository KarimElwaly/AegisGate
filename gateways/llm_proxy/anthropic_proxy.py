from typing import Any

from fastapi import APIRouter, Depends, Header, Request, Response

from core.auth.dependencies import AuthenticatedActor, get_pdp_actor
from core.pipeline.orchestrator import PipelineOrchestrator, get_pipeline_orchestrator
from gateways.llm_proxy.core_handler import execute_proxy_request
from gateways.llm_proxy.translators.anthropic_translator import AnthropicProtocolTranslator

router = APIRouter(prefix="/proxy/anthropic/v1", tags=["Anthropic Messages API Reverse Proxy"])
_translator = AnthropicProtocolTranslator()


@router.post("/messages")
async def anthropic_messages(
    request: Request,
    orchestrator: PipelineOrchestrator = Depends(get_pipeline_orchestrator),
    x_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
    x_aegis_tenant_id: str = Header(default="default"),
    x_aegis_workspace_id: str = Header(default="default"),
    x_aegis_policy_pack: str = Header(default="base-enterprise"),
    x_aegis_session_id: str | None = Header(default=None),
    x_aegis_actor_id: str = Header(default="anthropic_client"),
    x_aegis_actor_role: str = Header(default="user"),
    x_aegis_upstream_url: str | None = Header(default=None),
    actor: AuthenticatedActor = Depends(get_pdp_actor),
) -> Response:
    """Anthropic Messages API Reverse Proxy (/proxy/anthropic/v1/messages).
    Enforces llm_input guardrails, sovereignty routing, token budgets, and output scanning/SSE streaming.
    """
    body = await request.json()
    auth_header = authorization or (f"Bearer {x_api_key}" if x_api_key else None)
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
        actor=actor,
    )

