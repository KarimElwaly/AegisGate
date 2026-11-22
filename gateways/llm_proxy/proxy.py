from typing import Any

from fastapi import APIRouter, Depends, Header, Request, Response

from core.auth.dependencies import AuthenticatedActor, get_pdp_actor
from core.pipeline.orchestrator import PipelineOrchestrator, get_pipeline_orchestrator
from gateways.llm_proxy.core_handler import execute_proxy_request
from gateways.llm_proxy.translators.openai_translator import OpenAIProtocolTranslator

router = APIRouter(prefix="/proxy/llm/v1", tags=["OpenAI LLM Reverse Proxy"])
_translator = OpenAIProtocolTranslator()


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
    actor: AuthenticatedActor = Depends(get_pdp_actor),
) -> Response:
    """OpenAI-compatible Chat Completions Reverse Proxy.
    Enforces llm_input guardrails before forwarding, and llm_output guardrails
    (including SSE streaming buffer scanning) on returned completions.
    """
    body = await request.json()
    return await execute_proxy_request(
        request=request,
        body=body,
        translator=_translator,
        orchestrator=orchestrator,
        authorization=authorization,
        x_aegis_tenant_id=x_aegis_tenant_id,
        x_aegis_workspace_id=x_aegis_workspace_id,
        x_aegis_policy_pack=x_aegis_policy_pack,
        x_aegis_session_id=x_aegis_session_id,
        x_aegis_actor_id=x_aegis_actor_id,
        x_aegis_actor_role=x_aegis_actor_role,
        x_aegis_upstream_url=x_aegis_upstream_url,
        actor=actor,
    )
