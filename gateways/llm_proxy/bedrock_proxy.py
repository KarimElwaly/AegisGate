from fastapi import APIRouter, Depends, Header, Request, Response

from core.auth.dependencies import AuthenticatedActor, get_pdp_actor
from core.pipeline.orchestrator import PipelineOrchestrator, get_pipeline_orchestrator
from gateways.llm_proxy.core_handler import execute_proxy_request
from gateways.llm_proxy.translators.bedrock_translator import BedrockProtocolTranslator

router = APIRouter(prefix="/proxy/bedrock", tags=["AWS Bedrock Converse API Reverse Proxy"])
_translator = BedrockProtocolTranslator()


@router.post("/model/{model_id:path}/converse")
async def bedrock_converse(
    model_id: str,
    request: Request,
    orchestrator: PipelineOrchestrator = Depends(get_pipeline_orchestrator),
    authorization: str | None = Header(default=None),
    x_aegis_tenant_id: str = Header(default="default"),
    x_aegis_workspace_id: str = Header(default="default"),
    x_aegis_policy_pack: str = Header(default="base-enterprise"),
    x_aegis_session_id: str | None = Header(default=None),
    x_aegis_actor_id: str = Header(default="bedrock_client"),
    x_aegis_actor_role: str = Header(default="user"),
    x_aegis_upstream_url: str | None = Header(default=None),
    actor: AuthenticatedActor = Depends(get_pdp_actor),
) -> Response:
    """AWS Bedrock Converse API Reverse Proxy (/proxy/bedrock/model/{modelId}/converse)."""
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
        path_params={"model_id": model_id, "stream": "false"},
        force_stream=False,
        actor=actor,
    )


@router.post("/model/{model_id:path}/converse-stream")
async def bedrock_converse_stream(
    model_id: str,
    request: Request,
    orchestrator: PipelineOrchestrator = Depends(get_pipeline_orchestrator),
    authorization: str | None = Header(default=None),
    x_aegis_tenant_id: str = Header(default="default"),
    x_aegis_workspace_id: str = Header(default="default"),
    x_aegis_policy_pack: str = Header(default="base-enterprise"),
    x_aegis_session_id: str | None = Header(default=None),
    x_aegis_actor_id: str = Header(default="bedrock_client"),
    x_aegis_actor_role: str = Header(default="user"),
    x_aegis_upstream_url: str | None = Header(default=None),
    actor: AuthenticatedActor = Depends(get_pdp_actor),
) -> Response:
    """AWS Bedrock Converse Stream Reverse Proxy (/proxy/bedrock/model/{modelId}/converse-stream)."""
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
        path_params={"model_id": model_id, "stream": "true"},
        force_stream=True,
        actor=actor,
    )

