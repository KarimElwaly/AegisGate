from fastapi import APIRouter, Depends, Header, Query, Request, Response

from core.pipeline.orchestrator import PipelineOrchestrator, get_pipeline_orchestrator
from gateways.llm_proxy.core_handler import execute_proxy_request
from gateways.llm_proxy.translators.azure_openai_translator import AzureOpenAIProtocolTranslator

router = APIRouter(prefix="/proxy/azure/openai", tags=["Azure OpenAI Deployments API Reverse Proxy"])
_translator = AzureOpenAIProtocolTranslator()


@router.post("/deployments/{deployment:path}/chat/completions")
async def azure_openai_chat_completions(
    deployment: str,
    request: Request,
    api_version: str | None = Query(default=None, alias="api-version"),
    orchestrator: PipelineOrchestrator = Depends(get_pipeline_orchestrator),
    api_key: str | None = Header(default=None, alias="api-key"),
    authorization: str | None = Header(default=None),
    x_aegis_tenant_id: str = Header(default="default"),
    x_aegis_workspace_id: str = Header(default="default"),
    x_aegis_policy_pack: str = Header(default="base-enterprise"),
    x_aegis_session_id: str | None = Header(default=None),
    x_aegis_actor_id: str = Header(default="azure_client"),
    x_aegis_actor_role: str = Header(default="user"),
    x_aegis_upstream_url: str | None = Header(default=None),
) -> Response:
    """Azure OpenAI Chat Completions API Reverse Proxy (/proxy/azure/openai/deployments/{deployment}/chat/completions)."""
    body = await request.json()
    auth_header = authorization or (f"Bearer {api_key}" if api_key else None)
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
        path_params={"deployment": deployment, "api_version": api_version or ""},
    )

