from fastapi import APIRouter, Depends, HTTPException, status

from core.auth.dependencies import AuthenticatedActor, get_pdp_actor
from core.pipeline.orchestrator import PipelineOrchestrator, get_pipeline_orchestrator
from core.schemas.events import EvaluationRequest
from core.schemas.verdicts import EvaluationVerdict

router = APIRouter(prefix="/v1", tags=["Policy Decision Point"])


@router.post("/evaluate", response_model=EvaluationVerdict)
async def evaluate(
    request: EvaluationRequest,
    actor: AuthenticatedActor = Depends(get_pdp_actor),
    orchestrator: PipelineOrchestrator = Depends(get_pipeline_orchestrator),
) -> EvaluationVerdict:
    """Sub-15ms Policy Decision Point evaluation endpoint."""
    # Enforce cross-tenant isolation: Virtual Key bound to tenant A cannot evaluate for tenant B
    if actor.auth_type == "virtual_key" and actor.tenant_id != request.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Virtual API Key for tenant '{actor.tenant_id}' cannot evaluate request for tenant '{request.tenant_id}'",
        )

    try:
        verdict = await orchestrator.evaluate(request)
        return verdict
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Pipeline evaluation error: {exc!s}")
