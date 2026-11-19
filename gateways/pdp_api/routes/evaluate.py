from fastapi import APIRouter, Depends, HTTPException
from core.pipeline.orchestrator import PipelineOrchestrator, get_pipeline_orchestrator
from core.schemas.events import EvaluationRequest
from core.schemas.verdicts import EvaluationVerdict

router = APIRouter(prefix="/v1", tags=["Policy Decision Point"])


@router.post("/evaluate", response_model=EvaluationVerdict)
async def evaluate(
    request: EvaluationRequest,
    orchestrator: PipelineOrchestrator = Depends(get_pipeline_orchestrator),
) -> EvaluationVerdict:
    """Sub-15ms Policy Decision Point evaluation endpoint."""
    try:
        verdict = await orchestrator.evaluate(request)
        return verdict
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Pipeline evaluation error: {str(exc)}")
