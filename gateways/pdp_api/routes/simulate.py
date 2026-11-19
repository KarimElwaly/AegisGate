
from fastapi import APIRouter, HTTPException, Query

from core.simulator.replay import (
    ReplayDiffReport,
    ReplaySimulationRequest,
    get_replay_simulator,
)
from core.simulator.shadow import ShadowDeltaItem, get_shadow_delta_manager

router = APIRouter(prefix="/v1/simulate", tags=["Policy Simulation & Shadow Mode"])


@router.get("/shadow-deltas", response_model=list[ShadowDeltaItem])
async def list_shadow_deltas(
    tenant_id: str = Query(default="default", description="Tenant ID"),
    limit: int = Query(default=50, ge=1, le=500),
) -> list[ShadowDeltaItem]:
    """Retrieves live shadow deltas where active_decision != shadow_decision."""
    mgr = get_shadow_delta_manager()
    return await mgr.list_deltas(tenant_id=tenant_id, limit=limit)


@router.post("/replay", response_model=ReplayDiffReport)
async def replay_simulation(
    request: ReplaySimulationRequest,
) -> ReplayDiffReport:
    """
    Replays historical recorded audit logs against a candidate policy pack (YAML or ID)
    and returns a diff report of would-be-blocked, would-be-allowed, and concordance rate.
    """
    simulator = get_replay_simulator()
    try:
        report = await simulator.run_replay(request=request)
        return report
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Simulation replay error: {exc!s}")

