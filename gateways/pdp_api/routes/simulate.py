from fastapi import APIRouter, Depends, HTTPException, Query

from core.auth.dependencies import AuthenticatedActor, get_pdp_actor
from core.simulator.replay import (
    ReplayDiffReport,
    ReplaySimulationRequest,
    get_replay_simulator,
)
from core.simulator.shadow import ShadowDeltaItem, get_shadow_delta_manager

router = APIRouter(prefix="/v1/simulate", tags=["Policy Simulation & Shadow Mode"])


@router.get("/shadow-deltas", response_model=list[ShadowDeltaItem])
async def list_shadow_deltas(
    tenant_id: str | None = Query(default=None, description="Tenant ID"),
    limit: int = Query(default=50, ge=1, le=500),
    actor: AuthenticatedActor = Depends(get_pdp_actor),
) -> list[ShadowDeltaItem]:
    """Retrieves live shadow deltas where active_decision != shadow_decision."""
    effective_tenant = actor.tenant_id
    if actor.role == "SuperAdmin" and tenant_id:
        effective_tenant = tenant_id
    elif tenant_id and tenant_id != actor.tenant_id and actor.role != "SuperAdmin":
        raise HTTPException(status_code=403, detail="Cross-tenant access forbidden")

    mgr = get_shadow_delta_manager()
    return await mgr.list_deltas(tenant_id=effective_tenant, limit=limit)


@router.post("/replay", response_model=ReplayDiffReport)
async def replay_simulation(
    request: ReplaySimulationRequest,
    actor: AuthenticatedActor = Depends(get_pdp_actor),
) -> ReplayDiffReport:
    """
    Replays historical recorded audit logs against a candidate policy pack (YAML or ID)
    and returns a diff report of would-be-blocked, would-be-allowed, and concordance rate.
    """
    effective_tenant = actor.tenant_id
    if actor.role == "SuperAdmin" and request.tenant_id:
        effective_tenant = request.tenant_id
    elif request.tenant_id and request.tenant_id != actor.tenant_id and actor.role != "SuperAdmin":
        raise HTTPException(status_code=403, detail="Cross-tenant access forbidden")
    request.tenant_id = effective_tenant

    simulator = get_replay_simulator()
    try:
        report = await simulator.run_replay(request=request)
        return report
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Simulation replay error: {exc!s}")
