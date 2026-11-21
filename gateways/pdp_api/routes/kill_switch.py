from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from core.auth.dependencies import AuthenticatedActor, get_pdp_actor
from core.governance.kill_switch import KillSwitchService, get_kill_switch_service

router = APIRouter(prefix="/v1/kill-switch", tags=["Emergency Kill Switch"])


class KillSwitchActivateRequest(BaseModel):
    scope: str  # "global" | "tenant" | "workspace" | "agent" | "tool"
    target: str = ""
    tenant_id: str = "default"
    reason: str = "Emergency kill switch engaged by operator"
    ttl_seconds: int | None = None


class KillSwitchDeactivateRequest(BaseModel):
    scope: str
    target: str = ""
    tenant_id: str = "default"


@router.post("", response_model=dict[str, Any])
async def activate_kill_switch(
    payload: KillSwitchActivateRequest,
    service: KillSwitchService = Depends(get_kill_switch_service),
    actor: AuthenticatedActor = Depends(get_pdp_actor),
) -> dict[str, Any]:
    """Instantly activate an emergency circuit breaker kill switch."""
    if payload.scope == "global" and actor.role != "SuperAdmin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only SuperAdmin can engage global kill switch",
        )
    if actor.role != "SuperAdmin" and payload.tenant_id != actor.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cross-tenant kill switch manipulation forbidden",
        )
    if actor.role != "SuperAdmin":
        payload.tenant_id = actor.tenant_id

    key = await service.set_kill_switch(
        scope=payload.scope,
        target=payload.target,
        reason=payload.reason,
        tenant_id=payload.tenant_id,
        ttl_seconds=payload.ttl_seconds,
    )
    return {"status": "activated", "key": key, "scope": payload.scope, "target": payload.target}


@router.delete("", response_model=dict[str, Any])
async def deactivate_kill_switch(
    payload: KillSwitchDeactivateRequest,
    service: KillSwitchService = Depends(get_kill_switch_service),
    actor: AuthenticatedActor = Depends(get_pdp_actor),
) -> dict[str, Any]:
    """Deactivate an emergency kill switch."""
    if payload.scope == "global" and actor.role != "SuperAdmin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only SuperAdmin can disengage global kill switch",
        )
    if actor.role != "SuperAdmin" and payload.tenant_id != actor.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cross-tenant kill switch manipulation forbidden",
        )
    if actor.role != "SuperAdmin":
        payload.tenant_id = actor.tenant_id

    await service.remove_kill_switch(
        scope=payload.scope,
        target=payload.target,
        tenant_id=payload.tenant_id,
    )
    return {"status": "deactivated", "scope": payload.scope, "target": payload.target}


@router.get("", response_model=list[dict[str, Any]])
async def list_kill_switches(
    service: KillSwitchService = Depends(get_kill_switch_service),
    actor: AuthenticatedActor = Depends(get_pdp_actor),
) -> list[dict[str, Any]]:
    """List all currently active emergency kill switches."""
    all_switches = await service.list_active_kill_switches()
    if actor.role == "SuperAdmin":
        return all_switches
    return [
        s for s in all_switches
        if s.get("scope") == "global" or s.get("tenant_id") == actor.tenant_id
    ]
