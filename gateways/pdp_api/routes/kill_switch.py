from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from core.governance.kill_switch import KillSwitchService, get_kill_switch_service

router = APIRouter(prefix="/v1/kill-switch", tags=["Emergency Kill Switch"])


class KillSwitchActivateRequest(BaseModel):
    scope: str  # "global" | "tenant" | "workspace" | "agent" | "tool"
    target: str = ""
    tenant_id: str = "default"
    reason: str = "Emergency kill switch engaged by operator"
    ttl_seconds: Optional[int] = None


class KillSwitchDeactivateRequest(BaseModel):
    scope: str
    target: str = ""
    tenant_id: str = "default"


@router.post("", response_model=Dict[str, Any])
async def activate_kill_switch(
    payload: KillSwitchActivateRequest,
    service: KillSwitchService = Depends(get_kill_switch_service),
) -> Dict[str, Any]:
    """Instantly activate an emergency circuit breaker kill switch."""
    key = await service.set_kill_switch(
        scope=payload.scope,
        target=payload.target,
        reason=payload.reason,
        tenant_id=payload.tenant_id,
        ttl_seconds=payload.ttl_seconds,
    )
    return {"status": "activated", "key": key, "scope": payload.scope, "target": payload.target}


@router.delete("", response_model=Dict[str, Any])
async def deactivate_kill_switch(
    payload: KillSwitchDeactivateRequest,
    service: KillSwitchService = Depends(get_kill_switch_service),
) -> Dict[str, Any]:
    """Deactivate an emergency kill switch."""
    await service.remove_kill_switch(
        scope=payload.scope,
        target=payload.target,
        tenant_id=payload.tenant_id,
    )
    return {"status": "deactivated", "scope": payload.scope, "target": payload.target}


@router.get("", response_model=List[Dict[str, Any]])
async def list_kill_switches(
    service: KillSwitchService = Depends(get_kill_switch_service),
) -> List[Dict[str, Any]]:
    """List all currently active emergency kill switches."""
    return await service.list_active_kill_switches()
