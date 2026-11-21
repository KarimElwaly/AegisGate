from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from core.auth.dependencies import AuthenticatedActor, require_role
from core.redis_client import get_redis_client

router = APIRouter(prefix="/v1/budgets", tags=["Budgets & Quotas"])


class QuotaUpdateRequest(BaseModel):
    tenant_id: str
    workspace_id: str = "default"
    max_tokens: int = Field(default=100000)
    max_cost_usd: float = Field(default=10.0)
    max_tool_calls: int = Field(default=50)


class ResetLoopRequest(BaseModel):
    tenant_id: str
    session_id: str = "global"
    actor_id: str


@router.get("/usage", response_model=dict[str, Any])
async def get_budget_usage(
    tenant_id: str = Query(..., description="Tenant ID"),
    scope_type: str = Query("tenant", description="tenant | session | workspace"),
    scope_id: str | None = Query(None, description="Scope identifier"),
    actor: AuthenticatedActor = Depends(require_role("SuperAdmin", "TenantAdmin", "Auditor")),
) -> dict[str, Any]:
    """Inspect live Redis usage (tokens, cost, tool calls) for tenant/session/workspace."""
    if actor.role != "SuperAdmin" and actor.tenant_id != tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access forbidden")

    target_id = scope_id or tenant_id
    redis_key = f"aegis:budget:{tenant_id}:{scope_type}:{target_id}"

    redis = await get_redis_client()
    raw = await redis.hgetall(redis_key)
    tokens_used = int(raw.get("tokens_used", 0))
    cost_used = float(raw.get("cost_used_usd", 0.0))
    calls_used = int(raw.get("tool_calls_used", 0))
    failures = int(raw.get("consecutive_failures", 0))

    return {
        "tenant_id": tenant_id,
        "scope_type": scope_type,
        "scope_id": target_id,
        "tokens_used": tokens_used,
        "cost_used_usd": cost_used,
        "tool_calls_used": calls_used,
        "consecutive_failures": failures,
    }


@router.post("/quotas", response_model=dict[str, Any])
async def update_quotas(
    payload: QuotaUpdateRequest,
    actor: AuthenticatedActor = Depends(require_role("SuperAdmin", "TenantAdmin")),
) -> dict[str, Any]:
    """Update quota thresholds stored in Redis for a workspace/tenant."""
    if actor.role != "SuperAdmin" and actor.tenant_id != payload.tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access forbidden")

    redis = await get_redis_client()
    quota_key = f"aegis:quota:{payload.tenant_id}:{payload.workspace_id}"
    await redis.hset(
        quota_key,
        mapping={
            "max_tokens": str(payload.max_tokens),
            "max_cost_usd": str(payload.max_cost_usd),
            "max_tool_calls": str(payload.max_tool_calls),
        },
    )

    return {
        "status": "updated",
        "tenant_id": payload.tenant_id,
        "workspace_id": payload.workspace_id,
        "max_tokens": payload.max_tokens,
        "max_cost_usd": payload.max_cost_usd,
        "max_tool_calls": payload.max_tool_calls,
    }


@router.post("/reset-loop", response_model=dict[str, Any])
async def reset_loop_circuit(
    payload: ResetLoopRequest,
    actor: AuthenticatedActor = Depends(require_role("SuperAdmin", "TenantAdmin")),
) -> dict[str, Any]:
    """Manually reset a tripped runaway loop circuit breaker in Redis."""
    if actor.role != "SuperAdmin" and actor.tenant_id != payload.tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access forbidden")

    redis = await get_redis_client()
    loop_key = f"aegis:loop:{payload.tenant_id}:{payload.session_id}:{payload.actor_id}"
    deleted = await redis.delete(loop_key)

    return {
        "status": "reset",
        "tenant_id": payload.tenant_id,
        "session_id": payload.session_id,
        "actor_id": payload.actor_id,
        "key_cleared": bool(deleted),
    }

