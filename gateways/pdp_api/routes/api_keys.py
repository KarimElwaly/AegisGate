import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from core.auth.dependencies import AuthenticatedActor, require_role
from core.database import get_db_session
from core.tenancy.service import TenancyService, get_tenancy_service

router = APIRouter(prefix="/v1/api-keys/virtual", tags=["Virtual API Keys"])


class VirtualKeyIssueRequest(BaseModel):
    tenant_id: str
    workspace_id: str = "default"
    name: str = Field(..., min_length=2, max_length=128)
    role: str = Field(default="Auditor")
    environment: str = Field(default="dev", pattern="^(dev|staging|prod)$")
    default_policy_pack_id: str = "base-enterprise"
    allowed_models: list[str] = Field(default_factory=list)
    budget_cap_usd: float = 100.0
    rate_limit_rpm: int = 600
    expires_in_days: int | None = None


@router.post("", response_model=dict[str, Any], status_code=status.HTTP_201_CREATED)
async def issue_virtual_key(
    payload: VirtualKeyIssueRequest,
    session: AsyncSession = Depends(get_db_session),
    tenancy_svc: TenancyService = Depends(get_tenancy_service),
    actor: AuthenticatedActor = Depends(require_role("SuperAdmin", "TenantAdmin")),
) -> dict[str, Any]:
    """Issue a new Virtual API Key. The plaintext key is returned ONCE upon creation."""
    if actor.role != "SuperAdmin" and actor.tenant_id != payload.tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant key issuance forbidden")

    rec, plaintext = await tenancy_svc.issue_virtual_key(
        session=session,
        tenant_id=payload.tenant_id,
        workspace_id=payload.workspace_id,
        name=payload.name,
        role=payload.role,
        environment=payload.environment,
        default_policy_pack_id=payload.default_policy_pack_id,
        allowed_models=payload.allowed_models,
        budget_cap_usd=payload.budget_cap_usd,
        rate_limit_rpm=payload.rate_limit_rpm,
        expires_in_days=payload.expires_in_days,
    )
    return {
        "status": "created",
        "id": rec.id,
        "name": rec.name,
        "tenant_id": rec.tenant_id,
        "workspace_id": rec.workspace_id,
        "key_prefix": rec.key_prefix,
        "role": rec.role,
        "environment": rec.environment,
        "api_key": plaintext,  # Returned only once
        "created_at": rec.created_at.isoformat() if rec.created_at else None,
        "expires_at": rec.expires_at.isoformat() if rec.expires_at else None,
    }


@router.get("", response_model=list[dict[str, Any]])
async def list_virtual_keys(
    tenant_id: str = Query(..., description="Tenant ID to filter"),
    workspace_id: str | None = Query(None, description="Optional Workspace ID"),
    session: AsyncSession = Depends(get_db_session),
    tenancy_svc: TenancyService = Depends(get_tenancy_service),
    actor: AuthenticatedActor = Depends(require_role("SuperAdmin", "TenantAdmin", "Auditor")),
) -> list[dict[str, Any]]:
    """List Virtual API Keys for a tenant/workspace."""
    if actor.role != "SuperAdmin" and actor.tenant_id != tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access forbidden")

    keys = await tenancy_svc.list_virtual_keys(session, tenant_id=tenant_id, workspace_id=workspace_id)
    return [
        {
            "id": k.id,
            "name": k.name,
            "tenant_id": k.tenant_id,
            "workspace_id": k.workspace_id,
            "key_prefix": k.key_prefix,
            "role": k.role,
            "environment": k.environment,
            "default_policy_pack_id": k.default_policy_pack_id,
            "budget_cap_usd": k.budget_cap_usd,
            "rate_limit_rpm": k.rate_limit_rpm,
            "is_revoked": k.revoked_at is not None,
            "revoked_at": k.revoked_at.isoformat() if k.revoked_at else None,
            "expires_at": k.expires_at.isoformat() if k.expires_at else None,
            "created_at": k.created_at.isoformat() if k.created_at else None,
        }
        for k in keys
    ]


@router.post("/{key_id}/revoke", response_model=dict[str, Any])
async def revoke_virtual_key(
    key_id: str,
    tenant_id: str = Query(..., description="Tenant ID"),
    session: AsyncSession = Depends(get_db_session),
    tenancy_svc: TenancyService = Depends(get_tenancy_service),
    actor: AuthenticatedActor = Depends(require_role("SuperAdmin", "TenantAdmin")),
) -> dict[str, Any]:
    """Immediately revoke a Virtual API Key."""
    if actor.role != "SuperAdmin" and actor.tenant_id != tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access forbidden")

    revoked = await tenancy_svc.revoke_virtual_key(session, key_id, tenant_id)
    if not revoked:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Key not found or already revoked")
    return {"status": "revoked", "id": key_id}


@router.post("/{key_id}/rotate", response_model=dict[str, Any])
async def rotate_virtual_key(
    key_id: str,
    tenant_id: str = Query(..., description="Tenant ID"),
    session: AsyncSession = Depends(get_db_session),
    tenancy_svc: TenancyService = Depends(get_tenancy_service),
    actor: AuthenticatedActor = Depends(require_role("SuperAdmin", "TenantAdmin")),
) -> dict[str, Any]:
    """Atomically revoke the old key and issue a new replacement."""
    if actor.role != "SuperAdmin" and actor.tenant_id != tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access forbidden")

    rotated = await tenancy_svc.rotate_virtual_key(session, key_id, tenant_id)
    if not rotated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Key not found")

    new_rec, plaintext = rotated
    return {
        "status": "rotated",
        "old_key_id": key_id,
        "new_key_id": new_rec.id,
        "new_key_prefix": new_rec.key_prefix,
        "api_key": plaintext,  # Returned only once
        "created_at": new_rec.created_at.isoformat() if new_rec.created_at else None,
    }
