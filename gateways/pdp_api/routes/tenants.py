from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from core.auth.dependencies import AuthenticatedActor, require_role
from core.database import get_db_session
from core.tenancy.service import TenancyService, get_tenancy_service

router = APIRouter(prefix="/v1/tenants", tags=["Multi-Tenancy & Workspaces"])


class TenantCreateRequest(BaseModel):
    id: str = Field(..., min_length=2, max_length=64)
    name: str = Field(..., min_length=2, max_length=128)


class WorkspaceCreateRequest(BaseModel):
    id: str = Field(..., min_length=2, max_length=64)
    name: str = Field(..., min_length=2, max_length=128)
    environment: str = Field(default="dev", pattern="^(dev|staging|prod)$")


@router.post("", response_model=dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_tenant(
    payload: TenantCreateRequest,
    session: AsyncSession = Depends(get_db_session),
    tenancy_svc: TenancyService = Depends(get_tenancy_service),
    actor: AuthenticatedActor = Depends(require_role("SuperAdmin")),
) -> dict[str, Any]:
    """Create a new isolated tenant boundary with a default workspace."""
    existing = await tenancy_svc.get_tenant(session, payload.id)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Tenant '{payload.id}' already exists",
        )
    tenant = await tenancy_svc.create_tenant(session, payload.id, payload.name)
    return {
        "status": "created",
        "tenant_id": tenant.id,
        "name": tenant.name,
        "is_active": tenant.is_active,
        "created_at": tenant.created_at.isoformat() if tenant.created_at else None,
    }


@router.get("", response_model=list[dict[str, Any]])
async def list_tenants(
    session: AsyncSession = Depends(get_db_session),
    tenancy_svc: TenancyService = Depends(get_tenancy_service),
    actor: AuthenticatedActor = Depends(require_role("SuperAdmin", "TenantAdmin")),
) -> list[dict[str, Any]]:
    """List tenants."""
    tenants = await tenancy_svc.list_tenants(session)
    if actor.role != "SuperAdmin":
        tenants = [t for t in tenants if t.id == actor.tenant_id]
    return [
        {
            "id": t.id,
            "name": t.name,
            "is_active": t.is_active,
            "created_at": t.created_at.isoformat() if t.created_at else None,
        }
        for t in tenants
    ]


@router.get("/{tenant_id}", response_model=dict[str, Any])
async def get_tenant(
    tenant_id: str,
    session: AsyncSession = Depends(get_db_session),
    tenancy_svc: TenancyService = Depends(get_tenancy_service),
    actor: AuthenticatedActor = Depends(require_role("SuperAdmin", "TenantAdmin")),
) -> dict[str, Any]:
    """Get single tenant details."""
    if actor.role != "SuperAdmin" and actor.tenant_id != tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access forbidden")
    tenant = await tenancy_svc.get_tenant(session, tenant_id)
    if not tenant:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Tenant '{tenant_id}' not found")
    return {
        "id": tenant.id,
        "name": tenant.name,
        "is_active": tenant.is_active,
        "created_at": tenant.created_at.isoformat() if tenant.created_at else None,
    }


@router.post("/{tenant_id}/workspaces", response_model=dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_workspace(
    tenant_id: str,
    payload: WorkspaceCreateRequest,
    session: AsyncSession = Depends(get_db_session),
    tenancy_svc: TenancyService = Depends(get_tenancy_service),
    actor: AuthenticatedActor = Depends(require_role("SuperAdmin", "TenantAdmin")),
) -> dict[str, Any]:
    """Create a workspace under a tenant."""
    if actor.role != "SuperAdmin" and actor.tenant_id != tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access forbidden")
    ws = await tenancy_svc.create_workspace(
        session,
        workspace_id=payload.id,
        tenant_id=tenant_id,
        name=payload.name,
        environment=payload.environment,
    )
    return {
        "status": "created",
        "id": ws.id,
        "tenant_id": ws.tenant_id,
        "name": ws.name,
        "environment": ws.environment,
        "created_at": ws.created_at.isoformat() if ws.created_at else None,
    }


@router.get("/{tenant_id}/workspaces", response_model=list[dict[str, Any]])
async def list_workspaces(
    tenant_id: str,
    session: AsyncSession = Depends(get_db_session),
    tenancy_svc: TenancyService = Depends(get_tenancy_service),
    actor: AuthenticatedActor = Depends(require_role("SuperAdmin", "TenantAdmin")),
) -> list[dict[str, Any]]:
    """List workspaces for a tenant."""
    if actor.role != "SuperAdmin" and actor.tenant_id != tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access forbidden")
    workspaces = await tenancy_svc.list_workspaces(session, tenant_id)
    return [
        {
            "id": ws.id,
            "tenant_id": ws.tenant_id,
            "name": ws.name,
            "environment": ws.environment,
            "is_active": ws.is_active,
            "created_at": ws.created_at.isoformat() if ws.created_at else None,
        }
        for ws in workspaces
    ]
