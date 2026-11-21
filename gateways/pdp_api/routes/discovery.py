from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.auth.dependencies import AuthenticatedActor, get_pdp_actor
from core.database import get_db_session
from core.models.discovery import DiscoveredAssetRecord

router = APIRouter(prefix="/v1/discovery", tags=["Shadow AI & Asset Discovery"])


class UpdateAssetStatusRequest(BaseModel):
    governance_status: str | None = None  # governed | shadow_unapproved | blocked
    risk_level: str | None = None  # low | medium | high | critical


@router.get("/assets")
async def list_discovered_assets(
    workspace_id: str = Query(default="default"),
    asset_type: str | None = Query(default=None),
    governance_status: str | None = Query(default=None),
    actor: AuthenticatedActor = Depends(get_pdp_actor),
    db: AsyncSession = Depends(get_db_session),
):
    """List auto-discovered Shadow AI assets (models, tools, agents)."""
    tenant_id = actor.tenant_id
    query = select(DiscoveredAssetRecord).where(
        DiscoveredAssetRecord.tenant_id == tenant_id,
        DiscoveredAssetRecord.workspace_id == workspace_id,
    )
    if asset_type:
        query = query.where(DiscoveredAssetRecord.asset_type == asset_type)
    if governance_status:
        query = query.where(DiscoveredAssetRecord.governance_status == governance_status)

    query = query.order_by(DiscoveredAssetRecord.last_seen_at.desc())
    res = await db.execute(query)
    assets = res.scalars().all()

    return [
        {
            "id": a.id,
            "tenant_id": a.tenant_id,
            "workspace_id": a.workspace_id,
            "asset_type": a.asset_type,
            "name": a.name,
            "request_count": a.request_count,
            "risk_level": a.risk_level,
            "governance_status": a.governance_status,
            "first_seen_at": a.first_seen_at.isoformat() if a.first_seen_at else None,
            "last_seen_at": a.last_seen_at.isoformat() if a.last_seen_at else None,
        }
        for a in assets
    ]


@router.patch("/assets/{asset_id}")
async def update_asset_status(
    asset_id: str,
    payload: UpdateAssetStatusRequest,
    actor: AuthenticatedActor = Depends(get_pdp_actor),
    db: AsyncSession = Depends(get_db_session),
):
    """Update asset governance status (approve or block) or risk level."""
    tenant_id = actor.tenant_id
    stmt = select(DiscoveredAssetRecord).where(
        DiscoveredAssetRecord.id == asset_id,
        DiscoveredAssetRecord.tenant_id == tenant_id,
    )
    res = await db.execute(stmt)
    asset = res.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Discovered asset not found")

    if payload.governance_status:
        asset.governance_status = payload.governance_status
    if payload.risk_level:
        asset.risk_level = payload.risk_level

    await db.commit()
    return {
        "id": asset.id,
        "name": asset.name,
        "governance_status": asset.governance_status,
        "risk_level": asset.risk_level,
    }

