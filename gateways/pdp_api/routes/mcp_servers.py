import datetime
import hashlib
import json
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.auth.dependencies import AuthenticatedActor, get_pdp_actor
from core.database import get_db_session
from core.models.mcp import McpToolPinRecord, UpstreamMcpServerRecord

router = APIRouter(prefix="/v1/mcp", tags=["MCP Server & Tool Governance"])


def compute_hashes(schema: dict[str, Any] | None, description: str | None) -> tuple[str, str]:
    canonical_schema = json.dumps(schema or {}, sort_keys=True, separators=(",", ":"))
    s_hash = hashlib.sha256(canonical_schema.encode("utf-8")).hexdigest()
    d_hash = hashlib.sha256((description or "").strip().encode("utf-8")).hexdigest()
    return s_hash, d_hash


class RegisterMcpServerRequest(BaseModel):
    name: str
    server_url: str
    auth_headers: dict[str, str] = Field(default_factory=dict)
    workspace_id: str = "default"


class PinMcpToolRequest(BaseModel):
    workspace_id: str = "default"
    server_id: str | None = None
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)


@router.post("/servers", status_code=201)
async def register_mcp_server(
    payload: RegisterMcpServerRequest,
    actor: AuthenticatedActor = Depends(get_pdp_actor),
    db: AsyncSession = Depends(get_db_session),
):
    """Register an upstream MCP server."""
    tenant_id = actor.tenant_id
    server_id = str(uuid.uuid4())
    server = UpstreamMcpServerRecord(
        id=server_id,
        tenant_id=tenant_id,
        workspace_id=payload.workspace_id,
        name=payload.name,
        server_url=payload.server_url,
        auth_headers_json=json.dumps(payload.auth_headers),
        is_active=True,
    )
    db.add(server)
    await db.commit()
    return {
        "id": server_id,
        "tenant_id": tenant_id,
        "workspace_id": payload.workspace_id,
        "name": payload.name,
        "server_url": payload.server_url,
        "status": "registered",
    }


@router.get("/servers")
async def list_mcp_servers(
    workspace_id: str = Query(default="default"),
    actor: AuthenticatedActor = Depends(get_pdp_actor),
    db: AsyncSession = Depends(get_db_session),
):
    """List registered upstream MCP servers."""
    tenant_id = actor.tenant_id
    stmt = select(UpstreamMcpServerRecord).where(
        UpstreamMcpServerRecord.tenant_id == tenant_id,
        UpstreamMcpServerRecord.workspace_id == workspace_id,
    )
    res = await db.execute(stmt)
    servers = res.scalars().all()
    return [
        {
            "id": s.id,
            "tenant_id": s.tenant_id,
            "workspace_id": s.workspace_id,
            "name": s.name,
            "server_url": s.server_url,
            "is_active": s.is_active,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        }
        for s in servers
    ]


@router.delete("/servers/{server_id}")
async def delete_mcp_server(
    server_id: str,
    actor: AuthenticatedActor = Depends(get_pdp_actor),
    db: AsyncSession = Depends(get_db_session),
):
    """Unregister an upstream MCP server."""
    tenant_id = actor.tenant_id
    stmt = select(UpstreamMcpServerRecord).where(
        UpstreamMcpServerRecord.id == server_id,
        UpstreamMcpServerRecord.tenant_id == tenant_id,
    )
    res = await db.execute(stmt)
    server = res.scalar_one_or_none()
    if not server:
        raise HTTPException(status_code=404, detail="Upstream MCP server not found")
    await db.delete(server)
    await db.commit()
    return {"status": "deleted", "server_id": server_id}


@router.post("/tools/{tool_name}/pin")
async def pin_mcp_tool(
    tool_name: str,
    payload: PinMcpToolRequest,
    actor: AuthenticatedActor = Depends(get_pdp_actor),
    db: AsyncSession = Depends(get_db_session),
):
    """Pin or re-pin an MCP tool schema, resetting any quarantine (Anti-Rug-Pull baseline)."""
    tenant_id = actor.tenant_id
    s_hash, d_hash = compute_hashes(payload.input_schema, payload.description)

    stmt = select(McpToolPinRecord).where(
        McpToolPinRecord.tenant_id == tenant_id,
        McpToolPinRecord.workspace_id == payload.workspace_id,
        McpToolPinRecord.tool_name == tool_name,
    )
    res = await db.execute(stmt)
    pin = res.scalar_one_or_none()

    if pin:
        pin.schema_hash = s_hash
        pin.description_hash = d_hash
        pin.description = payload.description
        pin.input_schema_json = json.dumps(payload.input_schema)
        pin.is_quarantined = False
        pin.quarantine_reason = None
        pin.server_id = payload.server_id
        pin.updated_at = datetime.datetime.utcnow()
    else:
        pin = McpToolPinRecord(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            workspace_id=payload.workspace_id,
            server_id=payload.server_id,
            tool_name=tool_name,
            schema_hash=s_hash,
            description_hash=d_hash,
            description=payload.description,
            input_schema_json=json.dumps(payload.input_schema),
            is_quarantined=False,
            quarantine_reason=None,
        )
        db.add(pin)

    await db.commit()
    return {
        "tool_name": tool_name,
        "schema_hash": s_hash,
        "description_hash": d_hash,
        "is_quarantined": False,
        "status": "pinned",
    }


@router.get("/tools/quarantine")
async def list_quarantined_tools(
    workspace_id: str = Query(default="default"),
    actor: AuthenticatedActor = Depends(get_pdp_actor),
    db: AsyncSession = Depends(get_db_session),
):
    """List all currently quarantined tools."""
    tenant_id = actor.tenant_id
    stmt = select(McpToolPinRecord).where(
        McpToolPinRecord.tenant_id == tenant_id,
        McpToolPinRecord.workspace_id == workspace_id,
        McpToolPinRecord.is_quarantined.is_(True),
    )
    res = await db.execute(stmt)
    quarantined = res.scalars().all()
    return [
        {
            "id": p.id,
            "tool_name": p.tool_name,
            "server_id": p.server_id,
            "quarantine_reason": p.quarantine_reason,
            "schema_hash": p.schema_hash,
            "updated_at": p.updated_at.isoformat() if p.updated_at else None,
        }
        for p in quarantined
    ]


@router.get("/tools/pins")
async def list_tool_pins(
    workspace_id: str = Query(default="default"),
    actor: AuthenticatedActor = Depends(get_pdp_actor),
    db: AsyncSession = Depends(get_db_session),
):
    """List all tool pins."""
    tenant_id = actor.tenant_id
    stmt = select(McpToolPinRecord).where(
        McpToolPinRecord.tenant_id == tenant_id,
        McpToolPinRecord.workspace_id == workspace_id,
    )
    res = await db.execute(stmt)
    pins = res.scalars().all()
    return [
        {
            "id": p.id,
            "tool_name": p.tool_name,
            "schema_hash": p.schema_hash,
            "description_hash": p.description_hash,
            "is_quarantined": p.is_quarantined,
            "quarantine_reason": p.quarantine_reason,
        }
        for p in pins
    ]
