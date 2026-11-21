import json
import uuid
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.auth.dependencies import AuthenticatedActor, require_role
from core.database import get_db_session
from core.models.tenant import PluginConfigRecord
from core.redis_client import get_redis_client
from core.registry.registry import PluginRegistry, get_plugin_registry
from plugins.scanners.webhook_scanner import WebhookScanner

router = APIRouter(prefix="/v1/plugins", tags=["Plugin Registry & Dynamic Control"])


class PluginInstanceCreateRequest(BaseModel):
    tenant_id: str = "default"
    workspace_id: str = "default"
    plugin_type: str = Field(..., pattern="^(scanner|resolver|notifier)$")
    name: str = Field(..., min_length=2, max_length=128)
    config: dict[str, Any] = Field(default_factory=dict)
    is_enabled: bool = True


class PluginConfigPatchRequest(BaseModel):
    config: dict[str, Any] = Field(default_factory=dict)
    is_enabled: bool | None = None


class PluginTestRequest(BaseModel):
    test_payload: dict[str, Any] = Field(default_factory=dict)


@router.get("", response_model=dict[str, list[dict[str, Any]]])
@router.get("/catalog", response_model=dict[str, list[dict[str, Any]]])
async def get_plugin_catalog(
    registry: PluginRegistry = Depends(get_plugin_registry),
) -> dict[str, list[dict[str, Any]]]:
    """Returns the dynamic catalog and metadata for all loaded plugins."""
    return registry.get_plugin_catalog()


@router.get("/schemas", response_model=dict[str, Any])
async def get_plugin_schemas(
    registry: PluginRegistry = Depends(get_plugin_registry),
) -> dict[str, Any]:
    """Exports OpenAPI/Pydantic JSON Schema for every registered plugin's ConfigSchema."""
    schemas: dict[str, Any] = {}
    catalog = registry.get_plugin_catalog()
    for cat_name, items in catalog.items():
        for item in items:
            schemas[item["name"]] = {
                "type": cat_name[:-1],  # scanner | resolver | notifier
                "version": item.get("version", "1.0.0"),
                "tier": item.get("tier"),
                "schema": item.get("config_schema", {}),
            }
    return schemas


@router.post("/instances", response_model=dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_plugin_instance(
    payload: PluginInstanceCreateRequest,
    session: AsyncSession = Depends(get_db_session),
    registry: PluginRegistry = Depends(get_plugin_registry),
    actor: AuthenticatedActor = Depends(require_role("SuperAdmin", "TenantAdmin")),
) -> dict[str, Any]:
    """Dynamically register a plugin instance (e.g. custom WebhookScanner or ContextResolver)."""
    if actor.role != "SuperAdmin" and actor.tenant_id != payload.tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access forbidden")

    # Validate configuration against base plugin schema if known
    base_name = payload.config.get("base_plugin", "webhook_scanner")
    try:
        registry.validate_plugin_config(payload.plugin_type, base_name, payload.config)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Plugin config validation failed: {e!s}",
        )

    rec_id = str(uuid.uuid4())
    rec = PluginConfigRecord(
        id=rec_id,
        tenant_id=payload.tenant_id,
        workspace_id=payload.workspace_id,
        plugin_type=payload.plugin_type,
        name=payload.name,
        is_instance=True,
        config_json=json.dumps(payload.config),
        is_enabled=payload.is_enabled,
    )
    session.add(rec)
    await session.commit()
    await session.refresh(rec)

    # In-memory registration (e.g. for dynamic WebhookScanner instance)
    if payload.plugin_type == "scanner":
        instance = WebhookScanner()
        instance.name = payload.name
        registry.register_scanner(instance)

    # Publish Redis pub/sub invalidation event
    try:
        redis = await get_redis_client()
        await redis.publish(
            "aegisgate:plugins:reload",
            f"{payload.tenant_id}:{payload.workspace_id}:{payload.name}",
        )
    except Exception:
        pass

    return {
        "status": "created",
        "id": rec.id,
        "name": rec.name,
        "plugin_type": rec.plugin_type,
        "tenant_id": rec.tenant_id,
        "workspace_id": rec.workspace_id,
        "is_enabled": rec.is_enabled,
    }


@router.delete("/instances/{instance_id}", response_model=dict[str, Any])
async def delete_plugin_instance(
    instance_id: str,
    tenant_id: str = Query(..., description="Tenant ID"),
    session: AsyncSession = Depends(get_db_session),
    registry: PluginRegistry = Depends(get_plugin_registry),
    actor: AuthenticatedActor = Depends(require_role("SuperAdmin", "TenantAdmin")),
) -> dict[str, Any]:
    """Unregister and remove a dynamic plugin instance."""
    if actor.role != "SuperAdmin" and actor.tenant_id != tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access forbidden")

    stmt = select(PluginConfigRecord).where(
        PluginConfigRecord.id == instance_id,
        PluginConfigRecord.tenant_id == tenant_id,
    )
    res = await session.execute(stmt)
    rec = res.scalar_one_or_none()
    if not rec:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Plugin instance not found")

    if rec.plugin_type == "scanner":
        registry.unregister_scanner(rec.name)

    await session.delete(rec)
    await session.commit()

    try:
        redis = await get_redis_client()
        await redis.publish(
            "aegisgate:plugins:reload",
            f"{rec.tenant_id}:{rec.workspace_id}:{rec.name}:deleted",
        )
    except Exception:
        pass

    return {"status": "deleted", "id": instance_id}


@router.patch("/{plugin_name}/config", response_model=dict[str, Any])
async def update_plugin_config(
    plugin_name: str,
    payload: PluginConfigPatchRequest,
    tenant_id: str = Query("default"),
    workspace_id: str = Query("default"),
    session: AsyncSession = Depends(get_db_session),
    actor: AuthenticatedActor = Depends(require_role("SuperAdmin", "TenantAdmin")),
) -> dict[str, Any]:
    """Update and hot-reload scanner or resolver configuration parameters."""
    if actor.role != "SuperAdmin" and actor.tenant_id != tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access forbidden")

    stmt = select(PluginConfigRecord).where(
        PluginConfigRecord.tenant_id == tenant_id,
        PluginConfigRecord.workspace_id == workspace_id,
        PluginConfigRecord.name == plugin_name,
    )
    res = await session.execute(stmt)
    rec = res.scalar_one_or_none()

    if not rec:
        # Create record
        rec = PluginConfigRecord(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            plugin_type="scanner",
            name=plugin_name,
            config_json=json.dumps(payload.config),
            is_enabled=payload.is_enabled if payload.is_enabled is not None else True,
        )
        session.add(rec)
    else:
        existing = json.loads(rec.config_json or "{}")
        existing.update(payload.config)
        rec.config_json = json.dumps(existing)
        if payload.is_enabled is not None:
            rec.is_enabled = payload.is_enabled

    await session.commit()
    await session.refresh(rec)

    try:
        redis = await get_redis_client()
        await redis.publish("aegisgate:plugins:reload", f"{tenant_id}:{workspace_id}:{plugin_name}")
    except Exception:
        pass

    return {
        "status": "updated",
        "name": rec.name,
        "is_enabled": rec.is_enabled,
        "config": json.loads(rec.config_json),
    }


@router.post("/{plugin_name}/test", response_model=dict[str, Any])
async def test_plugin_connectivity(
    plugin_name: str,
    payload: PluginTestRequest,
    registry: PluginRegistry = Depends(get_plugin_registry),
    actor: AuthenticatedActor = Depends(require_role("SuperAdmin", "TenantAdmin", "Auditor")),
) -> dict[str, Any]:
    """Dry-run / connectivity ping test for a scanner or resolver endpoint."""
    scanner = registry.get_scanner(plugin_name)
    resolver = registry.get_resolver(plugin_name)

    if not scanner and not resolver:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Plugin '{plugin_name}' not found in registry",
        )

    # If it has an endpoint_url in config or payload, attempt HTTP ping
    endpoint = payload.test_payload.get("endpoint_url")
    if endpoint:
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                res = await client.get(endpoint)
                return {
                    "status": "reachable",
                    "plugin_name": plugin_name,
                    "endpoint": endpoint,
                    "http_status": res.status_code,
                }
        except Exception as e:
            return {
                "status": "unreachable",
                "plugin_name": plugin_name,
                "endpoint": endpoint,
                "error": str(e),
            }

    return {
        "status": "ok",
        "plugin_name": plugin_name,
        "registered": True,
        "type": "scanner" if scanner else "resolver",
    }
