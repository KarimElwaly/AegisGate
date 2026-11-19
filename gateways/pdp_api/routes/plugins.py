from typing import Any

from fastapi import APIRouter, Depends

from core.registry.registry import PluginRegistry, get_plugin_registry

router = APIRouter(prefix="/v1/plugins", tags=["Plugin Registry"])


@router.get("", response_model=dict[str, list[dict[str, Any]]])
@router.get("/catalog", response_model=dict[str, list[dict[str, Any]]])
async def get_plugin_catalog(
    registry: PluginRegistry = Depends(get_plugin_registry),
) -> dict[str, list[dict[str, Any]]]:
    """Returns the dynamic catalog and JSON schema for all loaded plugins (for UI auto-rendering)."""
    return registry.get_plugin_catalog()

