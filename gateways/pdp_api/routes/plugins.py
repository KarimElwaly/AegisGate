from typing import Any, Dict, List
from fastapi import APIRouter, Depends
from core.registry.registry import PluginRegistry, get_plugin_registry

router = APIRouter(prefix="/v1/plugins", tags=["Plugin Registry"])


@router.get("", response_model=Dict[str, List[Dict[str, Any]]])
async def get_plugin_catalog(
    registry: PluginRegistry = Depends(get_plugin_registry),
) -> Dict[str, List[Dict[str, Any]]]:
    """Returns the dynamic catalog and JSON schema for all loaded plugins (for UI auto-rendering)."""
    return registry.get_plugin_catalog()
