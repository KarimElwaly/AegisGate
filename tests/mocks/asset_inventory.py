from typing import Any

from fastapi import FastAPI, HTTPException

mock_inventory_app = FastAPI(title="Mock Asset Inventory Service")

MOCK_ASSET_DATABASE: dict[str, dict[str, Any]] = {
    "asset-dc-01": {
        "asset_id": "asset-dc-01",
        "hostname": "dc-primary.corp.local",
        "ip": "10.0.0.1",
        "asset_tier": "tier0",
        "is_domain_controller": True,
        "owner": "infrastructure-team",
    },
    "asset-db-02": {
        "asset_id": "asset-db-02",
        "hostname": "prod-db-cluster.corp.local",
        "ip": "10.0.1.50",
        "asset_tier": "tier0",
        "is_domain_controller": False,
        "owner": "database-team",
    },
    "asset-laptop-03": {
        "asset_id": "asset-laptop-03",
        "hostname": "laptop-analyst-33.corp.local",
        "ip": "192.168.10.45",
        "asset_tier": "standard",
        "is_domain_controller": False,
        "owner": "hr-department",
    },
}


@mock_inventory_app.get("/v1/assets/{asset_id}")
async def get_asset(asset_id: str) -> dict[str, Any]:
    asset = MOCK_ASSET_DATABASE.get(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found in inventory")
    return asset

