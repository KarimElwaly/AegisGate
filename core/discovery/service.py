import datetime
import json
import uuid
from typing import Any

from sqlalchemy import select

from core.database import db_context
from core.logger import get_logger
from core.models.discovery import DiscoveredAssetRecord

logger = get_logger("core.discovery.service")


class DiscoveryService:
    """Auto-discovers and inventories Shadow AI models, tools, and agents."""

    async def record_asset(
        self,
        tenant_id: str,
        workspace_id: str,
        asset_type: str,
        name: str,
        metadata: dict[str, Any] | None = None,
        risk_level: str = "medium",
    ) -> None:
        if not name or name in ("default", "default_action", "unknown"):
            return

        try:
            async with db_context() as session:
                stmt = select(DiscoveredAssetRecord).where(
                    DiscoveredAssetRecord.tenant_id == tenant_id,
                    DiscoveredAssetRecord.workspace_id == workspace_id,
                    DiscoveredAssetRecord.asset_type == asset_type,
                    DiscoveredAssetRecord.name == name,
                )
                res = await session.execute(stmt)
                rec = res.scalar_one_or_none()

                now = datetime.datetime.utcnow()
                if rec:
                    rec.request_count += 1
                    rec.last_seen_at = now
                    if metadata:
                        try:
                            curr_meta = json.loads(rec.metadata_json or "{}")
                            curr_meta.update(metadata)
                            rec.metadata_json = json.dumps(curr_meta)
                        except Exception:
                            pass
                else:
                    new_rec = DiscoveredAssetRecord(
                        id=str(uuid.uuid4()),
                        tenant_id=tenant_id,
                        workspace_id=workspace_id,
                        asset_type=asset_type,
                        name=name,
                        first_seen_at=now,
                        last_seen_at=now,
                        request_count=1,
                        risk_level=risk_level,
                        governance_status="shadow_unapproved",
                        metadata_json=json.dumps(metadata or {}),
                    )
                    session.add(new_rec)
                await session.commit()
        except Exception as e:
            logger.debug("record_asset_skipped", error=str(e), name=name)


default_discovery_service = DiscoveryService()


def get_discovery_service() -> DiscoveryService:
    return default_discovery_service

