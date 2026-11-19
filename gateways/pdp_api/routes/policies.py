from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import desc, select, update
from sqlalchemy.ext.asyncio import AsyncSession
import yaml
from core.database import get_db_session
from core.logger import get_logger
from core.models.policy import PolicyPackRecord
from core.policy_engine.yaml_engine import YamlPolicyEngine, get_yaml_policy_engine
from core.redis_client import get_redis_client
from core.schemas.policy import PolicyPackDefinition

logger = get_logger("gateways.policies")
router = APIRouter(prefix="/v1/policies", tags=["Policy Packs"])


class PolicyCreatePayload(BaseModel):
    yaml_content: str
    tenant_id: str = "default"
    workspace_id: str = "default"
    status: str = "draft"  # draft | shadow | active


class PolicyPromotePayload(BaseModel):
    version: str
    target_status: str = "active"  # shadow | active


class PolicyRollbackPayload(BaseModel):
    target_version: str


@router.post("", response_model=Dict[str, Any])
async def create_or_update_policy(
    payload: PolicyCreatePayload,
    db: AsyncSession = Depends(get_db_session),
    engine: YamlPolicyEngine = Depends(get_yaml_policy_engine),
) -> Dict[str, Any]:
    """Upload, validate, and store a new version of a Policy Pack."""
    try:
        raw_dict = yaml.safe_load(payload.yaml_content)
        parsed_pack = PolicyPackDefinition(**raw_dict)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid Policy Pack YAML: {str(e)}")

    # Check if this (tenant_id, pack_id, version) already exists
    stmt = select(PolicyPackRecord).where(
        PolicyPackRecord.tenant_id == payload.tenant_id,
        PolicyPackRecord.pack_id == parsed_pack.id,
        PolicyPackRecord.version == parsed_pack.version,
    )
    result = await db.execute(stmt)
    existing = result.scalar_one_or_none()

    if existing:
        existing.name = parsed_pack.name
        existing.description = parsed_pack.description
        existing.yaml_dsl = payload.yaml_content
        existing.status = payload.status
        await db.commit()
        record_id = existing.id
    else:
        new_record = PolicyPackRecord(
            tenant_id=payload.tenant_id,
            workspace_id=payload.workspace_id,
            pack_id=parsed_pack.id,
            version=parsed_pack.version,
            name=parsed_pack.name,
            description=parsed_pack.description,
            status=payload.status,
            yaml_dsl=payload.yaml_content,
        )
        db.add(new_record)
        await db.commit()
        record_id = new_record.id

    # If status is active or shadow, register in memory engine
    if payload.status in ("active", "shadow"):
        engine.register_policy_pack(parsed_pack)

    # Publish Redis pub/sub invalidation event
    try:
        redis = await get_redis_client()
        await redis.publish(
            "aegisgate:policy:invalidation",
            f"{payload.tenant_id}:{parsed_pack.id}:{parsed_pack.version}",
        )
    except Exception as e:
        logger.warning("Failed to publish policy invalidation event", error=str(e))

    return {
        "status": "success",
        "id": record_id,
        "pack_id": parsed_pack.id,
        "version": parsed_pack.version,
        "policy_status": payload.status,
    }


@router.get("", response_model=List[Dict[str, Any]])
async def list_policies(
    tenant_id: str = "default",
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db_session),
) -> List[Dict[str, Any]]:
    """List policy packs for a given tenant."""
    query = select(PolicyPackRecord).where(PolicyPackRecord.tenant_id == tenant_id)
    if status:
        query = query.where(PolicyPackRecord.status == status)
    query = query.order_by(desc(PolicyPackRecord.created_at))

    result = await db.execute(query)
    records = result.scalars().all()

    return [
        {
            "id": r.id,
            "tenant_id": r.tenant_id,
            "workspace_id": r.workspace_id,
            "pack_id": r.pack_id,
            "version": r.version,
            "name": r.name,
            "description": r.description,
            "status": r.status,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "updated_at": r.updated_at.isoformat() if r.updated_at else None,
        }
        for r in records
    ]


@router.get("/{pack_id}", response_model=Dict[str, Any])
async def get_policy_pack(
    pack_id: str,
    tenant_id: str = "default",
    db: AsyncSession = Depends(get_db_session),
    engine: YamlPolicyEngine = Depends(get_yaml_policy_engine),
) -> Dict[str, Any]:
    """Get active policy pack details."""
    # Check in-memory engine first
    in_mem = engine.get_policy_pack(pack_id)
    if in_mem:
        return in_mem.model_dump()

    # Query DB for active version
    stmt = (
        select(PolicyPackRecord)
        .where(
            PolicyPackRecord.tenant_id == tenant_id,
            PolicyPackRecord.pack_id == pack_id,
            PolicyPackRecord.status == "active",
        )
        .order_by(desc(PolicyPackRecord.created_at))
    )
    result = await db.execute(stmt)
    record = result.scalars().first()

    if not record:
        # Fall back to latest version
        stmt = (
            select(PolicyPackRecord)
            .where(
                PolicyPackRecord.tenant_id == tenant_id,
                PolicyPackRecord.pack_id == pack_id,
            )
            .order_by(desc(PolicyPackRecord.created_at))
        )
        result = await db.execute(stmt)
        record = result.scalars().first()

    if not record:
        raise HTTPException(status_code=404, detail=f"Policy pack '{pack_id}' not found")

    return {
        "id": record.pack_id,
        "version": record.version,
        "name": record.name,
        "description": record.description,
        "status": record.status,
        "yaml_dsl": record.yaml_dsl,
    }


@router.get("/{pack_id}/versions", response_model=List[Dict[str, Any]])
async def get_policy_versions(
    pack_id: str,
    tenant_id: str = "default",
    db: AsyncSession = Depends(get_db_session),
) -> List[Dict[str, Any]]:
    """Get version history for a policy pack."""
    stmt = (
        select(PolicyPackRecord)
        .where(
            PolicyPackRecord.tenant_id == tenant_id,
            PolicyPackRecord.pack_id == pack_id,
        )
        .order_by(desc(PolicyPackRecord.created_at))
    )
    result = await db.execute(stmt)
    records = result.scalars().all()

    return [
        {
            "id": r.id,
            "version": r.version,
            "status": r.status,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "updated_at": r.updated_at.isoformat() if r.updated_at else None,
        }
        for r in records
    ]


@router.post("/{pack_id}/promote", response_model=Dict[str, Any])
async def promote_policy_version(
    pack_id: str,
    payload: PolicyPromotePayload,
    tenant_id: str = "default",
    db: AsyncSession = Depends(get_db_session),
    engine: YamlPolicyEngine = Depends(get_yaml_policy_engine),
) -> Dict[str, Any]:
    """Promote a policy version: draft -> shadow -> active (1-click lifecycle)."""
    # Find the target version
    stmt = select(PolicyPackRecord).where(
        PolicyPackRecord.tenant_id == tenant_id,
        PolicyPackRecord.pack_id == pack_id,
        PolicyPackRecord.version == payload.version,
    )
    result = await db.execute(stmt)
    target_record = result.scalar_one_or_none()

    if not target_record:
        raise HTTPException(
            status_code=404,
            detail=f"Version '{payload.version}' of pack '{pack_id}' not found",
        )

    # If promoting to active, archive any currently active pack
    if payload.target_status == "active":
        await db.execute(
            update(PolicyPackRecord)
            .where(
                PolicyPackRecord.tenant_id == tenant_id,
                PolicyPackRecord.pack_id == pack_id,
                PolicyPackRecord.status == "active",
            )
            .values(status="archived")
        )

    target_record.status = payload.target_status
    await db.commit()

    # Load into memory
    parsed_pack = engine.load_from_yaml_string(target_record.yaml_dsl)

    return {
        "status": "promoted",
        "pack_id": pack_id,
        "version": payload.version,
        "new_status": payload.target_status,
    }


@router.post("/{pack_id}/rollback", response_model=Dict[str, Any])
async def rollback_policy_version(
    pack_id: str,
    payload: PolicyRollbackPayload,
    tenant_id: str = "default",
    db: AsyncSession = Depends(get_db_session),
    engine: YamlPolicyEngine = Depends(get_yaml_policy_engine),
) -> Dict[str, Any]:
    """1-click rollback: Demotes current active version and activates target_version."""
    stmt = select(PolicyPackRecord).where(
        PolicyPackRecord.tenant_id == tenant_id,
        PolicyPackRecord.pack_id == pack_id,
        PolicyPackRecord.version == payload.target_version,
    )
    result = await db.execute(stmt)
    target_record = result.scalar_one_or_none()

    if not target_record:
        raise HTTPException(
            status_code=404,
            detail=f"Target rollback version '{payload.target_version}' not found",
        )

    # Archive currently active
    await db.execute(
        update(PolicyPackRecord)
        .where(
            PolicyPackRecord.tenant_id == tenant_id,
            PolicyPackRecord.pack_id == pack_id,
            PolicyPackRecord.status == "active",
        )
        .values(status="archived")
    )

    target_record.status = "active"
    await db.commit()

    # Load into memory
    engine.load_from_yaml_string(target_record.yaml_dsl)

    return {
        "status": "rolled_back",
        "pack_id": pack_id,
        "active_version": payload.target_version,
    }
