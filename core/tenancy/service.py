import datetime
import hashlib
import json
import secrets
import uuid
from typing import Any

from sqlalchemy import desc, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from core.models.tenant import TenantRecord, VirtualApiKeyRecord, WorkspaceRecord


class TenancyService:
    """Service layer managing Tenants, Workspaces, and Virtual API Keys."""

    async def create_tenant(
        self, session: AsyncSession, tenant_id: str, name: str
    ) -> TenantRecord:
        tenant = TenantRecord(id=tenant_id, name=name, is_active=True)
        session.add(tenant)
        # Automatically provision default workspace
        ws = WorkspaceRecord(
            id=f"{tenant_id}-default",
            tenant_id=tenant_id,
            name="default",
            environment="dev",
            is_active=True,
        )
        session.add(ws)
        await session.commit()
        await session.refresh(tenant)
        return tenant

    async def get_tenant(self, session: AsyncSession, tenant_id: str) -> TenantRecord | None:
        stmt = select(TenantRecord).where(TenantRecord.id == tenant_id)
        res = await session.execute(stmt)
        return res.scalar_one_or_none()

    async def list_tenants(self, session: AsyncSession) -> list[TenantRecord]:
        stmt = select(TenantRecord).order_by(desc(TenantRecord.created_at))
        res = await session.execute(stmt)
        return list(res.scalars().all())

    async def create_workspace(
        self,
        session: AsyncSession,
        workspace_id: str,
        tenant_id: str,
        name: str,
        environment: str = "dev",
    ) -> WorkspaceRecord:
        ws = WorkspaceRecord(
            id=workspace_id,
            tenant_id=tenant_id,
            name=name,
            environment=environment,
            is_active=True,
        )
        session.add(ws)
        await session.commit()
        await session.refresh(ws)
        return ws

    async def list_workspaces(
        self, session: AsyncSession, tenant_id: str
    ) -> list[WorkspaceRecord]:
        stmt = (
            select(WorkspaceRecord)
            .where(WorkspaceRecord.tenant_id == tenant_id)
            .order_by(desc(WorkspaceRecord.created_at))
        )
        res = await session.execute(stmt)
        return list(res.scalars().all())

    async def issue_virtual_key(
        self,
        session: AsyncSession,
        tenant_id: str,
        workspace_id: str,
        name: str,
        role: str = "Auditor",
        environment: str = "dev",
        default_policy_pack_id: str = "base-enterprise",
        allowed_models: list[str] | None = None,
        budget_cap_usd: float = 100.0,
        rate_limit_rpm: int = 600,
        expires_in_days: int | None = None,
    ) -> tuple[VirtualApiKeyRecord, str]:
        token = secrets.token_hex(24)
        plaintext_key = f"ag_live_{token}"
        key_prefix = plaintext_key[:12]
        key_hash = hashlib.sha256(plaintext_key.encode("utf-8")).hexdigest()

        expires_at = (
            datetime.datetime.utcnow() + datetime.timedelta(days=expires_in_days)
            if expires_in_days
            else None
        )

        rec = VirtualApiKeyRecord(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            name=name,
            key_prefix=key_prefix,
            key_hash=key_hash,
            role=role,
            environment=environment,
            default_policy_pack_id=default_policy_pack_id,
            allowed_models=json.dumps(allowed_models or []),
            budget_cap_usd=budget_cap_usd,
            rate_limit_rpm=rate_limit_rpm,
            revoked_at=None,
            expires_at=expires_at,
        )
        session.add(rec)
        await session.commit()
        await session.refresh(rec)
        return rec, plaintext_key

    async def list_virtual_keys(
        self, session: AsyncSession, tenant_id: str, workspace_id: str | None = None
    ) -> list[VirtualApiKeyRecord]:
        stmt = select(VirtualApiKeyRecord).where(VirtualApiKeyRecord.tenant_id == tenant_id)
        if workspace_id:
            stmt = stmt.where(VirtualApiKeyRecord.workspace_id == workspace_id)
        stmt = stmt.order_by(desc(VirtualApiKeyRecord.created_at))
        res = await session.execute(stmt)
        return list(res.scalars().all())

    async def revoke_virtual_key(
        self, session: AsyncSession, key_id: str, tenant_id: str
    ) -> bool:
        stmt = (
            update(VirtualApiKeyRecord)
            .where(
                VirtualApiKeyRecord.id == key_id,
                VirtualApiKeyRecord.tenant_id == tenant_id,
                VirtualApiKeyRecord.revoked_at.is_(None),
            )
            .values(revoked_at=datetime.datetime.utcnow())
        )
        res = await session.execute(stmt)
        await session.commit()
        return res.rowcount > 0

    async def rotate_virtual_key(
        self, session: AsyncSession, key_id: str, tenant_id: str
    ) -> tuple[VirtualApiKeyRecord, str] | None:
        # 1. Fetch current key
        stmt = select(VirtualApiKeyRecord).where(
            VirtualApiKeyRecord.id == key_id,
            VirtualApiKeyRecord.tenant_id == tenant_id,
        )
        res = await session.execute(stmt)
        old_rec = res.scalar_one_or_none()
        if not old_rec:
            return None

        # 2. Revoke old key
        old_rec.revoked_at = datetime.datetime.utcnow()

        # 3. Issue replacement with same permissions
        new_rec, plaintext = await self.issue_virtual_key(
            session=session,
            tenant_id=old_rec.tenant_id,
            workspace_id=old_rec.workspace_id,
            name=f"{old_rec.name} (Rotated)",
            role=old_rec.role,
            environment=old_rec.environment,
            default_policy_pack_id=old_rec.default_policy_pack_id,
            allowed_models=json.loads(old_rec.allowed_models or "[]"),
            budget_cap_usd=old_rec.budget_cap_usd,
            rate_limit_rpm=old_rec.rate_limit_rpm,
        )
        return new_rec, plaintext

    async def validate_virtual_key(
        self, session: AsyncSession, plaintext_key: str
    ) -> VirtualApiKeyRecord | None:
        key_hash = hashlib.sha256(plaintext_key.encode("utf-8")).hexdigest()
        stmt = select(VirtualApiKeyRecord).where(VirtualApiKeyRecord.key_hash == key_hash)
        res = await session.execute(stmt)
        rec = res.scalar_one_or_none()
        if not rec:
            return None

        if rec.revoked_at is not None:
            return None

        if rec.expires_at is not None and rec.expires_at < datetime.datetime.utcnow():
            return None

        return rec


default_tenancy_service = TenancyService()


def get_tenancy_service() -> TenancyService:
    return default_tenancy_service

