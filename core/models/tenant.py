import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base


class TenantRecord(Base):
    """Multi-tenant isolation boundary record."""

    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.datetime.utcnow
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow
    )


class WorkspaceRecord(Base):
    """Scoped workspace under a tenant."""

    __tablename__ = "workspaces"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_tenant_workspace_name"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    environment: Mapped[str] = mapped_column(String(32), default="dev")  # dev | staging | prod
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.datetime.utcnow
    )


class VirtualApiKeyRecord(Base):
    """Scoped Virtual API Key with policy default, budget caps, and rate limits."""

    __tablename__ = "virtual_api_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    workspace_id: Mapped[str] = mapped_column(String(64), index=True, default="default")
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(16), index=True, nullable=False)  # ag_live_...
    key_hash: Mapped[str] = mapped_column(String(64), index=True, nullable=False)  # sha256(full_key)
    role: Mapped[str] = mapped_column(String(32), default="Auditor")
    environment: Mapped[str] = mapped_column(String(32), default="dev")
    default_policy_pack_id: Mapped[str] = mapped_column(String(64), default="base-enterprise")
    allowed_models: Mapped[str] = mapped_column(Text, default="[]")  # JSON list
    budget_cap_usd: Mapped[float] = mapped_column(Float, default=100.0)
    rate_limit_rpm: Mapped[int] = mapped_column(Integer, default=600)
    revoked_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    expires_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.datetime.utcnow
    )


class PluginConfigRecord(Base):
    """Dynamic plugin configuration and instance definitions."""

    __tablename__ = "plugin_configs"
    __table_args__ = (
        UniqueConstraint("tenant_id", "workspace_id", "name", name="uq_tenant_plugin_name"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, default="default")
    workspace_id: Mapped[str] = mapped_column(String(64), index=True, default="default")
    plugin_type: Mapped[str] = mapped_column(String(32), nullable=False)  # scanner | resolver | notifier
    name: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    is_instance: Mapped[bool] = mapped_column(Boolean, default=False)
    config_json: Mapped[str] = mapped_column(Text, default="{}")
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.datetime.utcnow
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow
    )

