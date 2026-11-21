import datetime
from sqlalchemy import Boolean, DateTime, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base


class UpstreamMcpServerRecord(Base):
    """Registered upstream Model Context Protocol (MCP) server."""

    __tablename__ = "upstream_mcp_servers"
    __table_args__ = (
        UniqueConstraint("tenant_id", "workspace_id", "name", name="uq_tenant_mcp_server_name"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, default="default")
    workspace_id: Mapped[str] = mapped_column(String(64), index=True, default="default")
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    server_url: Mapped[str] = mapped_column(String(512), nullable=False)
    auth_headers_json: Mapped[str] = mapped_column(Text, default="{}")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.datetime.utcnow
    )


class McpToolPinRecord(Base):
    """Cryptographic Anti-Rug-Pull pin for MCP tool schema and description."""

    __tablename__ = "mcp_tool_pins"
    __table_args__ = (
        UniqueConstraint("tenant_id", "workspace_id", "tool_name", name="uq_tenant_mcp_tool_pin"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, default="default")
    workspace_id: Mapped[str] = mapped_column(String(64), index=True, default="default")
    server_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    tool_name: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    schema_hash: Mapped[str] = mapped_column(String(64), nullable=False)  # sha256(canonical_json(schema))
    description_hash: Mapped[str] = mapped_column(String(64), nullable=False)  # sha256(description)
    description: Mapped[str] = mapped_column(Text, default="")
    input_schema_json: Mapped[str] = mapped_column(Text, default="{}")
    is_quarantined: Mapped[bool] = mapped_column(Boolean, default=False)
    quarantine_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.datetime.utcnow
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow
    )
