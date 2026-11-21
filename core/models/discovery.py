import datetime
from sqlalchemy import DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base


class DiscoveredAssetRecord(Base):
    """Auto-discovered Shadow AI model, tool, MCP server, or external destination."""

    __tablename__ = "discovered_assets"
    __table_args__ = (
        UniqueConstraint("tenant_id", "workspace_id", "asset_type", "name", name="uq_discovered_asset"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, default="default")
    workspace_id: Mapped[str] = mapped_column(String(64), index=True, default="default")
    asset_type: Mapped[str] = mapped_column(String(32), index=True)  # model | tool | mcp_server | agent
    name: Mapped[str] = mapped_column(String(128), index=True)
    first_seen_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.datetime.utcnow
    )
    last_seen_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow
    )
    request_count: Mapped[int] = mapped_column(Integer, default=1)
    risk_level: Mapped[str] = mapped_column(String(16), default="medium")  # low | medium | high | critical
    governance_status: Mapped[str] = mapped_column(
        String(32), default="shadow_unapproved"
    )  # governed | shadow_unapproved | blocked
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")

