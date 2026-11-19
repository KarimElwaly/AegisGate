import datetime
from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from core.database import Base


class ShadowDeltaRecord(Base):
    __tablename__ = "shadow_deltas"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, default="default")
    workspace_id: Mapped[str] = mapped_column(String(64), index=True, default="default")
    trace_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)

    active_pack_id: Mapped[str] = mapped_column(String(128), nullable=False)
    active_version: Mapped[str] = mapped_column(String(32), nullable=False)
    shadow_pack_id: Mapped[str] = mapped_column(String(128), nullable=False)
    shadow_version: Mapped[str] = mapped_column(String(32), nullable=False)

    active_decision: Mapped[str] = mapped_column(String(32), nullable=False)
    shadow_decision: Mapped[str] = mapped_column(String(32), nullable=False)

    active_reasons_json: Mapped[str] = mapped_column(Text, default="[]")
    shadow_reasons_json: Mapped[str] = mapped_column(Text, default="[]")
    request_summary_json: Mapped[str] = mapped_column(Text, default="{}")

    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.datetime.utcnow, index=True
    )
