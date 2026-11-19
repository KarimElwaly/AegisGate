import datetime

from sqlalchemy import DateTime, Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base


class AuditRecord(Base):
    __tablename__ = "audit_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, default="default")
    workspace_id: Mapped[str] = mapped_column(String(64), index=True, default="default")
    trace_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    session_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    policy_pack_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    policy_pack_version: Mapped[str] = mapped_column(String(32), nullable=False)
    effective_mode: Mapped[str] = mapped_column(String(32), default="enforce")
    stage: Mapped[str] = mapped_column(String(32), nullable=False)
    decision: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    would_have_decided: Mapped[str | None] = mapped_column(String(32), nullable=True)
    actor_json: Mapped[str] = mapped_column(Text, default="{}")
    action_json: Mapped[str] = mapped_column(Text, default="{}")
    resolved_context_json: Mapped[str] = mapped_column(Text, default="{}")
    scanner_findings_json: Mapped[str] = mapped_column(Text, default="[]")
    compliance_tags_json: Mapped[str] = mapped_column(Text, default="[]")
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)

    # Cryptographic Hash Chain Fields
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.datetime.utcnow, index=True
    )

