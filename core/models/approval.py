import datetime

from sqlalchemy import DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from core.database import Base


class ApprovalTicketRecord(Base):
    __tablename__ = "approval_tickets"

    ticket_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, default="default")
    workspace_id: Mapped[str] = mapped_column(String(64), index=True, default="default")
    trace_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    session_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    policy_pack_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)  # pending | approved | rejected | expired
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)

    action_name: Mapped[str] = mapped_column(String(128), nullable=False)
    original_parameters_json: Mapped[str] = mapped_column(Text, default="{}")
    modified_parameters_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    triggered_rules_json: Mapped[str] = mapped_column(Text, default="[]")
    resolved_context_json: Mapped[str] = mapped_column(Text, default="{}")

    # Multi-approval / Dual-Approval (4-eyes principle)
    required_approvals: Mapped[int] = mapped_column(Integer, default=1)
    required_approver_roles_json: Mapped[str] = mapped_column(Text, default="[]")
    approved_by_json: Mapped[str] = mapped_column(Text, default="[]")  # list of approver user IDs
    rejected_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    decision_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Webhook Callback on resolution
    callback_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    callback_secret: Mapped[str | None] = mapped_column(String(256), nullable=True)

    expires_at: Mapped[datetime.datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.datetime.utcnow, index=True
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow
    )

