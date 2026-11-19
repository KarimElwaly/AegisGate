"""phase5 audit, hitl, and shadow tables

Revision ID: 0002_phase5_audit_hitl_shadow
Revises: 0001_initial_phase1
Create Date: 2026-11-20 00:00:00

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0002_phase5_audit_hitl_shadow"
down_revision: Union[str, None] = "0001_initial_phase1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. audit_records table
    op.create_table(
        "audit_records",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("workspace_id", sa.String(length=64), nullable=False),
        sa.Column("trace_id", sa.String(length=64), nullable=False),
        sa.Column("session_id", sa.String(length=64), nullable=True),
        sa.Column("policy_pack_id", sa.String(length=128), nullable=False),
        sa.Column("policy_pack_version", sa.String(length=32), nullable=False),
        sa.Column("effective_mode", sa.String(length=32), nullable=False, server_default="enforce"),
        sa.Column("stage", sa.String(length=32), nullable=False),
        sa.Column("decision", sa.String(length=32), nullable=False),
        sa.Column("would_have_decided", sa.String(length=32), nullable=True),
        sa.Column("actor_json", sa.Text(), nullable=False),
        sa.Column("action_json", sa.Text(), nullable=False),
        sa.Column("resolved_context_json", sa.Text(), nullable=False),
        sa.Column("scanner_findings_json", sa.Text(), nullable=False),
        sa.Column("compliance_tags_json", sa.Text(), nullable=False),
        sa.Column("latency_ms", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("payload_hash", sa.String(length=64), nullable=False),
        sa.Column("prev_hash", sa.String(length=64), nullable=False),
        sa.Column("record_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_records_tenant_id", "audit_records", ["tenant_id"])
    op.create_index("ix_audit_records_workspace_id", "audit_records", ["workspace_id"])
    op.create_index("ix_audit_records_trace_id", "audit_records", ["trace_id"])
    op.create_index("ix_audit_records_session_id", "audit_records", ["session_id"])
    op.create_index("ix_audit_records_policy_pack_id", "audit_records", ["policy_pack_id"])
    op.create_index("ix_audit_records_decision", "audit_records", ["decision"])
    op.create_index("ix_audit_records_record_hash", "audit_records", ["record_hash"])
    op.create_index("ix_audit_records_created_at", "audit_records", ["created_at"])

    # 2. approval_tickets table
    op.create_table(
        "approval_tickets",
        sa.Column("ticket_id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("workspace_id", sa.String(length=64), nullable=False),
        sa.Column("trace_id", sa.String(length=64), nullable=False),
        sa.Column("session_id", sa.String(length=64), nullable=True),
        sa.Column("policy_pack_id", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("action_name", sa.String(length=128), nullable=False),
        sa.Column("original_parameters_json", sa.Text(), nullable=False),
        sa.Column("modified_parameters_json", sa.Text(), nullable=True),
        sa.Column("triggered_rules_json", sa.Text(), nullable=False),
        sa.Column("resolved_context_json", sa.Text(), nullable=False),
        sa.Column("required_approvals", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("required_approver_roles_json", sa.Text(), nullable=False),
        sa.Column("approved_by_json", sa.Text(), nullable=False),
        sa.Column("rejected_by", sa.String(length=128), nullable=True),
        sa.Column("decision_notes", sa.Text(), nullable=True),
        sa.Column("callback_url", sa.String(length=512), nullable=True),
        sa.Column("callback_secret", sa.String(length=256), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("ticket_id"),
    )
    op.create_index("ix_approval_tickets_tenant_id", "approval_tickets", ["tenant_id"])
    op.create_index("ix_approval_tickets_workspace_id", "approval_tickets", ["workspace_id"])
    op.create_index("ix_approval_tickets_trace_id", "approval_tickets", ["trace_id"])
    op.create_index("ix_approval_tickets_session_id", "approval_tickets", ["session_id"])
    op.create_index("ix_approval_tickets_policy_pack_id", "approval_tickets", ["policy_pack_id"])
    op.create_index("ix_approval_tickets_status", "approval_tickets", ["status"])
    op.create_index("ix_approval_tickets_expires_at", "approval_tickets", ["expires_at"])
    op.create_index("ix_approval_tickets_created_at", "approval_tickets", ["created_at"])

    # 3. shadow_deltas table
    op.create_table(
        "shadow_deltas",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("workspace_id", sa.String(length=64), nullable=False),
        sa.Column("trace_id", sa.String(length=64), nullable=False),
        sa.Column("active_pack_id", sa.String(length=128), nullable=False),
        sa.Column("active_version", sa.String(length=32), nullable=False),
        sa.Column("shadow_pack_id", sa.String(length=128), nullable=False),
        sa.Column("shadow_version", sa.String(length=32), nullable=False),
        sa.Column("active_decision", sa.String(length=32), nullable=False),
        sa.Column("shadow_decision", sa.String(length=32), nullable=False),
        sa.Column("active_reasons_json", sa.Text(), nullable=False),
        sa.Column("shadow_reasons_json", sa.Text(), nullable=False),
        sa.Column("request_summary_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_shadow_deltas_tenant_id", "shadow_deltas", ["tenant_id"])
    op.create_index("ix_shadow_deltas_workspace_id", "shadow_deltas", ["workspace_id"])
    op.create_index("ix_shadow_deltas_trace_id", "shadow_deltas", ["trace_id"])
    op.create_index("ix_shadow_deltas_created_at", "shadow_deltas", ["created_at"])


def downgrade() -> None:
    op.drop_table("shadow_deltas")
    op.drop_table("approval_tickets")
    op.drop_table("audit_records")
