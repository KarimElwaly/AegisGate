"""phase16 unique constraint on audit_records (tenant_id, prev_hash)

Revision ID: 0009_phase16_audit_chain_unique
Revises: 0008_phase14_audit_key_version
Create Date: 2026-11-22 14:00:00

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0009_phase16_audit_chain_unique"
down_revision: Union[str, None] = "0008_phase14_audit_key_version"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_unique_constraint(
        "uq_audit_records_tenant_prev_hash",
        "audit_records",
        ["tenant_id", "prev_hash"],
    )


def downgrade() -> None:
    op.drop_constraint("uq_audit_records_tenant_prev_hash", "audit_records", type_="unique")
