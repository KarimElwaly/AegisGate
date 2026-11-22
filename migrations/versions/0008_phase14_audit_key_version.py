"""phase14 kms_key_version column on audit_records table

Revision ID: 0008_phase14_audit_key_version
Revises: 0007_phase13_kms_signatures
Create Date: 2026-11-22 01:00:00

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0008_phase14_audit_key_version"
down_revision: Union[str, None] = "0007_phase13_kms_signatures"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("audit_records", sa.Column("kms_key_version", sa.String(length=32), nullable=True))


def downgrade() -> None:
    op.drop_column("audit_records", "kms_key_version")

