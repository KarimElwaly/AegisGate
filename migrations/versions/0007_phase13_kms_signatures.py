"""phase13 kms_signature column on audit_records table

Revision ID: 0007_phase13_kms_signatures
Revises: 0006_phase10_shadow_discovery
Create Date: 2026-11-21 23:45:00

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0007_phase13_kms_signatures"
down_revision: Union[str, None] = "0006_phase10_shadow_discovery"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("audit_records", sa.Column("kms_signature", sa.String(length=128), nullable=True))


def downgrade() -> None:
    op.drop_column("audit_records", "kms_signature")

