"""add_logo_to_industries

Revision ID: 008
Revises: 007
Create Date: 2026-01-16 17:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = '008'
down_revision = '007'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add logo column to industries table if it doesn't exist
    # Check if column already exists before adding (for idempotency)
    connection = op.get_bind()
    inspector = sa.inspect(connection)
    columns = [col['name'] for col in inspector.get_columns('industries')]
    
    if 'logo' not in columns:
        op.add_column('industries', sa.Column('logo', sa.String(), nullable=True))


def downgrade() -> None:
    # Remove logo column from industries table (only if it exists)
    connection = op.get_bind()
    inspector = sa.inspect(connection)
    columns = [col['name'] for col in inspector.get_columns('industries')]
    
    if 'logo' in columns:
        op.drop_column('industries', 'logo')

