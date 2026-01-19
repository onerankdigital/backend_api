"""add_is_top_to_industries

Revision ID: 007
Revises: 006
Create Date: 2026-01-16 16:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = '007'
down_revision = '006'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add is_top column to industries table if it doesn't exist
    # Check if column already exists before adding (for idempotency)
    connection = op.get_bind()
    inspector = sa.inspect(connection)
    columns = [col['name'] for col in inspector.get_columns('industries')]
    
    if 'is_top' not in columns:
        op.add_column('industries', sa.Column('is_top', sa.Boolean(), nullable=False, server_default='false'))


def downgrade() -> None:
    # Remove is_top column from industries table (only if it exists)
    connection = op.get_bind()
    inspector = sa.inspect(connection)
    columns = [col['name'] for col in inspector.get_columns('industries')]
    
    if 'is_top' in columns:
        op.drop_column('industries', 'is_top')

