"""add_is_home_to_industries

Revision ID: 004
Revises: 2a5c9bde3341
Create Date: 2026-01-16 14:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = '004'
down_revision = '2a5c9bde3341'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add is_home column to industries table if it doesn't exist
    # Check if column already exists before adding (for idempotency)
    connection = op.get_bind()
    inspector = sa.inspect(connection)
    columns = [col['name'] for col in inspector.get_columns('industries')]
    
    if 'is_home' not in columns:
        op.add_column('industries', sa.Column('is_home', sa.Boolean(), nullable=False, server_default='false'))


def downgrade() -> None:
    # Remove is_home column from industries table (only if it exists)
    connection = op.get_bind()
    inspector = sa.inspect(connection)
    columns = [col['name'] for col in inspector.get_columns('industries')]
    
    if 'is_home' in columns:
        op.drop_column('industries', 'is_home')


