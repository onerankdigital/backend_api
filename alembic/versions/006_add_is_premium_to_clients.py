"""add_is_premium_to_clients

Revision ID: 006
Revises: 005
Create Date: 2026-01-16 15:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = '006'
down_revision = '005'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add is_premium column to clients table if it doesn't exist
    connection = op.get_bind()
    inspector = sa.inspect(connection)
    columns = [col['name'] for col in inspector.get_columns('clients')]
    
    if 'is_premium' not in columns:
        op.add_column('clients', sa.Column('is_premium', sa.Boolean(), nullable=False, server_default='false'))


def downgrade() -> None:
    # Remove is_premium column from clients table (only if it exists)
    connection = op.get_bind()
    inspector = sa.inspect(connection)
    columns = [col['name'] for col in inspector.get_columns('clients')]
    
    if 'is_premium' in columns:
        op.drop_column('clients', 'is_premium')

