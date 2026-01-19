"""add_order_data_column_to_clients

Revision ID: 2a5c9bde3341
Revises: 003
Create Date: 2026-01-16 13:57:13.882606

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = '2a5c9bde3341'
down_revision = '003'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add order_data column to clients table if it doesn't exist
    # Check if column already exists before adding (for idempotency)
    connection = op.get_bind()
    inspector = sa.inspect(connection)
    columns = [col['name'] for col in inspector.get_columns('clients')]
    
    if 'order_data' not in columns:
        op.add_column('clients', sa.Column('order_data', postgresql.JSONB(), nullable=True))


def downgrade() -> None:
    # Remove order_data column from clients table (only if it exists)
    connection = op.get_bind()
    inspector = sa.inspect(connection)
    columns = [col['name'] for col in inspector.get_columns('clients')]
    
    if 'order_data' in columns:
        op.drop_column('clients', 'order_data')

