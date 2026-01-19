"""add_description_to_clients

Revision ID: 011
Revises: 010
Create Date: 2026-01-16 19:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '011'
down_revision = '010'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add description column to clients table if it doesn't exist
    connection = op.get_bind()
    inspector = sa.inspect(connection)
    columns = [col['name'] for col in inspector.get_columns('clients')]
    
    if 'description' not in columns:
        op.add_column('clients', sa.Column('description', sa.String(), nullable=True))


def downgrade() -> None:
    # Remove description column from clients table (only if it exists)
    connection = op.get_bind()
    inspector = sa.inspect(connection)
    columns = [col['name'] for col in inspector.get_columns('clients')]
    
    if 'description' in columns:
        op.drop_column('clients', 'description')

