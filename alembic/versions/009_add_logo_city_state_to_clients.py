"""add_logo_city_state_to_clients

Revision ID: 009
Revises: 008
Create Date: 2026-01-16 18:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = '009'
down_revision = '008'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add logo, city, and state columns to clients table if they don't exist
    connection = op.get_bind()
    inspector = sa.inspect(connection)
    columns = [col['name'] for col in inspector.get_columns('clients')]
    
    if 'logo' not in columns:
        op.add_column('clients', sa.Column('logo', sa.String(), nullable=True))
    
    if 'city' not in columns:
        op.add_column('clients', sa.Column('city', sa.String(), nullable=True))
    
    if 'state' not in columns:
        op.add_column('clients', sa.Column('state', sa.String(), nullable=True))


def downgrade() -> None:
    # Remove logo, city, and state columns from clients table (only if they exist)
    connection = op.get_bind()
    inspector = sa.inspect(connection)
    columns = [col['name'] for col in inspector.get_columns('clients')]
    
    if 'logo' in columns:
        op.drop_column('clients', 'logo')
    
    if 'city' in columns:
        op.drop_column('clients', 'city')
    
    if 'state' in columns:
        op.drop_column('clients', 'state')

