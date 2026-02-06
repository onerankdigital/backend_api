"""make user client fields optional

Revision ID: 014
Revises: 013
Create Date: 2026-01-21

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '014'
down_revision = '013'
branch_labels = None
depends_on = None


def upgrade():
    # Make client_id nullable in user_clients table
    op.alter_column('user_clients', 'client_id',
                    existing_type=sa.String(),
                    nullable=True)
    
    # Make role_id nullable in user_clients table
    op.alter_column('user_clients', 'role_id',
                    existing_type=sa.UUID(as_uuid=True),
                    nullable=True)


def downgrade():
    # Make client_id non-nullable again
    # Note: This will fail if there are NULL values, so handle with care
    op.execute("""
        UPDATE user_clients
        SET client_id = 'UNASSIGNED'
        WHERE client_id IS NULL
    """)
    op.alter_column('user_clients', 'client_id',
                    existing_type=sa.String(),
                    nullable=False)
    
    # Make role_id non-nullable again
    # Note: This will fail if there are NULL values, so handle with care
    op.execute("""
        UPDATE user_clients
        SET role_id = (SELECT id FROM roles LIMIT 1)
        WHERE role_id IS NULL
    """)
    op.alter_column('user_clients', 'role_id',
                    existing_type=sa.UUID(as_uuid=True),
                    nullable=False)

