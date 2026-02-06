"""add name to users

Revision ID: 013
Revises: 012
Create Date: 2026-01-21

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '013'
down_revision = '012'
branch_labels = None
depends_on = None


def upgrade():
    # Add name column to users table
    op.add_column('users', sa.Column('name', sa.String(), nullable=True))

    # Update existing users to have a default name (using email prefix)
    op.execute("""
        UPDATE users
        SET name = SPLIT_PART(email, '@', 1)
        WHERE name IS NULL
    """)

    # Make name column non-nullable after populating it
    op.alter_column('users', 'name', nullable=False)


def downgrade():
    # Remove name column from users table
    op.drop_column('users', 'name')
