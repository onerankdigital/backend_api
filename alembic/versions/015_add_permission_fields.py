"""add permission fields

Revision ID: 015
Revises: 014
Create Date: 2026-01-22

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '015'
down_revision = '014'
branch_labels = None
depends_on = None


def upgrade():
    # Add module field to permissions table
    op.add_column('permissions', 
                  sa.Column('module', sa.String(50), nullable=True))
    
    # Add action_type field to permissions table
    op.add_column('permissions',
                  sa.Column('action_type', sa.String(20), nullable=True))
    
    # Add is_cross_client field to permissions table
    op.add_column('permissions',
                  sa.Column('is_cross_client', sa.Boolean(), nullable=False, server_default='false'))
    
    # Create indexes for better query performance
    op.create_index('idx_permissions_module', 'permissions', ['module'])
    op.create_index('idx_permissions_action_type', 'permissions', ['action_type'])
    op.create_index('idx_permissions_cross_client', 'permissions', ['is_cross_client'])


def downgrade():
    # Drop indexes
    op.drop_index('idx_permissions_cross_client', 'permissions')
    op.drop_index('idx_permissions_action_type', 'permissions')
    op.drop_index('idx_permissions_module', 'permissions')
    
    # Drop columns
    op.drop_column('permissions', 'is_cross_client')
    op.drop_column('permissions', 'action_type')
    op.drop_column('permissions', 'module')

