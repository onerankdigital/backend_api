"""add_payment_method_created_by_rejection_reason_to_transactions

Revision ID: 012
Revises: 011
Create Date: 2025-01-16 20:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = '012'
down_revision = '011'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add payment_method column to transactions table
    op.add_column('transactions', sa.Column('payment_method', sa.String(), nullable=True))
    
    # Add created_by_user_id column to transactions table
    op.add_column('transactions', sa.Column('created_by_user_id', postgresql.UUID(as_uuid=True), nullable=True))
    op.create_foreign_key(
        'transactions_created_by_user_id_fkey',
        'transactions',
        'users',
        ['created_by_user_id'],
        ['id']
    )
    
    # Add rejection_reason column to transactions table
    op.add_column('transactions', sa.Column('rejection_reason', sa.String(), nullable=True))


def downgrade() -> None:
    # Remove rejection_reason column
    op.drop_column('transactions', 'rejection_reason')
    
    # Remove created_by_user_id column and its foreign key
    op.drop_constraint('transactions_created_by_user_id_fkey', 'transactions', type_='foreignkey')
    op.drop_column('transactions', 'created_by_user_id')
    
    # Remove payment_method column
    op.drop_column('transactions', 'payment_method')

