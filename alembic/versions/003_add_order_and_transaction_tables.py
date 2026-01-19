"""Add order and transaction tables

Revision ID: 003
Revises: 002
Create Date: 2024-01-15 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '003'
down_revision = '002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Alter clients table to add order-related fields
    op.add_column('clients', sa.Column('company_name', sa.String(), nullable=True))
    op.add_column('clients', sa.Column('contact_person', sa.String(), nullable=True))
    op.add_column('clients', sa.Column('designation', sa.String(), nullable=True))
    op.add_column('clients', sa.Column('address', sa.String(), nullable=True))
    op.add_column('clients', sa.Column('phone', sa.String(), nullable=True))
    op.add_column('clients', sa.Column('email', sa.String(), nullable=True))
    op.add_column('clients', sa.Column('domain_name', sa.String(), nullable=True))
    op.add_column('clients', sa.Column('gst_no', sa.String(), nullable=True))
    op.add_column('clients', sa.Column('package_amount', sa.Numeric(precision=12, scale=2), nullable=True))
    op.add_column('clients', sa.Column('gst_amount', sa.Numeric(precision=12, scale=2), nullable=True))
    op.add_column('clients', sa.Column('total_amount', sa.Numeric(precision=12, scale=2), nullable=True))
    op.add_column('clients', sa.Column('customer_no', sa.String(), nullable=True))
    op.add_column('clients', sa.Column('order_date', sa.Date(), nullable=True))
    op.add_column('clients', sa.Column('order_data', postgresql.JSONB(), nullable=True))  # Store all special instructions, guidelines, SEO, Adwords data
    
    # Create services table
    op.create_table(
        'services',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('name', sa.String(), nullable=False, unique=True, index=True),
        sa.Column('code', sa.String(), nullable=True, unique=True, index=True),  # e.g., 'domain-hosting', 'seo'
        sa.Column('category', sa.String(), nullable=True),  # e.g., 'Domain & Hosting', 'Web Design', 'SEO'
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('status', sa.String(), nullable=False, default='active'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
    )
    
    # Create client_services junction table
    op.create_table(
        'client_services',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('client_id', sa.String(), sa.ForeignKey('clients.client_id'), nullable=False, index=True),
        sa.Column('service_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('services.id'), nullable=False, index=True),
        sa.Column('quantity', sa.Integer(), nullable=True),  # For services like POP ID, G Suite ID
        sa.Column('status', sa.String(), nullable=False, default='active'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
        sa.UniqueConstraint('client_id', 'service_id', name='uq_client_service'),
    )
    
    # Create transactions table
    op.create_table(
        'transactions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('client_id', sa.String(), sa.ForeignKey('clients.client_id'), nullable=False, index=True),
        sa.Column('transaction_id', sa.String(), nullable=False, unique=True, index=True),  # Manually entered transaction ID
        sa.Column('amount', sa.Numeric(precision=12, scale=2), nullable=False),
        sa.Column('status', sa.String(), nullable=False, default='pending'),  # pending, verified, rejected
        sa.Column('verified_by_user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('notes', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
    )
    
    # Create index on client_id and status for faster queries
    op.create_index('idx_transactions_client_status', 'transactions', ['client_id', 'status'])


def downgrade() -> None:
    op.drop_index('idx_transactions_client_status', table_name='transactions')
    op.drop_table('transactions')
    op.drop_table('client_services')
    op.drop_table('services')
    
    # Remove columns from clients table
    op.drop_column('clients', 'order_data')
    op.drop_column('clients', 'order_date')
    op.drop_column('clients', 'customer_no')
    op.drop_column('clients', 'total_amount')
    op.drop_column('clients', 'gst_amount')
    op.drop_column('clients', 'package_amount')
    op.drop_column('clients', 'gst_no')
    op.drop_column('clients', 'domain_name')
    op.drop_column('clients', 'email')
    op.drop_column('clients', 'phone')
    op.drop_column('clients', 'address')
    op.drop_column('clients', 'designation')
    op.drop_column('clients', 'contact_person')
    op.drop_column('clients', 'company_name')

