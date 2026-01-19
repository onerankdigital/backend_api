"""Initial schema

Revision ID: 001
Revises: 
Create Date: 2024-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Users table (global)
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('email', sa.String(), nullable=False, unique=True, index=True),
        sa.Column('password_hash', sa.String(), nullable=False),
        sa.Column('is_admin', sa.String(), nullable=False, default='false'),
        sa.Column('status', sa.String(), nullable=False, default='active'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
    )
    
    # Clients table
    op.create_table(
        'clients',
        sa.Column('client_id', sa.String(), primary_key=True, unique=True, nullable=False, index=True),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('status', sa.String(), nullable=False, default='active'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
    )
    
    # Roles table
    op.create_table(
        'roles',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('name', sa.String(), nullable=False, unique=True, index=True),
        sa.Column('level', sa.String(), nullable=False),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('status', sa.String(), nullable=False, default='active'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
    )
    
    # User-Clients junction table
    op.create_table(
        'user_clients',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False, index=True),
        sa.Column('client_id', sa.String(), sa.ForeignKey('clients.client_id'), nullable=False, index=True),
        sa.Column('role_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('roles.id'), nullable=False),
        sa.Column('reports_to_user_client_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('user_clients.id'), nullable=True),
        sa.Column('status', sa.String(), nullable=False, default='active'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
    )
    
    # Permissions table
    op.create_table(
        'permissions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('method', sa.String(), nullable=False),
        sa.Column('path', sa.String(), nullable=False, index=True),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
    )
    
    # Role-Permissions junction table
    op.create_table(
        'role_permissions',
        sa.Column('role_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('roles.id'), primary_key=True),
        sa.Column('permission_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('permissions.id'), primary_key=True),
    )
    
    # User-Client Hierarchy (closure table)
    op.create_table(
        'user_client_hierarchy',
        sa.Column('ancestor_user_client_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('user_clients.id'), primary_key=True),
        sa.Column('descendant_user_client_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('user_clients.id'), primary_key=True),
        sa.Column('depth', sa.String(), nullable=False),
    )
    
    # Industries table
    op.create_table(
        'industries',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('name', sa.String(), nullable=False, unique=True, index=True),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('status', sa.String(), nullable=False, default='active'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
    )
    
    # Product Categories table
    op.create_table(
        'product_categories',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('industry_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('industries.id'), nullable=False, index=True),
        sa.Column('name', sa.String(), nullable=False, index=True),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('status', sa.String(), nullable=False, default='active'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
    )
    
    # Products table
    op.create_table(
        'products',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('category_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('product_categories.id'), nullable=False, index=True),
        sa.Column('name', sa.String(), nullable=False, index=True),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('status', sa.String(), nullable=False, default='active'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
    )
    
    # Client-Products junction table
    op.create_table(
        'client_products',
        sa.Column('client_id', sa.String(), sa.ForeignKey('clients.client_id'), primary_key=True),
        sa.Column('product_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('products.id'), primary_key=True),
        sa.Column('enabled', sa.String(), nullable=False, default='true'),
        sa.Column('attached_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    
    # Leads table
    op.create_table(
        'leads',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('client_id', sa.String(), sa.ForeignKey('clients.client_id'), nullable=False, index=True),
        sa.Column('created_by_user_client_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('user_clients.id'), nullable=True),
        sa.Column('name', sa.String(), nullable=True),
        sa.Column('email', sa.String(), nullable=True, index=True),
        sa.Column('phone', sa.String(), nullable=True, index=True),
        sa.Column('source', sa.String(), nullable=False, index=True),
        sa.Column('lead_reference_id', sa.String(), nullable=True, index=True),
        sa.Column('raw_payload', postgresql.JSONB(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
    )
    
    # Client API Keys table
    op.create_table(
        'client_api_keys',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('client_id', sa.String(), sa.ForeignKey('clients.client_id'), nullable=False, index=True),
        sa.Column('key_hash', sa.String(), nullable=False, unique=True, index=True),
        sa.Column('key_prefix', sa.String(), nullable=False, index=True),
        sa.Column('scopes', postgresql.JSONB(), nullable=True),
        sa.Column('status', sa.String(), nullable=False, default='active'),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
    )
    
    # Client Integrations table
    op.create_table(
        'client_integrations',
        sa.Column('client_id', sa.String(), sa.ForeignKey('clients.client_id'), primary_key=True),
        sa.Column('whatsapp_enabled', sa.String(), nullable=False, default='false'),
        sa.Column('google_sheets_enabled', sa.String(), nullable=False, default='false'),
        sa.Column('google_sheet_id', sa.String(), nullable=True),
        sa.Column('meta_page_id', sa.String(), nullable=True),
        sa.Column('meta_form_id', sa.String(), nullable=True),
        sa.Column('config', postgresql.JSONB(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table('client_integrations')
    op.drop_table('client_api_keys')
    op.drop_table('leads')
    op.drop_table('client_products')
    op.drop_table('products')
    op.drop_table('product_categories')
    op.drop_table('industries')
    op.drop_table('user_client_hierarchy')
    op.drop_table('role_permissions')
    op.drop_table('permissions')
    op.drop_table('user_clients')
    op.drop_table('roles')
    op.drop_table('clients')
    op.drop_table('users')

