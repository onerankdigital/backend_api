"""add_image_columns_and_product_images_table

Revision ID: 005
Revises: 004
Create Date: 2026-01-16 14:30:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = '005'
down_revision = '004'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add image column to industries table if it doesn't exist
    connection = op.get_bind()
    inspector = sa.inspect(connection)
    
    industries_columns = [col['name'] for col in inspector.get_columns('industries')]
    if 'image' not in industries_columns:
        op.add_column('industries', sa.Column('image', sa.String(), nullable=True))
    
    # Add image column to product_categories table if it doesn't exist
    categories_columns = [col['name'] for col in inspector.get_columns('product_categories')]
    if 'image' not in categories_columns:
        op.add_column('product_categories', sa.Column('image', sa.String(), nullable=True))
    
    # Create product_images table
    op.create_table(
        'product_images',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('product_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('products.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('image_url', sa.String(), nullable=False),
        sa.Column('display_order', sa.Integer(), nullable=False, default=0),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
    )
    
    # Create index on product_id and display_order for faster queries
    op.create_index('idx_product_images_product_order', 'product_images', ['product_id', 'display_order'])


def downgrade() -> None:
    # Drop product_images table
    op.drop_index('idx_product_images_product_order', table_name='product_images')
    op.drop_table('product_images')
    
    # Remove image columns
    connection = op.get_bind()
    inspector = sa.inspect(connection)
    
    categories_columns = [col['name'] for col in inspector.get_columns('product_categories')]
    if 'image' in categories_columns:
        op.drop_column('product_categories', 'image')
    
    industries_columns = [col['name'] for col in inspector.get_columns('industries')]
    if 'image' in industries_columns:
        op.drop_column('industries', 'image')


