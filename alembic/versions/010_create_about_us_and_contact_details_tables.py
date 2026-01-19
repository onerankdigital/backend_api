"""create_about_us_and_contact_details_tables

Revision ID: 010
Revises: 009
Create Date: 2026-01-16 19:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = '010'
down_revision = '009'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create about_us table (simplified: only title, subtitle, description)
    op.create_table(
        'about_us',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('title', sa.String(), nullable=True),
        sa.Column('subtitle', sa.String(), nullable=True),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('status', sa.String(), nullable=False, server_default='active'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
    )
    
    # Create contact_details table (email, phone, website, social_media as arrays)
    op.create_table(
        'contact_details',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('company_name', sa.String(), nullable=True),
        sa.Column('email', postgresql.ARRAY(sa.String()), nullable=True),  # Array of emails
        sa.Column('phone', postgresql.ARRAY(sa.String()), nullable=True),  # Array of phones
        sa.Column('address', sa.String(), nullable=True),
        sa.Column('website', postgresql.ARRAY(sa.String()), nullable=True),  # Array of websites
        sa.Column('social_media', postgresql.JSONB(), nullable=True),  # JSON object with multiple social media links
        sa.Column('status', sa.String(), nullable=False, server_default='active'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table('contact_details')
    op.drop_table('about_us')

