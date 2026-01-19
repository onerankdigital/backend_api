"""Create admin user

Revision ID: 002
Revises: 001
Create Date: 2024-01-02 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy import text
import uuid
import bcrypt
import os

# revision identifiers, used by Alembic.
revision = '002'
down_revision = '001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Get admin credentials from environment or use defaults
    admin_email = os.getenv("ADMIN_EMAIL", "admin@example.com")
    admin_password = os.getenv("ADMIN_PASSWORD", "admin@123")
    
    # Hash the password
    salt = bcrypt.gensalt(rounds=12)
    password_hash = bcrypt.hashpw(admin_password.encode('utf-8'), salt).decode('utf-8')
    
    # Create admin user
    admin_id = str(uuid.uuid4())
    
    # Escape single quotes in password hash for SQL
    password_hash_escaped = password_hash.replace("'", "''")
    admin_email_escaped = admin_email.replace("'", "''")
    
    # Use op.execute for SQL execution
    op.execute(
        f"""
        INSERT INTO users (id, email, password_hash, is_admin, status, created_at, updated_at)
        VALUES (
            '{admin_id}'::uuid,
            '{admin_email_escaped}',
            '{password_hash_escaped}',
            'true',
            'active',
            NOW(),
            NOW()
        )
        ON CONFLICT (email) DO NOTHING
        """
    )


def downgrade() -> None:
    # Remove admin user (by email)
    admin_email = os.getenv("ADMIN_EMAIL", "admin@example.com")
    admin_email_escaped = admin_email.replace("'", "''")
    op.execute(
        f"DELETE FROM users WHERE email = '{admin_email_escaped}' AND is_admin = 'true'"
    )

