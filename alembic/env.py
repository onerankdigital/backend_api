"""
Alembic environment configuration
"""
from logging.config import fileConfig
from sqlalchemy import engine_from_config
from sqlalchemy import pool
from alembic import context
import os
import sys

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

# Import all models
from shared.models.base import Base
from shared.database import DATABASE_URL

# Import all service models to ensure they're registered
# Note: In a true microservices setup, each service would have its own database
# For this implementation, we're using a shared database with separate schemas/tables

# This is the Alembic Config object
config = context.config

# Override sqlalchemy.url with environment variable if present
database_url = os.getenv("DATABASE_URL", DATABASE_URL)
# Convert asyncpg URL to psycopg2 URL for Alembic (synchronous)
sync_url = database_url.replace("+asyncpg", "")
# Replace localhost/127.0.0.1 with postgres if running in Docker
# This handles both the default URL and environment variable URL
if "@localhost" in sync_url or "@127.0.0.1" in sync_url:
    sync_url = sync_url.replace("@localhost", "@postgres").replace("@127.0.0.1", "@postgres")
config.set_main_option("sqlalchemy.url", sync_url)

# Interpret the config file for Python logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Add your model's MetaData object here
target_metadata = Base.metadata

def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

