"""
Backfill script to populate module, action_type, and is_cross_client fields
for existing permissions in the database.

Run this after migration 015 is applied.
"""
import sys
import os
import asyncio

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select, update
from shared.database import Base
from services.permission_service.main import Permission
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database URL - update this to match your database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://user:password@localhost/dbname")

# Module mapping based on path prefixes
MODULE_MAP = {
    '/api/auth': 'Auth',
    '/api/clients': 'Clients',
    '/api/transactions': 'Transactions',
    '/api/leads': 'Leads',
    '/api/products': 'Products',
    '/api/roles': 'Roles',
    '/api/permissions': 'Permissions',
    '/api/user-clients': 'User Clients',
    '/api/hierarchy': 'Hierarchy',
    '/api/api-keys': 'API Keys',
    '/api/about-us': 'Content',
    '/api/industries': 'Industries',
    '/api/product-categories': 'Categories',
    '/webhook': 'Webhooks',
}

# Method to action type mapping
ACTION_MAP = {
    'GET': 'read',
    'POST': 'create',
    'PUT': 'update',
    'PATCH': 'update',
    'DELETE': 'delete',
}

# Cross-client keywords
CROSS_CLIENT_KEYWORDS = [
    'cross-client', 'cross client', 'all clients', 'all enquiries',
    'all transactions', 'all leads', 'global access', 'admin access',
    'view all', 'access all'
]


def get_module_from_path(path: str) -> str:
    """Extract module name from permission path"""
    for prefix, module in MODULE_MAP.items():
        if path.startswith(prefix):
            return module
    return 'Other'


def get_action_type_from_method(method: str) -> str:
    """Get action type from HTTP method"""
    return ACTION_MAP.get(method.upper(), 'other')


def is_cross_client_permission(path: str, description: str) -> bool:
    """Check if permission is cross-client"""
    # Check path
    if path.endswith('/all'):
        return True
    
    # Check description
    desc_lower = (description or '').lower()
    for keyword in CROSS_CLIENT_KEYWORDS:
        if keyword in desc_lower:
            return True
    
    return False


async def backfill_permissions():
    """Backfill module, action_type, and is_cross_client fields"""
    engine = create_async_engine(DATABASE_URL, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    
    async with async_session() as session:
        try:
            # Get all permissions
            result = await session.execute(select(Permission))
            permissions = result.scalars().all()
            
            logger.info(f"Found {len(permissions)} permissions to update")
            
            updated_count = 0
            for perm in permissions:
                # Skip if already has module (already backfilled)
                if perm.module:
                    continue
                
                module = get_module_from_path(perm.path)
                action_type = get_action_type_from_method(perm.method)
                is_cross_client = is_cross_client_permission(perm.path, perm.description or '')
                
                # Update permission
                await session.execute(
                    update(Permission)
                    .where(Permission.id == perm.id)
                    .values(
                        module=module,
                        action_type=action_type,
                        is_cross_client=is_cross_client
                    )
                )
                updated_count += 1
                
                if updated_count % 10 == 0:
                    logger.info(f"Updated {updated_count} permissions...")
            
            await session.commit()
            logger.info(f"Successfully updated {updated_count} permissions")
            
        except Exception as e:
            await session.rollback()
            logger.error(f"Error during backfill: {e}", exc_info=True)
            raise
        finally:
            await engine.dispose()


if __name__ == "__main__":
    asyncio.run(backfill_permissions())

