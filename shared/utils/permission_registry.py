"""
Permission Registry - Auto-register API endpoints as permissions
"""
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from typing import Dict, Set
import logging

logger = logging.getLogger(__name__)

# Global registry to track registered routes
_registered_routes: Set[str] = set()


async def auto_register_permissions(app: FastAPI, db: AsyncSession, Permission=None):
    """
    Auto-register all API endpoints as permissions on startup.
    This scans all routes and creates permission entries.
    
    Args:
        app: FastAPI application instance
        db: Database session
        Permission: Permission model class (must be provided to avoid table redefinition)
    """
    if Permission is None:
        logger.warning("Permission model not provided, skipping auto-registration")
        return
    
    registered_count = 0
    
    # Scan all routes
    for route in app.routes:
        if hasattr(route, 'methods') and hasattr(route, 'path'):
            # Skip health checks and docs
            if route.path in ['/health', '/docs', '/openapi.json', '/redoc']:
                continue
            
            # Normalize path (remove path parameters for matching)
            normalized_path = route.path
            # Replace UUID patterns with {id} for consistency
            import re
            normalized_path = re.sub(r'/[a-f0-9-]{36}', '/{id}', normalized_path)
            normalized_path = re.sub(r'/[^/]+$', '/{id}', normalized_path) if '{' not in normalized_path else normalized_path
            
            for method in route.methods:
                if method == 'HEAD':
                    continue
                
                route_key = f"{method.upper()}:{normalized_path}"
                
                if route_key in _registered_routes:
                    continue
                
                _registered_routes.add(route_key)
                
                # Check if permission already exists
                result = await db.execute(
                    select(Permission).where(
                        and_(
                            Permission.method == method.upper(),
                            Permission.path == normalized_path
                        )
                    )
                )
                existing = result.scalar_one_or_none()
                
                if not existing:
                    # Create permission
                    description = f"{method.upper()} {normalized_path}"
                    if hasattr(route, 'summary'):
                        description = route.summary or description
                    
                    new_permission = Permission(
                        method=method.upper(),
                        path=normalized_path,
                        description=description
                    )
                    db.add(new_permission)
                    registered_count += 1
                    logger.info(f"Auto-registered permission: {method.upper()} {normalized_path}")
    
    if registered_count > 0:
        await db.commit()
        logger.info(f"Auto-registered {registered_count} new permissions")
    else:
        logger.info("All permissions already registered")


def register_permission(method: str, path: str, description: str = None):
    """Manually register a permission (for dynamic routes)"""
    route_key = f"{method.upper()}:{path}"
    _registered_routes.add(route_key)
    return route_key

