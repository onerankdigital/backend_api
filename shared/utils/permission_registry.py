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
    Also auto-registers cross-client permission variants (e.g., /api/leads/all).

    Args:
        app: FastAPI application instance
        db: Database session
        Permission: Permission model class (must be provided to avoid table redefinition)
    """
    if Permission is None:
        logger.warning("Permission model not provided, skipping auto-registration")
        return

    registered_count = 0
    cross_client_routes = []  # Track routes that need /all variants

    # Scan all routes
    for route in app.routes:
        if hasattr(route, 'methods') and hasattr(route, 'path'):
            # Skip health checks and docs
            if route.path in ['/health', '/docs', '/openapi.json', '/redoc']:
                continue

            # Normalize path (standardize path parameters to {id})
            normalized_path = route.path
            import re
            # Only normalize if the path already contains path parameters
            # Replace specific parameter names like {user_id}, {lead_id} with {id}
            if '{' in normalized_path:
                normalized_path = re.sub(r'\{[^}]+\}', '{id}', normalized_path)

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

                # Track GET endpoints for cross-client variants
                if method.upper() == 'GET' and normalized_path.startswith('/api/'):
                    # Only for top-level list endpoints without any path parameters
                    # Example: /api/leads, /api/transactions, /api/clients
                    # Exclude: /api/leads/{id}, /api/clients/{id}/products
                    if '{' not in normalized_path:
                        cross_client_routes.append((method.upper(), normalized_path))

    # Auto-register cross-client permission variants (e.g., /api/leads/all)
    for method, path in cross_client_routes:
        cross_client_path = f"{path}/all"
        route_key = f"{method}:{cross_client_path}"

        if route_key in _registered_routes:
            continue

        _registered_routes.add(route_key)

        # Check if cross-client permission already exists
        result = await db.execute(
            select(Permission).where(
                and_(
                    Permission.method == method,
                    Permission.path == cross_client_path
                )
            )
        )
        existing = result.scalar_one_or_none()

        if not existing:
            # Extract resource name from path (e.g., /api/leads -> leads)
            resource_name = path.split('/')[-1]

            # Create cross-client permission
            new_permission = Permission(
                method=method,
                path=cross_client_path,
                description=f"View all {resource_name} across all clients"
            )
            db.add(new_permission)
            registered_count += 1
            logger.info(f"Auto-registered cross-client permission: {method} {cross_client_path}")

    if registered_count > 0:
        await db.commit()
        logger.info(f"Auto-registered {registered_count} new permissions (including cross-client variants)")
    else:
        logger.info("All permissions already registered")


def register_permission(method: str, path: str, description: str = None):
    """Manually register a permission (for dynamic routes)"""
    route_key = f"{method.upper()}:{path}"
    _registered_routes.add(route_key)
    return route_key

