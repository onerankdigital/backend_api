"""
API Gateway - Routing, authentication, and RBAC enforcement
"""
from fastapi import FastAPI, Request, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_
from typing import Optional, Dict, Any, List
import sys
import os
import httpx
import json
import logging
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from shared.database import get_db
from shared.models.base import BaseModel as BaseDBModel, BaseModelNoID
from shared.utils.security import decode_token
from shared.utils.http_client import ServiceClient
from shared.utils.rate_limit import rate_limiter
from shared.utils.permission_registry import auto_register_permissions
from shared.utils.captcha import generate_captcha_text, create_captcha, hash_captcha_text
from sqlalchemy import Column, String, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
import uuid

app = FastAPI(title="Lead Automation Platform API Gateway", version="1.0.0")

# Logging - Must be defined before use
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# CORS - Must be added before other middleware
# Note: allow_credentials=True cannot be used with allow_origins=["*"]
# For development, we allow all origins without credentials
# For production, specify exact origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure in production to specific origins
    allow_credentials=False,  # Set to True in production with specific origins
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# Global exception handler to ensure CORS headers are always present
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler to ensure CORS headers are always present"""
    # Safely log exception without serializing UploadFile objects
    exc_type = type(exc).__name__
    exc_msg = str(exc)
    # Filter out UploadFile references to avoid serialization errors
    if "UploadFile" in exc_msg or "not JSON serializable" in exc_msg:
        exc_msg = "Error processing request with file upload"
    
    logger.error(f"Unhandled exception: {exc_type}: {exc_msg}")
    # Use exc_info=False to avoid serializing exception context which may contain UploadFile objects
    import traceback
    try:
        tb_str = ''.join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        # Filter out lines containing UploadFile to avoid serialization
        tb_lines = [line for line in tb_str.split('\n') if 'UploadFile' not in line]
        logger.error(f"Traceback (filtered):\n{''.join(tb_lines)}")
    except Exception:
        # If traceback formatting fails, just log the exception type
        logger.error(f"Exception type: {exc_type}")
    
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "error": exc_msg, "type": exc_type},
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
            "Access-Control-Allow-Headers": "*",
        }
    )

# Startup event - Auto-register permissions
@app.on_event("startup")
async def startup_event():
    """Auto-register all API endpoints as permissions on startup"""
    try:
        async for db in get_db():
            try:
                await auto_register_permissions(app, db, Permission)
            except Exception as e:
                logger.error(f"Failed to auto-register permissions: {e}", exc_info=True)
            finally:
                break  # Only run once
    except Exception as e:
        logger.error(f"Startup error: {e}", exc_info=True)

# Service URLs - Use Docker service names when running in containers
# Docker Compose sets these via environment variables
AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL", "http://localhost:8001")
CLIENT_SERVICE_URL = os.getenv("CLIENT_SERVICE_URL", "http://localhost:8002")
USER_SERVICE_URL = os.getenv("USER_SERVICE_URL", "http://localhost:8003")
LEAD_SERVICE_URL = os.getenv("LEAD_SERVICE_URL", "http://localhost:8004")
PRODUCT_SERVICE_URL = os.getenv("PRODUCT_SERVICE_URL", "http://localhost:8005")
CONTENT_SERVICE_URL = os.getenv("CONTENT_SERVICE_URL", "http://localhost:8010")
INTEGRATION_SERVICE_URL = os.getenv("INTEGRATION_SERVICE_URL", "http://localhost:8006")
WEBHOOK_SERVICE_URL = os.getenv("WEBHOOK_SERVICE_URL", "http://localhost:8007")
PERMISSION_SERVICE_URL = os.getenv("PERMISSION_SERVICE_URL", "http://localhost:8008")
HIERARCHY_SERVICE_URL = os.getenv("HIERARCHY_SERVICE_URL", "http://localhost:8009")

# Log service URLs on startup for debugging
logger.info(f"Service URLs configured:")
logger.info(f"  AUTH_SERVICE_URL: {AUTH_SERVICE_URL}")
logger.info(f"  CLIENT_SERVICE_URL: {CLIENT_SERVICE_URL}")
logger.info(f"  USER_SERVICE_URL: {USER_SERVICE_URL}")
logger.info(f"  LEAD_SERVICE_URL: {LEAD_SERVICE_URL}")

# Service clients
auth_client = ServiceClient(AUTH_SERVICE_URL)
client_client = ServiceClient(CLIENT_SERVICE_URL)
user_client = ServiceClient(USER_SERVICE_URL)
lead_client = ServiceClient(LEAD_SERVICE_URL)
product_client = ServiceClient(PRODUCT_SERVICE_URL)
content_client = ServiceClient(CONTENT_SERVICE_URL)
integration_client = ServiceClient(INTEGRATION_SERVICE_URL)
webhook_client = ServiceClient(WEBHOOK_SERVICE_URL)
permission_client = ServiceClient(PERMISSION_SERVICE_URL)
hierarchy_client = ServiceClient(HIERARCHY_SERVICE_URL)

security = HTTPBearer()


# Database Models (for permission checking)
class User(BaseDBModel):
    __tablename__ = "users"
    
    email = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    is_admin = Column(String, default="false", nullable=False)
    status = Column(String, default="active", nullable=False)


class UserClient(BaseDBModel):
    __tablename__ = "user_clients"
    
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    client_id = Column(String, ForeignKey("clients.client_id"), nullable=False, index=True)
    role_id = Column(UUID(as_uuid=True), ForeignKey("roles.id"), nullable=False)
    reports_to_user_client_id = Column(UUID(as_uuid=True), ForeignKey("user_clients.id"), nullable=True)
    status = Column(String, default="active", nullable=False)


class Permission(BaseDBModel):
    __tablename__ = "permissions"
    
    method = Column(String, nullable=False)
    path = Column(String, nullable=False, index=True)
    description = Column(String, nullable=True)


class RolePermission(BaseDBModel):
    __tablename__ = "role_permissions"
    
    role_id = Column(UUID(as_uuid=True), ForeignKey("roles.id"), nullable=False, primary_key=True)
    permission_id = Column(UUID(as_uuid=True), ForeignKey("permissions.id"), nullable=False, primary_key=True)


class UserClientHierarchy(BaseDBModel):
    __tablename__ = "user_client_hierarchy"
    
    ancestor_user_client_id = Column(UUID(as_uuid=True), ForeignKey("user_clients.id"), nullable=False, primary_key=True)
    descendant_user_client_id = Column(UUID(as_uuid=True), ForeignKey("user_clients.id"), nullable=False, primary_key=True)
    depth = Column(String, nullable=False)


# Dependencies
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Get current user from JWT token"""
    token = credentials.credentials
    try:
        payload = decode_token(token)
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        return payload
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))


async def has_cross_client_permission(
    user_id: str,
    method: str,
    endpoint_path: str,
    db: AsyncSession
) -> bool:
    """
    Check if user has a permission that grants cross-client access for any endpoint.
    
    Checks for:
    1. Special permission path pattern: /api/{resource}/all (e.g., /api/leads/all, /api/transactions/all)
    2. Permission description contains cross-client keywords (e.g., "cross-client", "all clients", "all enquiries")
    
    This allows granting admin-like access to specific endpoints without being a full admin.
    """
    # Get all user's active user_clients
    query = select(UserClient).where(
        and_(
            UserClient.user_id == uuid.UUID(user_id),
            UserClient.status == "active"
        )
    )
    result = await db.execute(query)
    user_clients = result.scalars().all()
    
    if not user_clients:
        return False
    
    # Normalize endpoint path (remove trailing slash, handle {id} patterns)
    normalized_endpoint = endpoint_path.rstrip('/')
    # Convert /api/leads/{id} to /api/leads for matching
    import re
    normalized_endpoint = re.sub(r'/\{[^}]+\}$', '', normalized_endpoint)
    
    # Build cross-client permission path pattern
    # /api/leads -> /api/leads/all
    # /api/transactions -> /api/transactions/all
    cross_client_path = f"{normalized_endpoint}/all"
    
    # Cross-client keywords to check in permission description
    cross_client_keywords = [
        "cross-client", "cross client", "all clients", "all enquiries", 
        "all transactions", "all leads", "global access", "admin access",
        "view all", "access all"
    ]
    
    # Check if any of the user's roles have cross-client permission
    for uc in user_clients:
        # Get all permissions for this role with matching method
        result = await db.execute(
            select(Permission)
            .join(RolePermission, Permission.id == RolePermission.permission_id)
            .where(
                and_(
                    RolePermission.role_id == uc.role_id,
                    Permission.method == method.upper()
                )
            )
        )
        permissions = result.scalars().all()
        
        for permission in permissions:
            # Check for special cross-client path pattern
            if permission.path == cross_client_path:
                logger.info(f"User {user_id} has cross-client permission via path pattern: {permission.path}")
                return True
            
            # Check if permission path matches endpoint and description contains cross-client keywords
            if permission.path == normalized_endpoint and permission.description:
                description_lower = permission.description.lower()
                if any(keyword in description_lower for keyword in cross_client_keywords):
                    logger.info(f"User {user_id} has cross-client permission via description: {permission.path} - {permission.description}")
                    return True
    
    return False


async def check_access_decision(
    method: str,
    path: str,
    user_id: str,
    client_id: Optional[str],
    target_client_id: Optional[str] = None,
    target_user_client_id: Optional[str] = None,
    db: AsyncSession = None
) -> bool:
    """
    Complete Access Decision Logic - A request is allowed ONLY IF:
    1. User has active user_clients entry for client
    2. Role has permission for API
    3. Target record belongs to same client (if applicable)
    4. Target user is in hierarchy subtree (if accessing user data)
    
    Admin bypasses all checks.
    """
    if not db:
        return False
    
    # Get user
    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user = result.scalar_one_or_none()
    
    if not user or user.status != "active":
        return False
    
    # Admin bypass
    if user.is_admin == "true":
        return True
    
    # Condition 1: User has active user_clients entry for client
    if not client_id:
        return False
    
    query = select(UserClient).where(
        and_(
            UserClient.user_id == uuid.UUID(user_id),
            UserClient.client_id == client_id,
            UserClient.status == "active"
        )
    )
    result = await db.execute(query)
    user_clients = result.scalars().all()
    
    if not user_clients:
        return False
    
    # Condition 2: Role has permission for API
    has_permission = False
    requester_user_client_id = None
    
    for uc in user_clients:
        requester_user_client_id = str(uc.id)
        # Get permissions for this role
        result = await db.execute(
            select(Permission)
            .join(RolePermission, Permission.id == RolePermission.permission_id)
            .where(
                and_(
                    RolePermission.role_id == uc.role_id,
                    Permission.method == method.upper(),
                    Permission.path == path
                )
            )
        )
        permission = result.scalar_one_or_none()
        if permission:
            has_permission = True
            break
    
    if not has_permission:
        return False
    
    # Condition 3: Target record belongs to same client (if applicable)
    if target_client_id and target_client_id != client_id:
        return False
    
    # Condition 4: Target user is in hierarchy subtree (if accessing user data)
    if target_user_client_id and requester_user_client_id:
        try:
            # Check hierarchy access via hierarchy service
            can_access = await hierarchy_client.post(
                "/hierarchy/check-access",
                json={
                    "requester_user_client_id": requester_user_client_id,
                    "target_user_client_id": target_user_client_id
                }
            )
            if not can_access.get("can_access", False):
                return False
        except Exception as e:
            logger.error(f"Hierarchy check failed: {e}")
            # Fallback: check directly in database
            result = await db.execute(
                select(UserClientHierarchy).where(
                    and_(
                        UserClientHierarchy.ancestor_user_client_id == uuid.UUID(requester_user_client_id),
                        UserClientHierarchy.descendant_user_client_id == uuid.UUID(target_user_client_id)
                    )
                )
            )
            if not result.scalar_one_or_none():
                return False
    
    return True


# Keep old function for backward compatibility
async def check_permission(
    method: str,
    path: str,
    user_id: str,
    client_id: Optional[str],
    db: AsyncSession
) -> bool:
    """Legacy function - use check_access_decision for complete logic"""
    return await check_access_decision(method, path, user_id, client_id, None, None, db)


# Rate limiting configuration
RATE_LIMIT_PER_IP = int(os.getenv("RATE_LIMIT_PER_IP", "100"))  # requests per window
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))  # seconds
RATE_LIMIT_PER_API_KEY = int(os.getenv("RATE_LIMIT_PER_API_KEY", "50"))  # requests per window


# Middleware for rate limiting
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Rate limiting middleware"""
    # Skip rate limiting for health checks and docs
    public_paths = ["/health", "/docs", "/openapi.json"]
    if any(request.url.path.startswith(path) for path in public_paths):
        return await call_next(request)
    
    # Get client IP
    client_ip = request.client.host if request.client else "unknown"
    # Check X-Forwarded-For header (for proxies)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        client_ip = forwarded_for.split(",")[0].strip()
    
    # IP-based rate limiting
    ip_key = f"ip:{client_ip}"
    is_allowed, rate_info = rate_limiter.is_allowed(
        ip_key,
        limit=RATE_LIMIT_PER_IP,
        window_seconds=RATE_LIMIT_WINDOW
    )
    
    if not is_allowed:
        return JSONResponse(
            status_code=429,
            content={
                "detail": "Rate limit exceeded",
                "error": "too_many_requests",
                "reset_at": rate_info.get("reset_at"),
                "limit": rate_info.get("limit"),
                "window_seconds": rate_info.get("window_seconds")
            },
            headers={
                "X-RateLimit-Limit": str(rate_info.get("limit")),
                "X-RateLimit-Remaining": str(rate_info.get("remaining")),
                "X-RateLimit-Reset": str(rate_info.get("reset_at")),
                "Retry-After": str(rate_info.get("reset_at") - int(time.time()))
            }
        )
    
    # API key-based rate limiting (for lead ingestion)
    if request.url.path == "/api/leads/ingest" and request.method == "POST":
        api_key = request.headers.get("X-API-Key")
        if api_key:
            api_key_key = f"api_key:{api_key}"
            is_allowed, rate_info = rate_limiter.is_allowed(
                api_key_key,
                limit=RATE_LIMIT_PER_API_KEY,
                window_seconds=RATE_LIMIT_WINDOW
            )
            
            if not is_allowed:
                return JSONResponse(
                    status_code=429,
                    content={
                        "detail": "API key rate limit exceeded",
                        "error": "too_many_requests",
                        "reset_at": rate_info.get("reset_at")
                    },
                    headers={
                        "X-RateLimit-Limit": str(rate_info.get("limit")),
                        "X-RateLimit-Remaining": str(rate_info.get("remaining")),
                        "X-RateLimit-Reset": str(rate_info.get("reset_at")),
                        "Retry-After": str(rate_info.get("reset_at") - int(time.time()))
                    }
                )
    
    response = await call_next(request)
    
    # Add rate limit headers to response
    if "X-RateLimit-Limit" not in response.headers:
        response.headers["X-RateLimit-Limit"] = str(rate_info.get("limit", RATE_LIMIT_PER_IP))
        response.headers["X-RateLimit-Remaining"] = str(rate_info.get("remaining", 0))
        response.headers["X-RateLimit-Reset"] = str(rate_info.get("reset_at", 0))
    
    return response


# Middleware for permission checking
@app.middleware("http")
async def permission_middleware(request: Request, call_next):
    """Check permissions for authenticated requests"""
    # Allow OPTIONS requests (CORS preflight) to pass through
    if request.method == "OPTIONS":
        return await call_next(request)
    
    # Skip permission check for public endpoints
    # All ordpanel (order portal) endpoints should be public for frontend access
    # Use exact matching or more specific path checks to avoid matching wrong paths
    # Auth endpoints that should ALWAYS be public (used to GET authentication)
    always_public_auth_paths = [
        "/api/auth/login",
        "/api/auth/register",
    ]
    
    public_exact_paths = [
        "/health", "/docs", "/openapi.json", 
        "/api/auth/me",  # Get current user - can work with or without token
        "/api/security/captcha", "/api/security/csrf", "/api/security/token",
        "/api/clients/premium",  # Premium clients for display
        "/api/about-us",  # About Us content for ordpanel
        "/api/contact-details",  # Contact details for ordpanel
        "/api/search",  # Search suggestions
        "/api/industries/home",  # Industries home page for ordpanel
        "/api/industries/top",  # Top industries for ordpanel
    ]
    
    # Paths that should only be public for GET requests (ordpanel frontend)
    public_get_paths = [
        "/api/industries",  # List all industries
        "/api/product-categories",  # List product categories
        "/api/products",  # List products
        "/api/product-images",  # List product images
        "/api/clients",  # List clients (public for ordpanel sitemap, but admin-only for POST/PUT/DELETE)
        "/static/images",  # Static image files
    ]
    
    # Paths that start with these should be public only for GET (ordpanel detail pages)
    # Note: These must have additional path segments (e.g., /api/clients/ORD_PANEL not /api/clients)
    public_get_prefixes = [
        "/api/products/",  # Product detail pages (e.g., /api/products/{id})
        "/api/clients/",  # Client detail endpoint for ordpanel (e.g., /api/clients/{id} or /api/clients/{id}/products)
        "/api/industries/",  # Industry detail pages (e.g., /api/industries/{id})
    ]
    
    # Check authentication header - public endpoints are only public when NO auth header is present
    # This allows ordpanel/website to access public endpoints without auth,
    # but requires frontend-ui (admin dashboard) to authenticate even for "public" endpoints
    auth_header = request.headers.get("Authorization")
    
    # Auth endpoints (login, register) should ALWAYS be public - they're used to GET authentication
    # These endpoints cannot require authentication
    always_public_paths = [
        "/api/auth/login",
        "/api/auth/register",
        "/api/auth/me",  # Used to check current user, should work with or without token
    ]
    
    if request.url.path in always_public_paths:
        logger.debug(f"Skipping permission check for always-public auth path: {request.url.path}")
        return await call_next(request)
    
    # Check exact matches - only public if no auth header
    if request.url.path in public_exact_paths:
        if not auth_header:
            logger.debug(f"Skipping permission check for exact public path (no auth): {request.url.path}")
            return await call_next(request)
        # If auth header exists, continue to permission check below
    
    # Check public GET paths - only allow GET method and exact match or sub-path
    # Only public if no auth header (ordpanel/website), otherwise require auth (frontend-ui)
    if request.method == "GET" and any(request.url.path == path or request.url.path.startswith(path + "/") for path in public_get_paths):
        if not auth_header:
            logger.debug(f"Skipping permission check for public GET path (no auth): {request.url.path}")
            return await call_next(request)
        # If auth header exists, continue to permission check below
    
    # Check public GET prefixes - only allow GET method and must have additional path segments
    # Only public if no auth header (ordpanel/website), otherwise require auth (frontend-ui)
    if request.method == "GET" and any(request.url.path.startswith(prefix) and len(request.url.path) > len(prefix) for prefix in public_get_prefixes):
        if not auth_header:
            logger.debug(f"Skipping permission check for public GET prefix path (no auth): {request.url.path}")
            return await call_next(request)
        # If auth header exists, continue to permission check below
    
    # Skip for webhook endpoints (all methods)
    if request.url.path.startswith("/webhook"):
        return await call_next(request)
    
    # Log that we're checking permissions for this path
    logger.info(f"Checking permissions for path: {request.url.path}, method: {request.method}")
    
    # Skip for webhook endpoints
    if request.url.path.startswith("/webhook"):
        return await call_next(request)
    
    # Allow /api/auth/me/permissions to bypass permission check
    # This endpoint is needed to determine user permissions
    if request.url.path == "/api/auth/me/permissions":
        return await call_next(request)
    
    # Allow self-service password changes (users changing their own password)
    # The auth service endpoint will validate that users can only change their own password
    # Admins can change any password (checked in auth service)
    if request.url.path.startswith("/api/auth/users/") and request.url.path.endswith("/change-password") and request.method == "POST":
        return await call_next(request)
    
    # Check authentication (auth_header already checked above for public endpoints)
    if not auth_header:
        # Allow API key authentication for lead ingestion
        if request.url.path == "/api/leads/ingest" and request.method == "POST":
            return await call_next(request)
        # Allow public access for ordpanel lead submission (public endpoint)
        if request.url.path == "/api/leads/ordpanel" and request.method == "POST":
            return await call_next(request)
        return JSONResponse(
            status_code=401,
            content={"detail": "Authentication required"}
        )
    
    # Extract token (only reached if auth_header exists)
    # Only catch token decoding errors here, not endpoint handler errors
    try:
        token = auth_header.replace("Bearer ", "")
        logger.info(f"Decoding token for path: {request.url.path}")
        payload = decode_token(token)
        logger.info(f"Token decoded successfully for path: {request.url.path}")
    except ValueError as e:
        # Token decoding failed - invalid token
        logger.error(f"Token decode error: {str(e)}", exc_info=True)
        return JSONResponse(
            status_code=401,
            content={"detail": f"Invalid token: {str(e)}"}
        )
    except Exception as e:
        # Other token-related errors
        logger.error(f"Token validation error: {str(e)}", exc_info=True)
        return JSONResponse(
            status_code=401,
            content={"detail": f"Authentication failed: {str(e)}"}
        )
    
    # Token decoded successfully - continue with permission checking
    try:
        user_id = payload.get("user_id")
        is_admin_value = payload.get("is_admin", False)
        
        # Log the raw JWT payload for debugging
        logger.info(f"JWT payload for user {user_id} on {request.method} {request.url.path}: is_admin={is_admin_value} (type: {type(is_admin_value)})")
        
        # Handle both boolean and string values for is_admin
        # JWT payload might have "true"/"false" as strings or boolean True/False
        # Also handle case where it might be the string "true" (not boolean)
        is_admin = False
        if isinstance(is_admin_value, bool):
            is_admin = is_admin_value == True
        elif isinstance(is_admin_value, str):
            # Handle string values: "true", "True", "TRUE", "1", "yes", etc.
            is_admin = str(is_admin_value).lower().strip() in ("true", "1", "yes", "on")
            logger.info(f"Admin check: is_admin_value is string '{is_admin_value}', converted to {is_admin}")
        else:
            # For any other type, try to convert to boolean
            is_admin = bool(is_admin_value)
            logger.info(f"Admin check: is_admin_value is {type(is_admin_value)} '{is_admin_value}', converted to {is_admin}")
        
        logger.info(f"Admin check result for user {user_id}: is_admin={is_admin} (original value: {is_admin_value}, type: {type(is_admin_value)})")
        
        # If JWT indicates admin, bypass immediately
        if is_admin:
            logger.info(f"Admin user {user_id} bypassing permission check for {request.method} {request.url.path}")
            request.state.user_id = user_id
            request.state.is_admin = True
            request.state.client_id = request.query_params.get("client_id")
            response = await call_next(request)
            return response
        
        # Get client_id from query params only (don't read body here as it can only be read once)
        client_id = request.query_params.get("client_id")
        
        # Normalize path for permission matching (same logic as permission_registry.py)
        # Convert path parameters to {id} format for matching
        # e.g., /api/clients/123e4567-e89b-12d3-a456-426614174000 -> /api/clients/{id}
        import re
        path = request.url.path
        normalized_path = path

        # Only normalize if the path contains actual ID values (UUIDs or numeric IDs)
        # Replace UUID patterns with {id}
        normalized_path = re.sub(r'/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', '/{id}', normalized_path)

        # Replace numeric IDs at the end (e.g., /api/clients/123 -> /api/clients/{id})
        # But NOT plain words like /api/leads or /api/clients
        # Only match if the last segment is purely numeric or looks like an ID
        if not normalized_path.endswith(('leads', 'clients', 'transactions', 'users', 'roles', 'permissions',
                                          'products', 'industries', 'about-us', 'contact-details', 'api-keys',
                                          'user-clients', 'endpoints', 'search', 'captcha', 'csrf', 'token')):
            # Replace last segment with {id} if it's numeric or UUID-like
            normalized_path = re.sub(r'/(\d+|[a-f0-9-]{36})$', '/{id}', normalized_path)
        method = request.method
        
        # Get database session for permission checking
        # Use async for to properly handle generator cleanup
        db_checked = False
        has_access = False
        
        async for db in get_db():
            # If JWT doesn't indicate admin, check database as fallback (in case token is stale)
            # This handles cases where user was made admin after token was issued
            if not is_admin:
                try:
                    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
                    user = result.scalar_one_or_none()
                    if user:
                        # Check both string and boolean values
                        user_is_admin = False
                        if isinstance(user.is_admin, bool):
                            user_is_admin = user.is_admin
                        elif isinstance(user.is_admin, str):
                            user_is_admin = user.is_admin.lower() in ("true", "1", "yes")
                        else:
                            user_is_admin = bool(user.is_admin)
                        
                        if user_is_admin:
                            is_admin = True
                            logger.info(f"User {user_id} is admin (verified from database: is_admin={user.is_admin}), bypassing permission check")
                except Exception as e:
                    logger.warning(f"Failed to check admin status from database: {e}", exc_info=True)
            
            # Admin bypass - admins have full access (check again after database lookup)
            if is_admin:
                logger.info(f"Admin user {user_id} bypassing permission check for {request.method} {request.url.path}")
                request.state.user_id = user_id
                request.state.is_admin = True
                request.state.client_id = client_id
                # For admin users, let the endpoint handler process the request
                # Don't catch exceptions from endpoint handlers - let FastAPI handle them
                response = await call_next(request)
                return response
            # Log permission check attempt
            logger.info(f"Permission check: user_id={user_id}, method={method}, path={path}, normalized_path={normalized_path}, client_id={client_id}")
            
            # For routes without client_id, check if user has permission via any of their roles
            # If client_id is provided, use the normal check_access_decision flow
            if not client_id:
                # Check permissions across all user's roles (any active user_client)
                query = select(UserClient).where(
                    and_(
                        UserClient.user_id == uuid.UUID(user_id),
                        UserClient.status == "active"
                    )
                )
                result = await db.execute(query)
                user_clients = result.scalars().all()
                
                logger.info(f"User {user_id} has {len(user_clients)} active user_clients")
                
                if not user_clients:
                    logger.warning(f"User {user_id} has no active user_clients - denying access to {method} {path}")
                    has_access = False
                else:
                    # Check if any of the user's roles have permission for this endpoint
                    has_access = False
                    for uc in user_clients:
                        logger.info(f"Checking role {uc.role_id} for permission {method} {normalized_path}")

                        # Check for exact match OR cross-client variant (/api/leads or /api/leads/all)
                        cross_client_path = f"{normalized_path}/all"

                        result = await db.execute(
                            select(Permission)
                            .join(RolePermission, Permission.id == RolePermission.permission_id)
                            .where(
                                and_(
                                    RolePermission.role_id == uc.role_id,
                                    Permission.method == method.upper(),
                                    or_(
                                        Permission.path == normalized_path,
                                        Permission.path == cross_client_path
                                    )
                                )
                            )
                        )
                        permission = result.scalar_one_or_none()
                        if permission:
                            logger.info(f"Permission found: {permission.method} {permission.path} for role {uc.role_id}")
                            has_access = True
                            break
                        else:
                            logger.warning(f"No permission {method} {normalized_path} or {cross_client_path} found for role {uc.role_id}")
                
                if not has_access:
                    # Log all permissions for this role for debugging
                    for uc in user_clients:
                        all_perms_result = await db.execute(
                            select(Permission)
                            .join(RolePermission, Permission.id == RolePermission.permission_id)
                            .where(RolePermission.role_id == uc.role_id)
                        )
                        all_perms = all_perms_result.scalars().all()
                        if all_perms:
                            logger.info(f"Role {uc.role_id} has {len(all_perms)} permissions: {[(p.method, p.path) for p in all_perms[:10]]}")
                        else:
                            logger.warning(f"Role {uc.role_id} has NO permissions assigned")
            else:
                # Use the full check_access_decision for routes with client_id
                has_access = await check_access_decision(
                    method=method,
                    path=normalized_path,  # Use normalized path for permission matching
                    user_id=user_id,
                    client_id=client_id,
                    target_client_id=None,
                    target_user_client_id=None,
                    db=db
                )
            
            db_checked = True
            # Break after first iteration (get_db yields once)
            break
        
        if not db_checked:
            logger.error(f"Database session error for user_id={user_id}, path={path}")
            return JSONResponse(
                status_code=500,
                content={"detail": "Database session error"}
            )
        
        if not has_access:
            logger.warning(f"Permission denied: user_id={user_id}, method={method}, path={path}, normalized_path={normalized_path}")
            return JSONResponse(
                status_code=403,
                content={"detail": "Permission denied. You do not have access to this resource."}
            )
        
        logger.info(f"Permission granted: user_id={user_id}, method={method}, path={path}, normalized_path={normalized_path}")
        
        # Set request state for downstream handlers
        request.state.user_id = user_id
        request.state.is_admin = False
        request.state.client_id = client_id
        
        response = await call_next(request)
        return response
    except Exception as e:
        # Errors during permission checking (database errors, etc.)
        # Don't catch exceptions from endpoint handlers - let FastAPI handle those
        # Only catch errors from our permission checking logic
        logger.error(f"Permission check failed: {str(e)}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": f"Permission check error: {str(e)}"}
        )
    
    # Fallback (should not reach here)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error during permission check"}
    )


# Health check
@app.get("/health")
async def health():
    """Health check"""
    return {"status": "healthy", "service": "api_gateway"}


# Auth routes (proxy to auth service)
@app.post("/api/auth/register")
async def register(request: Request):
    """Register endpoint is disabled. Only admin can create users."""
    return JSONResponse(
        status_code=403,
        content={"detail": "Public registration is disabled. Only administrators can create new users."}
    )


@app.post("/api/auth/create-user")
async def create_user(request: Request, current_user: dict = Depends(get_current_user)):
    """Create user (admin only)"""
    # Check if user is admin
    if not current_user.get("is_admin"):
        return JSONResponse(
            status_code=403,
            content={"detail": "Only administrators can create users"}
        )
    
    body = await request.json()
    # Forward to auth service - the auth service will validate admin status from token
    auth_header = request.headers.get("Authorization", "")
    try:
        result = await auth_client.post("/create-user", json=body, headers={"Authorization": auth_header})
        return result
    except httpx.HTTPStatusError as e:
        return JSONResponse(
            status_code=e.response.status_code,
            content=e.response.json() if e.response.content else {"detail": str(e)}
        )


@app.post("/api/auth/login")
async def login(request: Request):
    """Login"""
    try:
        body = await request.json()
        result = await auth_client.post("/login", json=body)
        return result
    except httpx.HTTPStatusError as e:
        logger.error(f"Auth service error: {e}")
        return JSONResponse(
            status_code=e.response.status_code,
            content=e.response.json() if e.response.content else {"detail": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except httpx.RequestError as e:
        logger.error(f"Auth service connection error: {e}")
        return JSONResponse(
            status_code=503,
            content={"detail": "Auth service unavailable", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"Login error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.post("/api/auth/refresh")
async def refresh(request: Request):
    """Refresh token"""
    body = await request.json()
    return await auth_client.post("/refresh", json=body)


@app.get("/api/auth/users")
async def list_users(request: Request, current_user: dict = Depends(get_current_user)):
    """List users (admin only)"""
    auth_header = request.headers.get("Authorization", "")
    try:
        result = await auth_client.get("/users", headers={"Authorization": auth_header})
        return result
    except httpx.HTTPStatusError as e:
        logger.error(f"Auth service error: {e}")
        return JSONResponse(
            status_code=e.response.status_code,
            content=e.response.json() if e.response.content else {"detail": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"List users error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.put("/api/auth/users/{user_id}")
async def update_user(
    user_id: str,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Update user (admin only)"""
    auth_header = request.headers.get("Authorization", "")
    try:
        body = await request.json()
        logger.info(f"PUT /api/auth/users/{user_id} - Updating user for admin: {current_user.get('user_id')}")
        result = await auth_client.put(f"/users/{user_id}", json=body, headers={"Authorization": auth_header})
        return JSONResponse(
            content=result,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except httpx.HTTPStatusError as e:
        logger.error(f"Auth service error: {e}")
        return JSONResponse(
            status_code=e.response.status_code,
            content=e.response.json() if e.response.content else {"detail": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"Update user error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.post("/api/auth/users/{user_id}/change-password")
async def change_user_password(
    user_id: str,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Change a user's password (self-service or admin)"""
    auth_header = request.headers.get("Authorization", "")
    try:
        body = await request.json()
        logger.info(
            f"POST /api/auth/users/{user_id}/change-password - "
            f"Password change requested by: {current_user.get('user_id')}"
        )
        result = await auth_client.post(
            f"/users/{user_id}/change-password",
            json=body,
            headers={"Authorization": auth_header},
        )
        return JSONResponse(
            content=result,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            },
        )
    except httpx.HTTPStatusError as e:
        logger.error(f"Auth service error (change-password): {e}")
        return JSONResponse(
            status_code=e.response.status_code,
            content=e.response.json() if e.response.content else {"detail": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            },
        )
    except Exception as e:
        logger.error("Change password error", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            },
        )


@app.delete("/api/auth/users/{user_id}")
async def delete_user(
    user_id: str,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Delete user (admin only) - Admins can delete any user including other admins"""
    # Check if user is admin
    if not current_user.get("is_admin"):
        return JSONResponse(
            status_code=403,
            content={"detail": "Only administrators can delete users"},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    
    auth_header = request.headers.get("Authorization", "")
    try:
        result = await auth_client.delete(f"/users/{user_id}", headers={"Authorization": auth_header})
        return result
    except httpx.HTTPStatusError as e:
        logger.error(f"Auth service error: {e}")
        error_content = e.response.json() if e.response.content else {"detail": str(e)}
        return JSONResponse(
            status_code=e.response.status_code,
            content=error_content,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"Delete user error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.get("/api/auth/me")
async def get_me(request: Request, current_user: dict = Depends(get_current_user)):
    """Get current user"""
    # Forward the authorization header from the original request
    auth_header = request.headers.get("Authorization", "")
    try:
        result = await auth_client.get("/me", headers={"Authorization": auth_header})
        return result
    except httpx.HTTPStatusError as e:
        logger.error(f"Auth service error: {e}")
        return JSONResponse(
            status_code=e.response.status_code,
            content=e.response.json() if e.response.content else {"detail": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"Get me error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.get("/api/auth/me/permissions")
async def get_my_permissions(current_user: dict = Depends(get_current_user)):
    """Get current user's permissions (from all their roles)"""
    try:
        user_id = current_user.get("user_id")
        is_admin_value = current_user.get("is_admin", False)
        
        # Handle both boolean and string values for is_admin
        # JWT might have it as string "true" if database has it as string
        is_admin = False
        if isinstance(is_admin_value, bool):
            is_admin = is_admin_value == True
        elif isinstance(is_admin_value, str):
            # Handle string values: "true", "True", "TRUE", "1", "yes", etc.
            is_admin = str(is_admin_value).lower().strip() in ("true", "1", "yes", "on")
            logger.info(f"/me/permissions: is_admin_value is string '{is_admin_value}', converted to {is_admin}")
        else:
            # For any other type, try to convert to boolean
            is_admin = bool(is_admin_value)
            logger.info(f"/me/permissions: is_admin_value is {type(is_admin_value)} '{is_admin_value}', converted to {is_admin}")
        
        logger.info(f"/me/permissions: Admin check for user {user_id}: is_admin={is_admin} (original: {is_admin_value}, type: {type(is_admin_value)})")
        
        # If JWT doesn't indicate admin, check database as fallback
        if not is_admin:
            async for db in get_db():
                try:
                    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
                    user = result.scalar_one_or_none()
                    if user:
                        # Check both string and boolean values
                        user_is_admin = False
                        if isinstance(user.is_admin, bool):
                            user_is_admin = user.is_admin
                        elif isinstance(user.is_admin, str):
                            user_is_admin = user.is_admin.lower() in ("true", "1", "yes")
                        else:
                            user_is_admin = bool(user.is_admin)
                        
                        if user_is_admin:
                            is_admin = True
                            logger.info(f"User {user_id} is admin (verified from database in /me/permissions)")
                except Exception as e:
                    logger.warning(f"Failed to check admin status from database in /me/permissions: {e}")
                break
        
        # Admin has all permissions (return empty list - frontend will handle as "all access")
        if is_admin:
            logger.info(f"Admin user {user_id} - returning empty permissions list")
            return JSONResponse(
                content={"permissions": [], "is_admin": True},
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                    "Access-Control-Allow-Headers": "*",
                }
            )
        
        # Get all permissions for user's roles
        async for db in get_db():
            # Get all active user_clients for this user
            query = select(UserClient).where(
                and_(
                    UserClient.user_id == uuid.UUID(user_id),
                    UserClient.status == "active"
                )
            )
            result = await db.execute(query)
            user_clients = result.scalars().all()
            
            if not user_clients:
                return JSONResponse(
                    content={"permissions": [], "is_admin": False},
                    headers={
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                        "Access-Control-Allow-Headers": "*",
                    }
                )
            
            # Collect all unique role IDs
            role_ids = [uc.role_id for uc in user_clients]
            
            # Get all permissions for these roles
            permissions_query = (
                select(Permission)
                .join(RolePermission, Permission.id == RolePermission.permission_id)
                .where(RolePermission.role_id.in_(role_ids))
                .distinct()
            )
            result = await db.execute(permissions_query)
            permissions = result.scalars().all()
            
            logger.info(f"User {user_id} has {len(permissions)} permissions from roles {role_ids}")
            
            # Convert to list of dicts
            permissions_list = [
                {
                    "id": str(perm.id),
                    "method": perm.method,
                    "path": perm.path,
                    "description": perm.description
                }
                for perm in permissions
            ]
            
            logger.info(f"Returning permissions: {len(permissions_list)} permissions for user {user_id}")
            
            return JSONResponse(
                content={"permissions": permissions_list, "is_admin": False},
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                    "Access-Control-Allow-Headers": "*",
                }
            )
    
    except Exception as e:
        logger.error(f"Get permissions error: {str(e)}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


# Client routes (proxy to client service)
@app.post("/api/clients")
async def create_client(request: Request, current_user: dict = Depends(get_current_user)):
    """Create client"""
    logger.info(f"POST /api/clients - Creating client for user: {current_user.get('user_id')}")
    try:
        content_type = request.headers.get("content-type", "")
        
        # Check if it's FormData (multipart/form-data)
        if "multipart/form-data" in content_type:
            # Forward FormData directly to client service
            logger.info(f"POST /api/clients - Creating client with FormData")
            body_bytes = await request.body()
            # Build headers - preserve original content-type with boundary
            forward_headers = {}
            if content_type:
                forward_headers["Content-Type"] = content_type
            forward_headers["Content-Length"] = str(len(body_bytes))
            
            result = await client_client.post(
                "/clients",
                content=body_bytes,
                headers=forward_headers
            )
        else:
            # Handle as JSON
            body = await request.json()
            logger.info(f"POST /api/clients - Request body: {body}")
            result = await client_client.post("/clients", json=body)
        
        logger.info(f"POST /api/clients - Client service response: {result}")
        return result
    except httpx.HTTPStatusError as e:
        logger.error(f"Client service error: {e}")
        return JSONResponse(
            status_code=e.response.status_code,
            content=e.response.json() if e.response.content else {"detail": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"Create client error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.get("/api/clients/premium")
async def get_premium_clients():
    """Get premium clients for display (public endpoint for ordpanel)"""
    return await client_client.get("/clients/premium")


@app.get("/api/clients")
async def list_clients(current_user: dict = Depends(get_current_user)):
    """List clients - filtered by user's connected clients unless they have cross-client permission"""
    try:
        user_id = current_user.get("user_id")
        is_admin = current_user.get("is_admin", False)

        # Admin users can see all clients
        if is_admin:
            logger.info(f"Admin user {user_id} fetching all clients")
            result = await client_client.get("/clients")
            return result

        # Check for cross-client permission
        async for db in get_db():
            has_cross_client_access = await has_cross_client_permission(
                user_id=user_id,
                method="GET",
                endpoint_path="/api/clients",
                db=db
            )

            # If user has cross-client permission, return all clients
            if has_cross_client_access:
                logger.info(f"User {user_id} has cross-client permission for clients")
                result = await client_client.get("/clients")
                return result

            # Get user's connected clients
            query = select(UserClient).where(
                and_(
                    UserClient.user_id == uuid.UUID(user_id),
                    UserClient.status == "active"
                )
            )
            result = await db.execute(query)
            user_clients = result.scalars().all()

            if not user_clients:
                logger.warning(f"User {user_id} has no active user_clients")
                return JSONResponse(
                    content=[],
                    headers={
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                        "Access-Control-Allow-Headers": "*",
                    }
                )

            # Get list of client_ids user is connected to
            user_client_ids = [uc.client_id for uc in user_clients]
            logger.info(f"User {user_id} filtering clients to: {user_client_ids}")

            # Fetch all clients from service
            all_clients_result = await client_client.get("/clients")
            all_clients = all_clients_result if isinstance(all_clients_result, list) else []

            # Filter to only user's connected clients
            filtered_clients = [c for c in all_clients if c.get("client_id") in user_client_ids]

            return JSONResponse(
                content=filtered_clients,
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                    "Access-Control-Allow-Headers": "*",
                }
            )
            break
    except httpx.ConnectError as e:
        logger.error(f"Connection error to CLIENT_SERVICE_URL ({CLIENT_SERVICE_URL}): {e}")
        return JSONResponse(
            status_code=503,
            content={
                "detail": "Client service unavailable",
                "error": f"Could not connect to client service at {CLIENT_SERVICE_URL}. Please ensure the service is running.",
                "service_url": CLIENT_SERVICE_URL
            },
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except httpx.HTTPStatusError as e:
        logger.error(f"Client service HTTP error: {e}, status_code: {e.response.status_code}")
        try:
            if e.response.content:
                content = e.response.json()
            else:
                content = {"detail": f"Client service returned {e.response.status_code}", "status_code": e.response.status_code}
        except (ValueError, json.JSONDecodeError) as json_err:
            logger.error(f"Failed to parse client service response as JSON: {json_err}, response text: {e.response.text[:200]}")
            content = {
                "detail": f"Client service returned invalid JSON",
                "status_code": e.response.status_code,
                "error": str(json_err)
            }
        return JSONResponse(
            status_code=e.response.status_code,
            content=content,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except httpx.RequestError as e:
        logger.error(f"Request error to CLIENT_SERVICE_URL ({CLIENT_SERVICE_URL}): {e}")
        return JSONResponse(
            status_code=503,
            content={
                "detail": "Client service request failed",
                "error": str(e),
                "service_url": CLIENT_SERVICE_URL
            },
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error: {e}")
        return JSONResponse(
            status_code=500,
            content={
                "detail": "Failed to parse response from client service",
                "error": str(e),
                "service_url": CLIENT_SERVICE_URL
            },
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"List clients error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.get("/api/clients/{client_id}")
async def get_client(client_id: str):
    """Get client (public endpoint for ordpanel)"""
    try:
        return await client_client.get(f"/clients/{client_id}")
    except httpx.HTTPStatusError as e:
        logger.error(f"Client service error: {e}")
        return JSONResponse(
            status_code=e.response.status_code,
            content=e.response.json() if e.response.content else {"detail": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"Get client error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.put("/api/clients/{client_id}")
async def update_client(
    client_id: str,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Update client"""
    auth_header = request.headers.get("Authorization", "")
    try:
        content_type = request.headers.get("content-type", "")
        
        # Check if it's FormData (multipart/form-data)
        if "multipart/form-data" in content_type:
            # Forward FormData directly to client service
            logger.info(f"PUT /api/clients/{client_id} - Updating client with FormData for user: {current_user.get('user_id')}")
            # Read the raw body and forward it
            body_bytes = await request.body()
            # Build headers - preserve original content-type with boundary
            forward_headers = {"Authorization": auth_header}
            if content_type:
                forward_headers["Content-Type"] = content_type
            forward_headers["Content-Length"] = str(len(body_bytes))
            
            result = await client_client.put(
                f"/clients/{client_id}",
                content=body_bytes,
                headers=forward_headers
            )
        else:
            # Handle as JSON
            body = await request.json()
            logger.info(f"PUT /api/clients/{client_id} - Updating client for user: {current_user.get('user_id')}")
            logger.info(f"PUT /api/clients/{client_id} - Request body: {body}")
            result = await client_client.put(f"/clients/{client_id}", json=body, headers={"Authorization": auth_header})
        
        logger.info(f"PUT /api/clients/{client_id} - Client service response: {result}")
        return JSONResponse(
            content=result if result else {"detail": "Client updated successfully"},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except httpx.HTTPStatusError as e:
        logger.error(f"Client service error: {e}")
        try:
            error_content = e.response.json() if e.response.content else {"detail": str(e)}
        except (ValueError, json.JSONDecodeError):
            error_content = {"detail": e.response.text if e.response.text else str(e)}
        return JSONResponse(
            status_code=e.response.status_code,
            content=error_content,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"Update client error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.delete("/api/clients/{client_id}")
async def delete_client(
    client_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete client (soft delete)"""
    try:
        logger.info(f"DELETE /api/clients/{client_id} - Deleting client for user: {current_user.get('user_id')}")
        result = await client_client.delete(f"/clients/{client_id}")
        logger.info(f"DELETE /api/clients/{client_id} - Client service response: {result}")
        return Response(
            status_code=204,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except httpx.HTTPStatusError as e:
        logger.error(f"Client service error: {e}")
        error_content = {}
        if e.response.content:
            try:
                error_content = e.response.json()
            except:
                error_content = {"detail": str(e)}
        return JSONResponse(
            status_code=e.response.status_code,
            content=error_content,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"Delete client error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.get("/api/clients/{client_id}/integrations")
async def get_client_integration(client_id: str, current_user: dict = Depends(get_current_user)):
    """Get client integration settings"""
    try:
        result = await integration_client.get(f"/client-integrations/{client_id}")
        return JSONResponse(
            content=result,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except httpx.HTTPStatusError as e:
        logger.error(f"Integration service error: {e}")
        try:
            error_content = e.response.json() if e.response.content else {"detail": str(e)}
        except (ValueError, json.JSONDecodeError):
            error_content = {"detail": e.response.text if e.response.text else str(e)}
        return JSONResponse(
            status_code=e.response.status_code,
            content=error_content,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"Get client integration error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.put("/api/clients/{client_id}/integrations")
async def update_client_integration(client_id: str, request: Request, current_user: dict = Depends(get_current_user)):
    """Update client integration settings"""
    try:
        body = await request.json()
        result = await integration_client.put(f"/client-integrations/{client_id}", json=body)
        return JSONResponse(
            content=result if result else {"detail": "Integration updated successfully"},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except httpx.HTTPStatusError as e:
        logger.error(f"Integration service error: {e}")
        try:
            error_content = e.response.json() if e.response.content else {"detail": str(e)}
        except (ValueError, json.JSONDecodeError):
            error_content = {"detail": e.response.text if e.response.text else str(e)}
        return JSONResponse(
            status_code=e.response.status_code,
            content=error_content,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"Update client integration error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


# Lead routes
@app.post("/api/leads/ingest")
async def ingest_lead(request: Request):
    """Ingest lead via API key with CSRF and CAPTCHA validation for website leads only"""
    try:
        body = await request.json()
        
        # Check if this is a website lead (requires CSRF and CAPTCHA)
        lead_source = body.get("source", "").lower()
        is_website_lead = lead_source == "website"
        
        raw_payload = body.get("raw_payload", {})
        
        # For website leads, require CSRF token and CAPTCHA validation
        if is_website_lead:
            # Validate CSRF token
            csrf_token = raw_payload.get("csrf_token") or body.get("csrf_token")
            if not csrf_token:
                return JSONResponse(
                    status_code=400,
                    content={"detail": "CSRF token is required for website leads. Please refresh the page and try again."},
                    headers={
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                        "Access-Control-Allow-Headers": "*",
                    }
                )
            
            if not validate_csrf_token(csrf_token):
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid or expired CSRF token. Please refresh the page and try again."},
                    headers={
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                        "Access-Control-Allow-Headers": "*",
                    }
                )
            
            # Validate CAPTCHA
            captcha_id = raw_payload.get("captcha_id")
            captcha_text = raw_payload.get("captcha_text")
            
            if not captcha_id or not captcha_text:
                return JSONResponse(
                    status_code=400,
                    content={"detail": "CAPTCHA is required for website leads. Please complete the CAPTCHA and try again."},
                    headers={
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                        "Access-Control-Allow-Headers": "*",
                    }
                )
            
            if not validate_captcha(captcha_id, captcha_text):
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid or expired CAPTCHA. Please refresh and try again."},
                    headers={
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                        "Access-Control-Allow-Headers": "*",
                    }
                )
        
        # For non-website leads (Instagram, Facebook, etc.), skip CSRF and CAPTCHA validation
        
        # Only forward the X-API-Key header, not all headers (to avoid Content-Length mismatch)
        headers = {}
        api_key = request.headers.get("X-API-Key")
        if api_key:
            headers["X-API-Key"] = api_key
        
        result = await lead_client.post("/leads/ingest", json=body, headers=headers if headers else None)
        return JSONResponse(
            content=result,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except httpx.HTTPStatusError as e:
        # Pass through the status code and error message from lead service
        error_content = {}
        if e.response.content:
            try:
                error_content = e.response.json()
            except:
                error_content = {"detail": str(e)}
        
        return JSONResponse(
            status_code=e.response.status_code,
            content=error_content,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"Error in ingest_lead: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.get("/api/leads")
async def list_leads(
    client_id: Optional[str] = None,
    source: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    current_user: dict = Depends(get_current_user)
):
    """List leads - automatically filtered to user's connected clients"""
    try:
        user_id = current_user.get("user_id")
        is_admin = current_user.get("is_admin", False)
        
        # Admin users can see all leads
        if is_admin:
            params = {}
            if client_id:
                params["client_id"] = client_id
            if source:
                params["source"] = source
            params["skip"] = skip
            params["limit"] = limit
            
            result = await lead_client.get("/leads", params=params)
            return JSONResponse(
                content=result if result else [],
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                    "Access-Control-Allow-Headers": "*",
                }
            )
        
        # Non-admin users: Check if they have cross-client permission
        async for db in get_db():
            # Check for special permission to view all leads across all clients
            has_cross_client_access = await has_cross_client_permission(
                user_id=user_id,
                method="GET",
                endpoint_path="/api/leads",
                db=db
            )
            
            # If user has cross-client permission, return all leads (like admin)
            if has_cross_client_access:
                params = {}
                if client_id:
                    params["client_id"] = client_id
                if source:
                    params["source"] = source
                params["skip"] = skip
                params["limit"] = limit
                
                result = await lead_client.get("/leads", params=params)
                return JSONResponse(
                    content=result if result else [],
                    headers={
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                        "Access-Control-Allow-Headers": "*",
                    }
                )
            
            # Normal flow: Get their connected client_ids
            query = select(UserClient).where(
                and_(
                    UserClient.user_id == uuid.UUID(user_id),
                    UserClient.status == "active"
                )
            )
            result = await db.execute(query)
            user_clients = result.scalars().all()
            
            if not user_clients:
                # User has no connected clients, return empty list
                return JSONResponse(
                    content=[],
                    headers={
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                        "Access-Control-Allow-Headers": "*",
                    }
                )
            
            # Get list of client_ids user is connected to
            user_client_ids = [uc.client_id for uc in user_clients]
            
            # If client_id is provided, verify user has access to it
            if client_id:
                if client_id not in user_client_ids:
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "You do not have access to this client's data"},
                        headers={
                            "Access-Control-Allow-Origin": "*",
                            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                            "Access-Control-Allow-Headers": "*",
                        }
                    )
                # User has access to this specific client - fetch leads for this client only
                params = {"client_id": client_id}
                if source:
                    params["source"] = source
                params["skip"] = skip
                params["limit"] = limit
                
                all_leads = await lead_client.get("/leads", params=params)
                filtered_leads = all_leads if all_leads else []
            else:
                # Fetch leads for each of the user's connected clients in parallel
                # Then combine, sort, and paginate
                import asyncio
                
                tasks = []
                for user_client_id in user_client_ids:
                    params = {"client_id": user_client_id, "limit": 1000}  # Get enough leads per client
                    if source:
                        params["source"] = source
                    tasks.append(lead_client.get("/leads", params=params))
                
                # Execute all requests in parallel
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Combine leads from all clients
                all_leads = []
                for result in results:
                    if isinstance(result, Exception):
                        logger.error(f"Error fetching leads: {result}")
                        continue
                    if result:
                        all_leads.extend(result if isinstance(result, list) else [result])
                
                # Sort by created_at descending (most recent first)
                all_leads.sort(key=lambda x: x.get("created_at", ""), reverse=True)
                
                # Apply pagination
                filtered_leads = all_leads[skip:skip + limit]
            
            return JSONResponse(
                content=filtered_leads,
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                    "Access-Control-Allow-Headers": "*",
                }
            )
    except httpx.HTTPStatusError as e:
        logger.error(f"Lead service error: {e}")
        error_content = {}
        if e.response.content:
            try:
                error_content = e.response.json()
            except ValueError:
                error_content = {"detail": str(e)}
        else:
            error_content = {"detail": str(e)}
        return JSONResponse(
            status_code=e.response.status_code,
            content=error_content,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"List leads error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.post("/api/leads/ordpanel")
async def create_ordpanel_lead(request: Request):
    """Create lead from ordpanel (public endpoint, requires CSRF and CAPTCHA)"""
    try:
        body = await request.json()
        raw_payload = body.get("raw_payload", {})
        
        # Validate CSRF token (required for ordpanel leads)
        csrf_token = raw_payload.get("csrf_token") or body.get("csrf_token")
        if not csrf_token:
            return JSONResponse(
                status_code=400,
                content={"detail": "CSRF token is required. Please refresh the page and try again."},
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                    "Access-Control-Allow-Headers": "*",
                }
            )
        
        if not validate_csrf_token(csrf_token):
            return JSONResponse(
                status_code=400,
                content={"detail": "Invalid or expired CSRF token. Please refresh the page and try again."},
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                    "Access-Control-Allow-Headers": "*",
                }
            )
        
        # Validate CAPTCHA (required for ordpanel leads)
        captcha_id = raw_payload.get("captcha_id") or body.get("captcha_id")
        captcha_text = raw_payload.get("captcha_text") or body.get("captcha_text")
        
        if not captcha_id or not captcha_text:
            return JSONResponse(
                status_code=400,
                content={"detail": "CAPTCHA is required. Please complete the CAPTCHA and try again."},
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                    "Access-Control-Allow-Headers": "*",
                }
            )
        
        if not validate_captcha(captcha_id, captcha_text):
            return JSONResponse(
                status_code=400,
                content={"detail": "Invalid or expired CAPTCHA. Please refresh and try again."},
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                    "Access-Control-Allow-Headers": "*",
                }
            )
        
        # Forward to lead service
        result = await lead_client.post("/leads/ordpanel", json=body)
        return JSONResponse(
            content=result,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except httpx.HTTPStatusError as e:
        return JSONResponse(
            status_code=e.response.status_code,
            content=e.response.json() if e.response.content else {"detail": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"Ordpanel lead creation error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.get("/api/leads/{lead_id}")
async def get_lead(lead_id: str, current_user: dict = Depends(get_current_user)):
    """Get lead"""
    try:
        result = await lead_client.get(f"/leads/{lead_id}")
        return JSONResponse(
            content=result if result else {},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except httpx.HTTPStatusError as e:
        logger.error(f"Lead service error: {e}")
        error_content = {}
        if e.response.content:
            try:
                error_content = e.response.json()
            except ValueError:
                error_content = {"detail": str(e)}
        else:
            error_content = {"detail": str(e)}
        return JSONResponse(
            status_code=e.response.status_code,
            content=error_content,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"Get lead error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


# API Key routes
@app.post("/api/api-keys/generate")
async def generate_api_key(request: Request, current_user: dict = Depends(get_current_user)):
    """Generate API key for a client"""
    body = await request.json()
    return await lead_client.post("/api-keys/generate", json=body)


@app.get("/api/api-keys")
async def list_api_keys(
    client_id: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """List API keys"""
    try:
        params = {}
        if client_id:
            params["client_id"] = client_id
        return await lead_client.get("/api-keys", params=params)
    except httpx.HTTPStatusError as e:
        logger.error(f"Lead service error: {e}")
        return JSONResponse(
            status_code=e.response.status_code,
            content=e.response.json() if e.response.content else {"detail": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"List API keys error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.get("/api/api-keys/{api_key_id}")
async def get_api_key(
    api_key_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get API key details by ID"""
    try:
        result = await lead_client.get(f"/api-keys/{api_key_id}")
        return result
    except httpx.HTTPStatusError as e:
        logger.error(f"Lead service error: {e}")
        return JSONResponse(
            status_code=e.response.status_code,
            content=e.response.json() if e.response.content else {"detail": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"Get API key error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.patch("/api/api-keys/{api_key_id}")
async def update_api_key(
    api_key_id: str,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Update API key (disable/enable)"""
    logger.info(f"Update API key request: api_key_id={api_key_id}")
    try:
        body = await request.json()
        logger.info(f"Request body: {body}")
        logger.info(f"Calling lead service: PATCH {LEAD_SERVICE_URL}/api-keys/{api_key_id}")
        result = await lead_client.patch(f"/api-keys/{api_key_id}", json=body)
        logger.info(f"Lead service response: {result}")
        return JSONResponse(
            content=result,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except httpx.HTTPStatusError as e:
        logger.error(f"Lead service HTTP error: {e.response.status_code} - {e.response.text}")
        error_content = {}
        if e.response.content:
            try:
                error_content = e.response.json()
            except:
                error_content = {"detail": str(e)}
        return JSONResponse(
            status_code=e.response.status_code,
            content=error_content,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"Update API key error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.delete("/api/api-keys/{api_key_id}")
async def delete_api_key(
    api_key_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Delete API key"""
    logger.info(f"Delete API key request: api_key_id={api_key_id}")
    try:
        logger.info(f"Calling lead service: DELETE {LEAD_SERVICE_URL}/api-keys/{api_key_id}")
        result = await lead_client.delete(f"/api-keys/{api_key_id}")
        logger.info(f"Lead service response: {result}")
        # For 204 No Content, return empty response
        return Response(
            status_code=204,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except httpx.HTTPStatusError as e:
        logger.error(f"Lead service HTTP error: {e.response.status_code} - {e.response.text}")
        error_content = {}
        if e.response.content:
            try:
                error_content = e.response.json()
            except:
                error_content = {"detail": str(e)}
        logger.error(f"Returning error: {error_content}")
        return JSONResponse(
            status_code=e.response.status_code,
            content=error_content,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"Delete API key error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


# Order Service Routes
@app.post("/api/orders/submit")
async def submit_order(request: Request):
    """Submit order form (public endpoint, can use API key)"""
    body = await request.json()
    headers = {}
    
    # Forward API key if present
    api_key = request.headers.get("X-API-Key")
    if api_key:
        headers["X-API-Key"] = api_key
    
    try:
        result = await client_client.post("/orders/submit", json=body, headers=headers if headers else None)
        return result
    except httpx.HTTPStatusError as e:
        logger.error(f"Order service error: {e}")
        return JSONResponse(
            status_code=e.response.status_code,
            content=e.response.json() if e.response.content else {"detail": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"Submit order error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


# Transaction Routes
@app.post("/api/transactions")
async def create_transaction(request: Request, current_user: dict = Depends(get_current_user)):
    """Create a new transaction (requires authentication)"""
    try:
        body = await request.json()
    except Exception as e:
        logger.error(f"Failed to parse request body: {e}")
        return JSONResponse(
            status_code=400,
            content={"detail": "Invalid JSON in request body", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    
    try:
        result = await client_client.post("/transactions", json=body)
        return result
    except httpx.HTTPStatusError as e:
        logger.error(f"Client service error: {e}")
        # Try to parse JSON response, but handle empty or invalid JSON
        content = None
        status_code = 500
        
        try:
            # Get status code safely
            if hasattr(e, 'response') and e.response:
                status_code = e.response.status_code
                
                # Try to get response content
                if hasattr(e.response, 'content') and e.response.content:
                    # Try to parse as JSON first
                    try:
                        content = e.response.json()
                        logger.info(f"Client service error response (JSON): {content}, type: {type(content)}")
                        # If content is just a generic error, enhance it with more helpful information
                        if isinstance(content, dict):
                            detail = content.get("detail", "")
                            logger.info(f"Detail from response: '{detail}', type: {type(detail)}")
                            # Normalize detail for comparison (strip whitespace, lowercase)
                            detail_normalized = str(detail).strip().lower() if detail else ""
                            logger.info(f"Detail normalized: '{detail_normalized}'")
                            # Check if it's a generic error message
                            generic_errors = ["internal server error", "internal error", ""]
                            logger.info(f"Checking if '{detail_normalized}' in {generic_errors} or empty: {not detail_normalized}")
                            if detail_normalized in generic_errors or not detail_normalized:
                                logger.info(f"✓ Detected generic error, enhancing message")
                                content = {
                                    "detail": "Client service encountered an internal error",
                                    "service": "client_service",
                                    "status_code": status_code,
                                    "message": "The client service returned a 500 error. This is typically caused by:",
                                    "possible_causes": [
                                        "Database connection or schema issues",
                                        "Missing or incorrect database tables/foreign keys",
                                        "Service configuration problems",
                                        "Unhandled exceptions in the service"
                                    ],
                                    "suggestion": "Check the client_service logs for detailed error information"
                                }
                            else:
                                # Keep the original detail but add service info
                                # Only add if not already present to avoid overwriting
                                if "service" not in content:
                                    content["service"] = "client_service"
                                if "status_code" not in content:
                                    content["status_code"] = status_code
                    except (ValueError, json.JSONDecodeError, AttributeError):
                        # If JSON parsing fails, try to get text content
                        try:
                            if hasattr(e.response, 'text'):
                                text_content = e.response.text
                                if text_content and text_content.strip():
                                    # Check if it's HTML (FastAPI default error page)
                                    if text_content.strip().startswith('<'):
                                        content = {
                                            "detail": f"Client service returned {status_code}",
                                            "service": "client_service",
                                            "status_code": status_code,
                                            "message": "The client service encountered an error. This is likely a database or service configuration issue."
                                        }
                                    else:
                                        content = {
                                            "detail": text_content[:500],  # Limit length
                                            "service": "client_service",
                                            "status_code": status_code
                                        }
                                else:
                                    content = {
                                        "detail": f"Client service returned {status_code} with empty response",
                                        "service": "client_service",
                                        "status_code": status_code
                                    }
                            else:
                                content = {
                                    "detail": f"Client service returned {status_code}",
                                    "service": "client_service",
                                    "status_code": status_code
                                }
                        except Exception as text_error:
                            logger.error(f"Error getting response text: {text_error}")
                            content = {
                                "detail": f"Client service returned {status_code}",
                                "service": "client_service",
                                "status_code": status_code
                            }
                else:
                    content = {
                        "detail": f"Client service returned {status_code} with no content",
                        "service": "client_service",
                        "status_code": status_code,
                        "message": "The client service returned an error but provided no error details."
                    }
            else:
                content = {
                    "detail": f"Client service error: {str(e)}",
                    "service": "client_service"
                }
        except Exception as parse_error:
            logger.error(f"Error parsing client service error response: {parse_error}", exc_info=True)
            content = {
                "detail": f"Client service error: {str(e)}",
                "service": "client_service",
                "parse_error": str(parse_error)
            }
        
        # Ensure we have content
        if not content:
            content = {
                "detail": f"Client service returned {status_code}",
                "service": "client_service",
                "status_code": status_code
            }
        
        logger.info(f"Returning error response: status={status_code}, content={content}")
        
        return JSONResponse(
            status_code=status_code,
            content=content,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"Create transaction error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.get("/api/transactions")
async def list_transactions(
    client_id: Optional[str] = None,
    status: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    current_user: dict = Depends(get_current_user)
):
    """List transactions (requires authentication) - automatically filtered to user's connected clients unless cross-client permission"""
    try:
        user_id = current_user.get("user_id")
        is_admin = current_user.get("is_admin", False)
        
        # Admin users can see all transactions
        if is_admin:
            params = {}
            if client_id:
                params["client_id"] = client_id
            if status:
                params["status_filter"] = status
            params["skip"] = skip
            params["limit"] = limit
            
            result = await client_client.get("/transactions", params=params)
            return result
        
        # Non-admin users: Check if they have cross-client permission
        async for db in get_db():
            # Check for special permission to view all transactions across all clients
            has_cross_client_access = await has_cross_client_permission(
                user_id=user_id,
                method="GET",
                endpoint_path="/api/transactions",
                db=db
            )
            
            # If user has cross-client permission, return all transactions (like admin)
            if has_cross_client_access:
                params = {}
                if client_id:
                    params["client_id"] = client_id
                if status:
                    params["status_filter"] = status
                params["skip"] = skip
                params["limit"] = limit
                
                result = await client_client.get("/transactions", params=params)
                return result
            
            # Normal flow: Get their connected client_ids
            query = select(UserClient).where(
                and_(
                    UserClient.user_id == uuid.UUID(user_id),
                    UserClient.status == "active"
                )
            )
            result = await db.execute(query)
            user_clients = result.scalars().all()
            
            if not user_clients:
                # User has no connected clients, return empty list
                return JSONResponse(
                    content=[],
                    headers={
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                        "Access-Control-Allow-Headers": "*",
                    }
                )
            
            # Get list of client_ids user is connected to
            user_client_ids = [uc.client_id for uc in user_clients]
            
            # If client_id is provided, verify user has access to it
            if client_id:
                if client_id not in user_client_ids:
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "You do not have access to this client's data"},
                        headers={
                            "Access-Control-Allow-Origin": "*",
                            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                            "Access-Control-Allow-Headers": "*",
                        }
                    )
                # User has access to this specific client
                params = {"client_id": client_id}
            else:
                # Filter by all user's connected clients
                # Since transactions endpoint doesn't support multiple client_ids in one call,
                # we'll need to fetch for each client and combine
                import asyncio
                
                tasks = []
                for user_client_id in user_client_ids:
                    params = {"client_id": user_client_id, "limit": 1000}
                    if status:
                        params["status_filter"] = status
                    tasks.append(client_client.get("/transactions", params=params))
                
                # Execute all requests in parallel
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Combine transactions from all clients
                all_transactions = []
                for result in results:
                    if isinstance(result, Exception):
                        logger.error(f"Error fetching transactions: {result}")
                        continue
                    if result:
                        # Handle both array and object responses
                        transactions = result if isinstance(result, list) else (result.get("data", []) if isinstance(result, dict) else [])
                        if transactions:
                            all_transactions.extend(transactions)
                
                # Sort by created_at descending (most recent first)
                all_transactions.sort(key=lambda x: x.get("created_at", ""), reverse=True)
                
                # Apply pagination
                filtered_transactions = all_transactions[skip:skip + limit]
                
                return JSONResponse(
                    content=filtered_transactions,
                    headers={
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                        "Access-Control-Allow-Headers": "*",
                    }
                )
            
            # Single client access
            params = {}
            if client_id:
                params["client_id"] = client_id
            if status:
                params["status_filter"] = status
            params["skip"] = skip
            params["limit"] = limit
            
            result = await client_client.get("/transactions", params=params)
            return result
    except httpx.HTTPStatusError as e:
        logger.error(f"Order service error: {e}")
        return JSONResponse(
            status_code=e.response.status_code,
            content=e.response.json() if e.response.content else {"detail": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"List transactions error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.get("/api/transactions/{transaction_id}")
async def get_transaction(transaction_id: str, current_user: dict = Depends(get_current_user)):
    """Get transaction by ID (requires authentication)"""
    try:
        result = await client_client.get(f"/transactions/{transaction_id}")
        return result
    except httpx.HTTPStatusError as e:
        logger.error(f"Order service error: {e}")
        return JSONResponse(
            status_code=e.response.status_code,
            content=e.response.json() if e.response.content else {"detail": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"Get transaction error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.patch("/api/transactions/{transaction_id}/verify")
async def verify_transaction(
    transaction_id: str,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Verify or reject a transaction (admin only)"""
    body = await request.json()
    # Add verified_by_user_id from current user
    body["verified_by_user_id"] = current_user.get("user_id")
    
    try:
        result = await client_client.patch(f"/transactions/{transaction_id}/verify", json=body)
        return result
    except httpx.HTTPStatusError as e:
        logger.error(f"Order service error: {e}")
        return JSONResponse(
            status_code=e.response.status_code,
            content=e.response.json() if e.response.content else {"detail": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"Verify transaction error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.get("/api/clients/{client_id}/balance")
async def get_client_balance(client_id: str, current_user: dict = Depends(get_current_user)):
    """Get client's payment balance (requires authentication)"""
    try:
        result = await client_client.get(f"/clients/{client_id}/balance")
        return result
    except httpx.HTTPStatusError as e:
        logger.error(f"Order service error: {e}")
        return JSONResponse(
            status_code=e.response.status_code,
            content=e.response.json() if e.response.content else {"detail": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"Get client balance error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


# Security/CAPTCHA routes (public - no authentication required)
@app.get("/api/security/captcha")
async def get_captcha():
    """Generate and return a new CAPTCHA"""
    try:
        logger.info("CAPTCHA generation requested")
        
        # Check if Pillow is available
        try:
            from shared.utils.captcha import PILLOW_AVAILABLE
            if not PILLOW_AVAILABLE:
                logger.error("Pillow is not installed. Please install it with: pip install Pillow")
                return JSONResponse(
                    status_code=500,
                    content={"detail": "CAPTCHA service unavailable. Pillow library is not installed."},
                    headers={
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                        "Access-Control-Allow-Headers": "*",
                    }
                )
        except ImportError as ie:
            logger.error(f"Failed to import CAPTCHA utilities: {ie}")
            return JSONResponse(
                status_code=500,
                content={"detail": "CAPTCHA service unavailable", "error": str(ie)},
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                    "Access-Control-Allow-Headers": "*",
                }
            )
        
        # Generate CAPTCHA
        captcha_text = generate_captcha_text()
        captcha_id = str(uuid.uuid4())
        logger.info(f"Generated CAPTCHA text: {captcha_text} (ID: {captcha_id})")
        
        # Store CAPTCHA solution in Redis with 10-minute expiration
        if rate_limiter.redis:
            captcha_key = f"captcha:{captcha_id}"
            # Store hashed solution for security
            hashed_solution = hash_captcha_text(captcha_text.upper())
            rate_limiter.redis.setex(captcha_key, 600, hashed_solution)  # 10 minutes
            logger.info(f"Stored CAPTCHA solution in Redis: {captcha_key}")
        else:
            logger.warning("Redis not available - CAPTCHA validation will be skipped")
        
        # Generate CAPTCHA image
        logger.info("Generating CAPTCHA image...")
        image_data_url, _ = create_captcha(captcha_id, captcha_text)
        logger.info("CAPTCHA image generated successfully")
        
        return JSONResponse(
            content={
                "captcha_id": captcha_id,
                "captcha_image": image_data_url
            },
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"CAPTCHA generation error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Failed to generate CAPTCHA", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.get("/api/security/csrf")
async def get_csrf_token():
    """Generate CSRF token for website forms"""
    try:
        # Generate a random CSRF token
        csrf_token = str(uuid.uuid4())
        
        # Store CSRF token in Redis with 1-hour expiration
        if rate_limiter.redis:
            csrf_key = f"csrf:{csrf_token}"
            rate_limiter.redis.setex(csrf_key, 3600, "valid")  # 1 hour
            logger.info(f"Generated CSRF token: {csrf_token}")
        else:
            logger.warning("Redis not available - CSRF token will not be validated")
        
        return JSONResponse(
            content={"csrf_token": csrf_token},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"CSRF token generation error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Failed to generate CSRF token", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.get("/api/security/token")
async def get_js_token():
    """Generate JS token (optional - returns empty for compatibility)"""
    # JS token is not required for API key authentication, but return empty token for compatibility
    return JSONResponse(
        content={"js_token": ""},
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "*",
        }
    )


# Helper function to validate CAPTCHA
def validate_captcha(captcha_id: str, captcha_text: str) -> bool:
    """Validate CAPTCHA solution"""
    if not captcha_id or not captcha_text:
        return False
    
    if not rate_limiter.redis:
        # If Redis is not available, skip CAPTCHA validation (not ideal but allows form to work)
        logger.warning("Redis not available, skipping CAPTCHA validation")
        return True
    
    captcha_key = f"captcha:{captcha_id}"
    stored_hash = rate_limiter.redis.get(captcha_key)
    
    if not stored_hash:
        return False
    
    # Compare hashed solutions
    provided_hash = hash_captcha_text(captcha_text.upper().strip())
    is_valid = stored_hash == provided_hash
    
    # Delete CAPTCHA after validation (one-time use)
    if is_valid:
        rate_limiter.redis.delete(captcha_key)
    
    return is_valid


# Helper function to validate CSRF token
def validate_csrf_token(csrf_token: str) -> bool:
    """Validate CSRF token"""
    if not csrf_token:
        return False
    
    if not rate_limiter.redis:
        # If Redis is not available, skip CSRF validation (not ideal but allows form to work)
        logger.warning("Redis not available, skipping CSRF validation")
        return True
    
    csrf_key = f"csrf:{csrf_token}"
    is_valid = rate_limiter.redis.exists(csrf_key)
    
    # Delete CSRF token after validation (one-time use)
    if is_valid:
        rate_limiter.redis.delete(csrf_key)
    
    return bool(is_valid)


# Webhook routes (public)
@app.get("/webhook/meta")
async def meta_webhook_verification(request: Request):
    """Meta webhook verification"""
    params = dict(request.query_params)
    return await webhook_client.get("/webhook/meta", params=params)


@app.post("/webhook/meta")
async def meta_webhook_handler(request: Request):
    """Meta webhook handler"""
    body = await request.json()
    headers = dict(request.headers)
    return await webhook_client.post("/webhook/meta", json=body, headers=headers)


# Roles routes (proxy to permission service)
@app.post("/api/roles")
async def create_role(request: Request, current_user: dict = Depends(get_current_user)):
    """Create role"""
    body = await request.json()
    try:
        return await permission_client.post("/roles", json=body)
    except httpx.HTTPStatusError as e:
        logger.error(f"Permission service error: {e}")
        try:
            content = e.response.json() if e.response.content else {"detail": str(e)}
        except (ValueError, json.JSONDecodeError):
            content = {"detail": f"Permission service returned {e.response.status_code}"}
        return JSONResponse(
            status_code=e.response.status_code,
            content=content,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"Create role error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.get("/api/roles")
async def list_roles(current_user: dict = Depends(get_current_user)):
    """List roles"""
    try:
        return await permission_client.get("/roles")
    except httpx.HTTPStatusError as e:
        logger.error(f"Permission service error: {e}")
        try:
            content = e.response.json() if e.response.content else {"detail": str(e)}
        except (ValueError, json.JSONDecodeError):
            content = {"detail": f"Permission service returned {e.response.status_code}"}
        return JSONResponse(
            status_code=e.response.status_code,
            content=content,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"List roles error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.get("/api/roles/{role_id}")
async def get_role(role_id: str, current_user: dict = Depends(get_current_user)):
    """Get role"""
    try:
        return await permission_client.get(f"/roles/{role_id}")
    except httpx.HTTPStatusError as e:
        logger.error(f"Permission service error: {e}")
        try:
            content = e.response.json() if e.response.content else {"detail": str(e)}
        except (ValueError, json.JSONDecodeError):
            content = {"detail": f"Permission service returned {e.response.status_code}"}
        return JSONResponse(
            status_code=e.response.status_code,
            content=content,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"Get role error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.put("/api/roles/{role_id}")
async def update_role(role_id: str, request: Request, current_user: dict = Depends(get_current_user)):
    """Update role"""
    body = await request.json()
    try:
        return await permission_client.put(f"/roles/{role_id}", json=body)
    except httpx.HTTPStatusError as e:
        logger.error(f"Permission service error: {e}")
        try:
            content = e.response.json() if e.response.content else {"detail": str(e)}
        except (ValueError, json.JSONDecodeError):
            content = {"detail": f"Permission service returned {e.response.status_code}"}
        return JSONResponse(
            status_code=e.response.status_code,
            content=content,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"Update role error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


# Permissions routes (proxy to permission service)
@app.post("/api/permissions")
async def create_permission(request: Request, current_user: dict = Depends(get_current_user)):
    """Create permission"""
    body = await request.json()
    try:
        result = await permission_client.post("/permissions", json=body)
        return result
    except httpx.HTTPStatusError as e:
        logger.error(f"Permission service error: {e}")
        return JSONResponse(
            status_code=e.response.status_code,
            content=e.response.json() if e.response.content else {"detail": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"Create permission error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.get("/api/permissions")
async def list_permissions(current_user: dict = Depends(get_current_user)):
    """List permissions"""
    try:
        result = await permission_client.get("/permissions")
        return result
    except httpx.HTTPStatusError as e:
        logger.error(f"Permission service error: {e}")
        return JSONResponse(
            status_code=e.response.status_code,
            content=e.response.json() if e.response.content else {"detail": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"List permissions error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.get("/api/permissions/{permission_id}")
async def get_permission(permission_id: str, current_user: dict = Depends(get_current_user)):
    """Get permission"""
    return await permission_client.get(f"/permissions/{permission_id}")


@app.get("/api/endpoints")
async def list_available_endpoints(current_user: dict = Depends(get_current_user)):
    """Get all available API endpoints for permission creation"""
    endpoints = []
    
    # Scan all routes in the API Gateway
    for route in app.routes:
        if hasattr(route, 'methods') and hasattr(route, 'path'):
            # Skip health checks, docs, and webhook endpoints
            if route.path in ['/health', '/docs', '/openapi.json', '/redoc']:
                continue
            if route.path.startswith('/webhook'):
                continue
            
            for method in route.methods:
                if method == 'HEAD' or method == 'OPTIONS':
                    continue
                
                # Get route summary/description if available
                description = f"{method.upper()} {route.path}"
                if hasattr(route, 'summary') and route.summary:
                    description = route.summary
                elif hasattr(route, 'description') and route.description:
                    description = route.description
                
                endpoints.append({
                    "method": method.upper(),
                    "path": route.path,
                    "description": description
                })
    
    # Sort by method, then by path
    endpoints.sort(key=lambda x: (x["method"], x["path"]))
    
    return endpoints


# Role-Permission routes (proxy to permission service)
@app.post("/api/role-permissions")
async def assign_permission_to_role(request: Request, current_user: dict = Depends(get_current_user)):
    """Assign permission to role"""
    body = await request.json()
    return await permission_client.post("/role-permissions", json=body)


@app.delete("/api/role-permissions")
async def remove_permission_from_role(request: Request, current_user: dict = Depends(get_current_user)):
    """Remove permission from role"""
    body = await request.json()
    try:
        result = await permission_client.delete("/role-permissions", json=body)
        return result
    except httpx.HTTPStatusError as e:
        logger.error(f"Permission service error: {e}")
        return JSONResponse(
            status_code=e.response.status_code,
            content=e.response.json() if e.response.content else {"detail": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"Remove permission error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.get("/api/roles/{role_id}/permissions")
async def get_role_permissions(role_id: str, current_user: dict = Depends(get_current_user)):
    """Get permissions for a role"""
    return await permission_client.get(f"/roles/{role_id}/permissions")


# User-Client routes (proxy to user service)
@app.post("/api/user-clients")
async def create_user_client(request: Request, current_user: dict = Depends(get_current_user)):
    """Assign user to client with role"""
    body = await request.json()
    return await user_client.post("/user-clients", json=body)


@app.get("/api/user-clients")
async def list_user_clients(current_user: dict = Depends(get_current_user)):
    """List user-client relationships"""
    return await user_client.get("/user-clients")


@app.get("/api/user-clients/{user_client_id}")
async def get_user_client(user_client_id: str, current_user: dict = Depends(get_current_user)):
    """Get user-client relationship"""
    return await user_client.get(f"/user-clients/{user_client_id}")


@app.put("/api/user-clients/{user_client_id}")
async def update_user_client(user_client_id: str, request: Request, current_user: dict = Depends(get_current_user)):
    """Update user-client relationship"""
    body = await request.json()
    return await user_client.put(f"/user-clients/{user_client_id}", json=body)


@app.get("/api/users/{user_id}/clients")
async def get_user_clients(user_id: str, current_user: dict = Depends(get_current_user)):
    """Get all clients for a user"""
    return await user_client.get(f"/users/{user_id}/clients")


# Hierarchy routes (proxy to hierarchy service)
@app.post("/api/hierarchy/rebuild/{client_id}")
async def rebuild_hierarchy(client_id: str, current_user: dict = Depends(get_current_user)):
    """Rebuild hierarchy for a client"""
    return await hierarchy_client.post(f"/hierarchy/rebuild/{client_id}")


@app.get("/api/hierarchy/{user_client_id}/descendants")
async def get_descendants(
    user_client_id: str,
    include_self: bool = False,
    current_user: dict = Depends(get_current_user)
):
    """Get descendant user-clients"""
    params = {"include_self": str(include_self).lower()}
    return await hierarchy_client.get(f"/hierarchy/{user_client_id}/descendants", params=params)


@app.get("/api/hierarchy/{user_client_id}/tree")
async def get_hierarchy_tree(user_client_id: str, current_user: dict = Depends(get_current_user)):
    """Get hierarchy tree starting from a user-client"""
    return await hierarchy_client.get(f"/hierarchy/{user_client_id}/tree")


@app.post("/api/hierarchy/check-access")
async def check_hierarchy_access(request: Request, current_user: dict = Depends(get_current_user)):
    """Check if requester can access target user-client"""
    body = await request.json()
    return await hierarchy_client.post("/hierarchy/check-access", json=body)


# Product routes (proxy to product service)
@app.post("/api/industries")
async def create_industry(request: Request, current_user: dict = Depends(get_current_user)):
    """Create industry"""
    try:
        # Handle multipart/form-data for file uploads
        content_type = request.headers.get("content-type", "")
        if "multipart/form-data" in content_type:
            form = await request.form()
            files = {}
            data = {}
            for key, value in form.items():
                if hasattr(value, 'read'):  # It's a file upload
                    files[key] = (value.filename, await value.read(), value.content_type)
                else:
                    # Convert boolean strings to lowercase for FastAPI to parse correctly
                    if key in ['is_home', 'is_top']:
                        # Keep as lowercase string - FastAPI Form() will convert it
                        str_value = str(value).lower()
                        data[key] = 'true' if str_value in ('true', '1', 'yes', 'on') else 'false'
                    else:
                        data[key] = value
            
            # Forward to product service
            async with httpx.AsyncClient() as client:
                try:
                    response = await client.post(
                        f"{PRODUCT_SERVICE_URL}/industries",
                        data=data,
                        files=files,
                        timeout=30.0
                    )
                    response.raise_for_status()
                    return response.json()
                except httpx.HTTPStatusError as e:
                    logger.error(f"Product service error: {e}")
                    logger.error(f"Response status: {e.response.status_code}")
                    logger.error(f"Response text: {e.response.text[:500] if e.response.text else 'No response text'}")
                    try:
                        error_content = e.response.json() if e.response.content else {"detail": str(e)}
                    except (ValueError, json.JSONDecodeError):
                        error_content = {
                            "detail": "Internal server error",
                            "error": f"Server error '{e.response.status_code} {e.response.reason_phrase}' for url '{e.request.url}'"
                        }
                        if e.response.text:
                            error_content["error_detail"] = e.response.text[:500]
                    return JSONResponse(
                        status_code=e.response.status_code,
                        content=error_content,
                        headers={
                            "Access-Control-Allow-Origin": "*",
                            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                            "Access-Control-Allow-Headers": "*",
                        }
                    )
                except httpx.RequestError as e:
                    logger.error(f"Product service connection error: {e}")
                    return JSONResponse(
                        status_code=503,
                        content={"detail": "Product service unavailable", "error": str(e)},
                        headers={
                            "Access-Control-Allow-Origin": "*",
                            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                            "Access-Control-Allow-Headers": "*",
                        }
                    )
        else:
            body = await request.json()
            return await product_client.post("/industries", json=body)
    except httpx.HTTPStatusError as e:
        logger.error(f"Product service error: {e}")
        logger.error(f"Response status: {e.response.status_code}")
        logger.error(f"Response text: {e.response.text[:500] if e.response.text else 'No response text'}")
        try:
            error_content = e.response.json() if e.response.content else {"detail": str(e)}
        except (ValueError, json.JSONDecodeError):
            error_content = {
                "detail": "Internal server error",
                "error": f"Server error '{e.response.status_code} {e.response.reason_phrase}' for url '{e.request.url}'"
            }
            if e.response.text:
                error_content["error_detail"] = e.response.text[:500]
        return JSONResponse(
            status_code=e.response.status_code,
            content=error_content,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except httpx.RequestError as e:
        logger.error(f"Product service connection error: {e}")
        return JSONResponse(
            status_code=503,
            content={"detail": "Product service unavailable", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"Create industry error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.get("/api/industries")
async def list_industries():
    """List industries (public endpoint for ordpanel)"""
    return await product_client.get("/industries")


@app.get("/api/industries/{industry_id}")
async def get_industry(industry_id: str):
    """Get industry (public endpoint for ordpanel)"""
    return await product_client.get(f"/industries/{industry_id}")


@app.get("/api/industries/top")
async def get_top_industries():
    """Get top industries (public endpoint for frontend)"""
    return await product_client.get("/industries/top")


@app.get("/api/industries/home")
async def get_home_industries():
    """Get home industries for industry map display (public endpoint for ordpanel)"""
    return await product_client.get("/industries/home")


@app.get("/api/about-us")
async def get_about_us():
    """Get About Us content (public endpoint for ordpanel)"""
    return await content_client.get("/about-us")


@app.post("/api/about-us")
async def create_about_us(request: Request, current_user: dict = Depends(get_current_user)):
    """Create About Us content (admin only)"""
    body = await request.json()
    return await content_client.post("/about-us", json=body)


@app.put("/api/about-us/{about_us_id}")
async def update_about_us(
    about_us_id: str,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Update About Us content (admin only)"""
    body = await request.json()
    return await content_client.put(f"/about-us/{about_us_id}", json=body)


@app.get("/api/search")
async def search_suggestions(q: str):
    """Search suggestions across industries, categories, products, and clients (public endpoint for ordpanel)"""
    query = q.strip().lower()
    if not query or len(query) < 2:
        return {
            "industries": [],
            "categories": [],
            "products": [],
            "clients": []
        }
    
    suggestions = {
        "industries": [],
        "categories": [],
        "products": [],
        "clients": []
    }
    
    try:
        # Search industries
        try:
            industries_response = await product_client.get("/industries")
            if industries_response and isinstance(industries_response, list):
                industries = [
                    {
                        "id": ind.get("id"),
                        "name": ind.get("name"),
                        "type": "industry",
                        "url": f"/industry/{ind.get('id')}",
                        "logo": ind.get("logo"),
                        "image": ind.get("image")
                    }
                    for ind in industries_response
                    if query in ind.get("name", "").lower()
                ][:5]  # Limit to 5 suggestions
                suggestions["industries"] = industries
        except Exception as e:
            logger.error(f"Error searching industries: {e}")
        
        # Search product categories
        try:
            categories_response = await product_client.get("/product-categories")
            if categories_response and isinstance(categories_response, list):
                categories = [
                    {
                        "id": cat.get("id"),
                        "name": cat.get("name"),
                        "industry_name": cat.get("industry_name"),
                        "type": "category",
                        "url": f"/category/{cat.get('id')}",
                        "image": cat.get("image")
                    }
                    for cat in categories_response
                    if query in cat.get("name", "").lower()
                ][:5]  # Limit to 5 suggestions
                suggestions["categories"] = categories
        except Exception as e:
            logger.error(f"Error searching categories: {e}")
        
        # Search products
        try:
            products_response = await product_client.get("/products")
            if products_response and isinstance(products_response, list):
                products = [
                    {
                        "id": prod.get("id"),
                        "name": prod.get("name"),
                        "category_name": prod.get("category_name"),
                        "type": "product",
                        "url": f"/product/{prod.get('id')}",
                        "first_image": prod.get("first_image")  # First image from product images
                    }
                    for prod in products_response
                    if query in prod.get("name", "").lower()
                ][:5]  # Limit to 5 suggestions
                suggestions["products"] = products
        except Exception as e:
            logger.error(f"Error searching products: {e}")
        
        # Search clients (company names)
        try:
            clients_response = await client_client.get("/clients/premium")
            if clients_response and isinstance(clients_response, list):
                clients = [
                    {
                        "id": client.get("id"),
                        "name": client.get("name") or client.get("company_name", ""),
                        "city": client.get("city"),
                        "state": client.get("state"),
                        "type": "client",
                        "url": f"/?client={client.get('name', '').lower().replace(' ', '-')}"
                    }
                    for client in clients_response
                    if query in (client.get("name") or client.get("company_name", "")).lower()
                ][:5]  # Limit to 5 suggestions
                suggestions["clients"] = clients
        except Exception as e:
            logger.error(f"Error searching clients: {e}")
    
    except Exception as e:
        logger.error(f"Error in search endpoint: {e}")
    
    return suggestions


@app.get("/api/contact-details")
async def get_contact_details():
    """Get Contact Details (public endpoint for ordpanel)"""
    return await content_client.get("/contact-details")


@app.post("/api/contact-details")
async def create_contact_details(request: Request, current_user: dict = Depends(get_current_user)):
    """Create Contact Details (admin only)"""
    body = await request.json()
    return await content_client.post("/contact-details", json=body)


@app.put("/api/contact-details/{contact_id}")
async def update_contact_details(
    contact_id: str,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Update Contact Details (admin only)"""
    body = await request.json()
    return await content_client.put(f"/contact-details/{contact_id}", json=body)


@app.put("/api/industries/{industry_id}")
async def update_industry(
    industry_id: str,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Update industry"""
    try:
        content_type = request.headers.get("content-type", "")
        if "multipart/form-data" in content_type:
            form = await request.form()
            files = {}
            data = {}
            for key, value in form.items():
                if hasattr(value, 'read'):  # It's a file upload
                    files[key] = (value.filename, await value.read(), value.content_type)
                else:
                    # Convert boolean strings to lowercase for FastAPI to parse correctly
                    if key in ['is_home', 'is_top']:
                        str_value = str(value).lower()
                        data[key] = 'true' if str_value in ('true', '1', 'yes', 'on') else 'false'
                    else:
                        data[key] = value
            
            async with httpx.AsyncClient() as client:
                try:
                    response = await client.put(
                        f"{PRODUCT_SERVICE_URL}/industries/{industry_id}",
                        data=data,
                        files=files,
                        timeout=30.0
                    )
                    response.raise_for_status()
                    return response.json()
                except httpx.HTTPStatusError as e:
                    logger.error(f"Product service error: {e}")
                    try:
                        error_content = e.response.json() if e.response.content else {"detail": str(e)}
                    except (ValueError, json.JSONDecodeError):
                        error_content = {
                            "detail": "Internal server error",
                            "error": f"Server error '{e.response.status_code} {e.response.reason_phrase}' for url '{e.request.url}'"
                        }
                    return JSONResponse(
                        status_code=e.response.status_code,
                        content=error_content,
                        headers={
                            "Access-Control-Allow-Origin": "*",
                            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                            "Access-Control-Allow-Headers": "*",
                        }
                    )
        else:
            body = await request.json()
            async with httpx.AsyncClient() as client:
                response = await client.put(
                    f"{PRODUCT_SERVICE_URL}/industries/{industry_id}",
                    json=body,
                    timeout=30.0
                )
                response.raise_for_status()
                return response.json()
    except httpx.HTTPStatusError as e:
        logger.error(f"Product service error: {e}")
        try:
            error_content = e.response.json() if e.response.content else {"detail": str(e)}
        except (ValueError, json.JSONDecodeError):
            error_content = {"detail": e.response.text if e.response.text else str(e)}
        return JSONResponse(
            status_code=e.response.status_code,
            content=error_content,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"Update industry error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.delete("/api/industries/{industry_id}")
async def delete_industry(industry_id: str, current_user: dict = Depends(get_current_user)):
    """Delete industry"""
    try:
        return await product_client.delete(f"/industries/{industry_id}")
    except httpx.HTTPStatusError as e:
        logger.error(f"Product service error: {e}")
        try:
            error_content = e.response.json() if e.response.content else {"detail": str(e)}
        except (ValueError, json.JSONDecodeError):
            error_content = {"detail": e.response.text if e.response.text else str(e)}
        return JSONResponse(
            status_code=e.response.status_code,
            content=error_content,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"Delete industry error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.post("/api/product-categories")
async def create_product_category(request: Request, current_user: dict = Depends(get_current_user)):
    """Create product category"""
    # Handle multipart/form-data for file uploads
    content_type = request.headers.get("content-type", "")
    if "multipart/form-data" in content_type:
        form = await request.form()
        files = {}
        data = {}
        for key, value in form.items():
            if hasattr(value, 'read'):  # It's a file upload
                files[key] = (value.filename, await value.read(), value.content_type)
            else:
                data[key] = value
        
        # Forward to product service
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{PRODUCT_SERVICE_URL}/product-categories",
                data=data,
                files=files,
                timeout=30.0
            )
            response.raise_for_status()
            return response.json()
    else:
        body = await request.json()
        return await product_client.post("/product-categories", json=body)


@app.get("/api/product-categories")
async def list_product_categories():
    """List product categories (public endpoint for ordpanel)"""
    return await product_client.get("/product-categories")


@app.put("/api/product-categories/{category_id}")
async def update_product_category(
    category_id: str,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Update product category"""
    try:
        content_type = request.headers.get("content-type", "")
        if "multipart/form-data" in content_type:
            form = await request.form()
            files = {}
            data = {}
            for key, value in form.items():
                if hasattr(value, 'read'):  # It's a file upload
                    files[key] = (value.filename, await value.read(), value.content_type)
                else:
                    data[key] = value
            
            async with httpx.AsyncClient() as client:
                try:
                    response = await client.put(
                        f"{PRODUCT_SERVICE_URL}/product-categories/{category_id}",
                        data=data,
                        files=files,
                        timeout=30.0
                    )
                    response.raise_for_status()
                    return response.json()
                except httpx.HTTPStatusError as e:
                    logger.error(f"Product service error: {e}")
                    try:
                        error_content = e.response.json() if e.response.content else {"detail": str(e)}
                    except (ValueError, json.JSONDecodeError):
                        error_content = {
                            "detail": "Internal server error",
                            "error": f"Server error '{e.response.status_code} {e.response.reason_phrase}' for url '{e.request.url}'"
                        }
                    return JSONResponse(
                        status_code=e.response.status_code,
                        content=error_content,
                        headers={
                            "Access-Control-Allow-Origin": "*",
                            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                            "Access-Control-Allow-Headers": "*",
                        }
                    )
        else:
            body = await request.json()
            async with httpx.AsyncClient() as client:
                response = await client.put(
                    f"{PRODUCT_SERVICE_URL}/product-categories/{category_id}",
                    json=body,
                    timeout=30.0
                )
                response.raise_for_status()
                return response.json()
    except httpx.HTTPStatusError as e:
        logger.error(f"Product service error: {e}")
        try:
            error_content = e.response.json() if e.response.content else {"detail": str(e)}
        except (ValueError, json.JSONDecodeError):
            error_content = {"detail": e.response.text if e.response.text else str(e)}
        return JSONResponse(
            status_code=e.response.status_code,
            content=error_content,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"Update product category error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.delete("/api/product-categories/{category_id}")
async def delete_product_category(category_id: str, current_user: dict = Depends(get_current_user)):
    """Delete product category"""
    try:
        return await product_client.delete(f"/product-categories/{category_id}")
    except httpx.HTTPStatusError as e:
        logger.error(f"Product service error: {e}")
        try:
            error_content = e.response.json() if e.response.content else {"detail": str(e)}
        except (ValueError, json.JSONDecodeError):
            error_content = {"detail": e.response.text if e.response.text else str(e)}
        return JSONResponse(
            status_code=e.response.status_code,
            content=error_content,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"Delete product category error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.post("/api/products")
async def create_product(request: Request, current_user: dict = Depends(get_current_user)):
    """Create product with multiple images"""
    # Handle multipart/form-data for file uploads
    content_type = request.headers.get("content-type", "")
    if "multipart/form-data" in content_type:
        form = await request.form()
        files = []
        data = {}
        for key, value in form.items():
            if hasattr(value, 'read'):  # It's a file upload
                if key == "images":  # Multiple files with same key
                    files.append(("images", (value.filename, await value.read(), value.content_type)))
                else:
                    files.append((key, (value.filename, await value.read(), value.content_type)))
            else:
                data[key] = value
        
        # Forward to product service
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{PRODUCT_SERVICE_URL}/products",
                data=data,
                files=files if files else None,
                timeout=30.0
            )
            response.raise_for_status()
            return response.json()
    else:
        body = await request.json()
        return await product_client.post("/products", json=body)


@app.get("/api/products")
async def list_products():
    """List products (public endpoint for ordpanel)"""
    return await product_client.get("/products")


@app.get("/api/products/{product_id}")
async def get_product(product_id: str):
    """Get single product by ID (public endpoint for ordpanel)"""
    return await product_client.get(f"/products/{product_id}")


@app.put("/api/products/{product_id}")
async def update_product(
    product_id: str,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Update product"""
    try:
        content_type = request.headers.get("content-type", "")
        if "multipart/form-data" in content_type:
            form = await request.form()
            files = []
            data = {}
            
            # Process all form fields
            # Starlette's form.items() only returns one value per key
            # For multiple files with same key, we must access _list directly
            # But we must be very careful not to serialize UploadFile objects
            try:
                # Access _list which contains ALL form entries including duplicates
                # This is the only way to get multiple files with the same key
                if hasattr(form, '_list'):
                    form_entries = form._list
                else:
                    # Fallback: use items() if _list doesn't exist (won't work for duplicates)
                    form_entries = [(k, v) for k, v in form.items()]
                
                for entry in form_entries:
                    try:
                        # Handle both tuple and list entries from _list
                        if isinstance(entry, (tuple, list)) and len(entry) >= 2:
                            key, value = entry[0], entry[1]
                        else:
                            continue
                        
                        # Check if it's a file BEFORE any operations that might serialize
                        if hasattr(value, 'read'):
                            # Read file content immediately - converts UploadFile to bytes
                            # This prevents any serialization issues
                            file_content = await value.read()
                            filename = getattr(value, 'filename', 'file') or "file"
                            file_content_type = getattr(value, 'content_type', None) or "application/octet-stream"
                            
                            # For multiple files with same key, append each one
                            # httpx will send them correctly as multiple entries with same key
                            files.append((key, (filename, file_content, file_content_type)))
                        else:
                            # For non-file fields, only keep the first value
                            if key not in data:
                                data[key] = value
                    except Exception as entry_error:
                        # Log error safely without UploadFile objects
                        error_type = type(entry_error).__name__
                        error_msg = str(entry_error)
                        if 'UploadFile' not in error_msg and 'serializable' not in error_msg:
                            logger.error(f"Error processing form entry: {error_type}: {error_msg}")
                        continue
            except Exception as form_error:
                # If form processing fails, log safely and re-raise
                error_type = type(form_error).__name__
                error_msg = str(form_error)
                if 'UploadFile' not in error_msg and 'serializable' not in error_msg:
                    logger.error(f"Error processing form: {error_type}: {error_msg}")
                raise
            
            async with httpx.AsyncClient() as client:
                try:
                    response = await client.put(
                        f"{PRODUCT_SERVICE_URL}/products/{product_id}",
                        data=data,
                        files=files if files else None,
                        timeout=30.0
                    )
                    response.raise_for_status()
                    return response.json()
                except httpx.HTTPStatusError as e:
                    logger.error(f"Product service error: {e}")
                    try:
                        error_content = e.response.json() if e.response.content else {"detail": str(e)}
                    except (ValueError, json.JSONDecodeError):
                        error_content = {
                            "detail": "Internal server error",
                            "error": f"Server error '{e.response.status_code} {e.response.reason_phrase}' for url '{e.request.url}'"
                        }
                    return JSONResponse(
                        status_code=e.response.status_code,
                        content=error_content,
                        headers={
                            "Access-Control-Allow-Origin": "*",
                            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                            "Access-Control-Allow-Headers": "*",
                        }
                    )
        else:
            body = await request.json()
            async with httpx.AsyncClient() as client:
                response = await client.put(
                    f"{PRODUCT_SERVICE_URL}/products/{product_id}",
                    json=body,
                    timeout=30.0
                )
                response.raise_for_status()
                return response.json()
    except httpx.HTTPStatusError as e:
        logger.error(f"Product service error: {e}")
        try:
            error_content = e.response.json() if e.response.content else {"detail": str(e)}
        except (ValueError, json.JSONDecodeError):
            error_content = {"detail": e.response.text if e.response.text else str(e)}
        return JSONResponse(
            status_code=e.response.status_code,
            content=error_content,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        # Don't include UploadFile objects in error logging/serialization
        error_type = type(e).__name__
        error_msg = str(e)
        if "UploadFile" in error_msg or "not JSON serializable" in error_msg:
            error_msg = "Error processing file upload. Please ensure files are valid."
        
        # Log without exc_info=True to avoid serializing exception context with UploadFile objects
        logger.error(f"Update product error: {error_type}: {error_msg}")
        # Try to log filtered traceback if needed
        try:
            import traceback
            tb = traceback.format_exception(type(e), e, e.__traceback__)
            filtered_tb = [line for line in tb if 'UploadFile' not in line]
            if filtered_tb:
                logger.debug(f"Filtered traceback:\n{''.join(filtered_tb)}")
        except Exception:
            pass  # Ignore traceback formatting errors
        
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": error_msg, "type": error_type},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.delete("/api/products/{product_id}")
async def delete_product(product_id: str, current_user: dict = Depends(get_current_user)):
    """Delete product"""
    try:
        return await product_client.delete(f"/products/{product_id}")
    except httpx.HTTPStatusError as e:
        logger.error(f"Product service error: {e}")
        try:
            error_content = e.response.json() if e.response.content else {"detail": str(e)}
        except (ValueError, json.JSONDecodeError):
            error_content = {"detail": e.response.text if e.response.text else str(e)}
        return JSONResponse(
            status_code=e.response.status_code,
            content=error_content,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        logger.error(f"Delete product error: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )


@app.post("/api/client-products")
async def attach_product_to_client(request: Request, current_user: dict = Depends(get_current_user)):
    """Attach product to client"""
    body = await request.json()
    return await product_client.post("/client-products", json=body)


@app.get("/api/clients/{client_id}/products")
async def get_client_products(client_id: str):
    """Get products for a client"""
    return await product_client.get(f"/clients/{client_id}/products")


# Product Images routes
@app.post("/api/product-images")
async def create_product_image(request: Request, current_user: dict = Depends(get_current_user)):
    """Create product image"""
    body = await request.json()
    return await product_client.post("/product-images", json=body)


@app.get("/api/product-images")
async def list_product_images(
    product_id: Optional[str] = None
):
    """List product images (public endpoint for ordpanel)"""
    params = {}
    if product_id:
        params["product_id"] = product_id
    return await product_client.get("/product-images", params=params)


@app.get("/api/product-images/{image_id}")
async def get_product_image(image_id: str):
    """Get product image by ID (public endpoint for ordpanel)"""
    return await product_client.get(f"/product-images/{image_id}")


@app.put("/api/product-images/{image_id}")
async def update_product_image(
    image_id: str,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Update product image"""
    body = await request.json()
    return await product_client.put(f"/product-images/{image_id}", json=body)


@app.delete("/api/product-images/{image_id}")
async def delete_product_image(image_id: str, current_user: dict = Depends(get_current_user)):
    """Delete product image"""
    return await product_client.delete(f"/product-images/{image_id}")


@app.get("/api/products/{product_id}/images")
async def get_product_images(product_id: str):
    """Get all images for a specific product (public endpoint for ordpanel)"""
    images = await product_client.get(f"/products/{product_id}/images")
    return images


@app.get("/api/products/{product_id}/clients")
async def get_product_clients(product_id: str):
    """Get all clients for a specific product (public endpoint for ordpanel)"""
    try:
        # Get client IDs from product service
        result = await product_client.get(f"/products/{product_id}/clients")
        if not result:
            return {"clients": []}
        
        # ServiceClient.get() returns the JSON response directly
        # Product service returns {"client_ids": [...]}
        client_ids = result.get("client_ids", [])
        if not client_ids:
            return {"clients": []}
        
        # Get client details from client service
        clients = []
        for client_id in client_ids:
            try:
                client = await client_client.get(f"/clients/{client_id}")
                if client and isinstance(client, dict):
                    clients.append(client)
            except Exception:
                continue
        
        return {"clients": clients}
    except Exception:
        return {"clients": []}


# Static files proxy - forward image requests to Product Service
@app.get("/static/images/{file_path:path}")
async def serve_static_image(file_path: str, request: Request):
    """Serve static images from Product Service or Client Service (public endpoint)"""
    try:
        # Determine which service to use based on the path
        # Client logos are in /static/images/clients/
        # Product images are in /static/images/products/ or /static/images/industries/
        if file_path.startswith("clients/"):
            # Client Service handles client logos
            service_url = CLIENT_SERVICE_URL
        else:
            # Product Service handles product and industry images
            service_url = PRODUCT_SERVICE_URL
        
        # Forward request to appropriate service
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{service_url}/static/images/{file_path}",
                timeout=30.0
            )
            response.raise_for_status()
            
            # Return the image with appropriate headers
            from fastapi.responses import Response
            return Response(
                content=response.content,
                media_type=response.headers.get("content-type", "image/png"),
                headers={
                    "Cache-Control": "public, max-age=31536000",  # Cache for 1 year
                    "Access-Control-Allow-Origin": "*",
                }
            )
    except httpx.HTTPStatusError as e:
        logger.error(f"Service error serving image: {e}")
        return JSONResponse(
            status_code=e.response.status_code,
            content={"detail": "Image not found"},
            headers={"Access-Control-Allow-Origin": "*"}
        )
    except Exception as e:
        logger.error(f"Error serving static image: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": str(e)},
            headers={"Access-Control-Allow-Origin": "*"}
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

