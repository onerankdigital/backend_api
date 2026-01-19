"""
Auth Service - JWT token management and authentication
"""
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, EmailStr
from typing import Optional
import sys
import os

# Add parent directory to path for shared imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from shared.database import get_db
from shared.utils.security import (
    hash_password, verify_password,
    create_access_token, create_refresh_token, decode_token
)
from shared.models.base import BaseModel as BaseDBModel
from sqlalchemy import Column, String, Boolean
import uuid

app = FastAPI(title="Auth Service", version="1.0.0")
security = HTTPBearer()


# Database Models
class User(BaseDBModel):
    __tablename__ = "users"
    
    email = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    status = Column(String, default="active", nullable=False)


# Pydantic Schemas
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    is_admin: bool = False


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class TokenPayload(BaseModel):
    user_id: str
    email: str
    is_admin: bool


# Dependencies
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> User:
    """Get current authenticated user from JWT token"""
    token = credentials.credentials
    try:
        payload = decode_token(token)
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        
        user_id = payload.get("user_id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
        user = result.scalar_one_or_none()
        
        if not user or user.status != "active":
            raise HTTPException(status_code=401, detail="User not found or inactive")
        
        return user
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))


# Routes
@app.post("/register", response_model=dict)
async def register(user_data: UserCreate, db: AsyncSession = Depends(get_db)):
    """Register endpoint is disabled. Only admin can create users via /create-user endpoint."""
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Public registration is disabled. Only administrators can create new users."
    )


@app.post("/create-user", response_model=dict)
async def create_user(
    user_data: UserCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Create a new user (admin only)"""
    # Check if current user is admin
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can create users"
        )
    
    # Check if user exists
    result = await db.execute(select(User).where(User.email == user_data.email))
    existing_user = result.scalar_one_or_none()
    
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Prevent non-admin from creating admin users
    if user_data.is_admin and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can create admin users"
        )
    
    # Create user
    password_hash = hash_password(user_data.password)
    new_user = User(
        id=uuid.uuid4(),
        email=user_data.email,
        password_hash=password_hash,
        is_admin=user_data.is_admin,
        status="active"
    )
    
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    
    return {
        "id": str(new_user.id),
        "email": new_user.email,
        "is_admin": new_user.is_admin,
        "status": new_user.status
    }


@app.post("/login", response_model=TokenResponse)
async def login(credentials: UserLogin, db: AsyncSession = Depends(get_db)):
    """Login and get JWT tokens"""
    # Find user
    result = await db.execute(select(User).where(User.email == credentials.email))
    user = result.scalar_one_or_none()
    
    if not user or user.status != "active":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    # Verify password
    if not verify_password(credentials.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    # Create tokens
    token_data = {
        "user_id": str(user.id),
        "email": user.email,
        "is_admin": user.is_admin
    }
    
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token
    )


@app.post("/refresh", response_model=TokenResponse)
async def refresh_token(request: RefreshTokenRequest):
    """Refresh access token using refresh token"""
    try:
        payload = decode_token(request.refresh_token)
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
        
        # Create new access token
        token_data = {
            "user_id": payload.get("user_id"),
            "email": payload.get("email"),
            "is_admin": payload.get("is_admin", False)
        }
        
        access_token = create_access_token(token_data)
        
        # Optionally create new refresh token
        refresh_token = create_refresh_token(token_data)
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token
        )
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))


@app.get("/me")
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information"""
    return {
        "id": str(current_user.id),
        "email": current_user.email,
        "is_admin": current_user.is_admin,
        "status": current_user.status
    }


@app.get("/users")
async def list_users(
    skip: int = 0,
    limit: int = 100,
    status_filter: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """List all users (admin only)"""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can list users"
        )
    
    query = select(User)
    if status_filter:
        query = query.where(User.status == status_filter)
    
    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    users = result.scalars().all()
    
    return [
        {
            "id": str(user.id),
            "email": user.email,
            "is_admin": user.is_admin,
            "status": user.status,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "updated_at": user.updated_at.isoformat() if user.updated_at else None,
        }
        for user in users
    ]


@app.get("/health")
async def health():
    """Health check"""
    return {"status": "healthy", "service": "auth_service"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)

