"""
Auth Service - JWT token management and authentication
"""
from fastapi import FastAPI, Depends, HTTPException, status, Body
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

    name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    status = Column(String, default="active", nullable=False)


# Pydantic Schemas
class UserCreate(BaseModel):
    name: str
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
        name=user_data.name,
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
        "name": new_user.name,
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
    # Normalize is_admin to boolean (database may have it as string "true"/"false")
    is_admin_bool = False
    if isinstance(user.is_admin, bool):
        is_admin_bool = user.is_admin
    elif isinstance(user.is_admin, str):
        is_admin_bool = user.is_admin.lower() == "true"
    else:
        is_admin_bool = bool(user.is_admin)
    
    token_data = {
        "user_id": str(user.id),
        "email": user.email,
        "is_admin": is_admin_bool
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
    # Normalize is_admin to boolean (database may have it as string "true"/"false")
    is_admin_bool = False
    if isinstance(current_user.is_admin, bool):
        is_admin_bool = current_user.is_admin
    elif isinstance(current_user.is_admin, str):
        is_admin_bool = current_user.is_admin.lower() == "true"
    else:
        is_admin_bool = bool(current_user.is_admin)
    
    return {
        "id": str(current_user.id),
        "name": current_user.name,
        "email": current_user.email,
        "is_admin": is_admin_bool,
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


@app.delete("/users/{user_id}")
async def delete_user(
    user_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Delete a user (admin only) - Admins can delete any user including other admins"""
    # Check if current user is admin
    is_admin_bool = False
    if isinstance(current_user.is_admin, bool):
        is_admin_bool = current_user.is_admin
    elif isinstance(current_user.is_admin, str):
        is_admin_bool = current_user.is_admin.lower() == "true"
    else:
        is_admin_bool = bool(current_user.is_admin)
    
    if not is_admin_bool:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can delete users"
        )
    
    # Prevent self-deletion
    if str(current_user.id) == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot delete your own account"
        )
    
    # Find the user to delete
    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user_to_delete = result.scalar_one_or_none()
    
    if not user_to_delete:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found"
        )
    
    # Delete the user (admins can delete any user including other admins)
    await db.delete(user_to_delete)
    await db.commit()
    
    return {
        "message": f"User {user_to_delete.email} deleted successfully",
        "deleted_user_id": str(user_to_delete.id),
        "was_admin": user_to_delete.is_admin
    }


@app.put("/users/{user_id}")
async def update_user(
    user_id: str,
    name: str = Body(...),
    email: EmailStr = Body(...),
    status: str = Body(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update user details (name, email, status) - Admin only"""
    # Check if current user is admin
    if isinstance(current_user.is_admin, bool):
        is_admin_bool = current_user.is_admin
    elif isinstance(current_user.is_admin, str):
        is_admin_bool = current_user.is_admin.lower() == "true"
    else:
        is_admin_bool = bool(current_user.is_admin)

    if not is_admin_bool:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can update users"
        )

    # Find the user to update
    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user_to_update = result.scalar_one_or_none()

    if not user_to_update:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found"
        )

    # Check if email is being changed to an existing email
    if email != user_to_update.email:
        result = await db.execute(select(User).where(User.email == email))
        existing_user = result.scalar_one_or_none()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already exists"
            )

    # Update user fields
    user_to_update.name = name
    user_to_update.email = email
    user_to_update.status = status

    await db.commit()
    await db.refresh(user_to_update)

    return {
        "message": "User updated successfully",
        "user": {
            "id": str(user_to_update.id),
            "name": user_to_update.name,
            "email": user_to_update.email,
            "status": user_to_update.status,
            "is_admin": user_to_update.is_admin
        }
    }


@app.post("/users/{user_id}/change-password")
async def change_user_password(
    user_id: str,
    new_password: str = Body(..., embed=True),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Change a user's password - Users can change their own password, admins can change any password"""
    # Check if current user is admin
    if isinstance(current_user.is_admin, bool):
        is_admin_bool = current_user.is_admin
    elif isinstance(current_user.is_admin, str):
        is_admin_bool = current_user.is_admin.lower() == "true"
    else:
        is_admin_bool = bool(current_user.is_admin)

    # Find the user
    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user_to_update = result.scalar_one_or_none()

    if not user_to_update:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found"
        )

    # Allow if: 1) User is admin, OR 2) User is changing their own password
    if not is_admin_bool and str(current_user.id) != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only change your own password. Administrators can change any user's password."
        )

    # Hash the new password
    password_hash = hash_password(new_password)
    user_to_update.password_hash = password_hash

    await db.commit()

    return {
        "message": "Password changed successfully",
        "user_id": str(user_to_update.id)
    }


@app.get("/health")
async def health():
    """Health check"""
    return {"status": "healthy", "service": "auth_service"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)

