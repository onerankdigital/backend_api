"""
User Service - Multi-client user management
"""
from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from sqlalchemy.orm import selectinload
from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional, List
from datetime import datetime
import sys
import os
import logging

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from shared.database import get_db
from shared.models.base import BaseModel as BaseDBModel, BaseModelNoID
from shared.utils.http_client import ServiceClient
from sqlalchemy import Column, String, ForeignKey, Boolean
from sqlalchemy.dialects.postgresql import UUID
import uuid

app = FastAPI(title="User Service", version="1.0.0")

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Service clients
AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL", "http://localhost:8001")
auth_client = ServiceClient(AUTH_SERVICE_URL)


# Database Models
class User(BaseDBModel):
    __tablename__ = "users"
    
    email = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    status = Column(String, default="active", nullable=False)


class Client(BaseModelNoID):
    __tablename__ = "clients"
    
    client_id = Column(String, primary_key=True, unique=True, nullable=False, index=True)
    name = Column(String, nullable=False)
    status = Column(String, default="active", nullable=False)


class Role(BaseDBModel):
    __tablename__ = "roles"
    
    name = Column(String, unique=True, nullable=False)
    level = Column(String, nullable=False)  # Integer as string for flexibility
    description = Column(String, nullable=True)
    status = Column(String, default="active", nullable=False)


class UserClient(BaseDBModel):
    __tablename__ = "user_clients"
    
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    client_id = Column(String, ForeignKey("clients.client_id"), nullable=False, index=True)
    role_id = Column(UUID(as_uuid=True), ForeignKey("roles.id"), nullable=False)
    reports_to_user_client_id = Column(UUID(as_uuid=True), ForeignKey("user_clients.id"), nullable=True)
    status = Column(String, default="active", nullable=False)
    
    __table_args__ = (
        {"comment": "Junction table for user-client relationships with roles and hierarchy"}
    )


# Pydantic Schemas
class UserClientCreate(BaseModel):
    user_id: str
    client_id: str
    role_id: str
    reports_to_user_client_id: Optional[str] = None
    status: str = "active"


class UserClientUpdate(BaseModel):
    role_id: Optional[str] = None
    reports_to_user_client_id: Optional[str] = None
    status: Optional[str] = None


class UserClientResponse(BaseModel):
    id: str
    user_id: str
    client_id: str
    role_id: str
    reports_to_user_client_id: Optional[str] = None
    status: str
    created_at: datetime
    updated_at: datetime
    
    @field_validator('id', 'user_id', 'role_id', 'reports_to_user_client_id', mode='before')
    @classmethod
    def convert_uuid_to_str(cls, v):
        """Convert UUID object to string"""
        if v is None:
            return None
        if isinstance(v, uuid.UUID):
            return str(v)
        return v
    
    class Config:
        from_attributes = True


class UserClientsResponse(BaseModel):
    id: str
    user_id: str
    email: str
    client_id: str
    client_name: str
    role_id: str
    role_name: str
    reports_to_user_client_id: Optional[str] = None
    status: str
    
    @field_validator('id', 'user_id', 'role_id', 'reports_to_user_client_id', mode='before')
    @classmethod
    def convert_uuid_to_str(cls, v):
        """Convert UUID object to string"""
        if v is None:
            return None
        if isinstance(v, uuid.UUID):
            return str(v)
        return v


# Routes
@app.post("/user-clients", response_model=UserClientResponse, status_code=status.HTTP_201_CREATED)
async def create_user_client(
    user_client_data: UserClientCreate,
    db: AsyncSession = Depends(get_db)
):
    """Assign user to client with role"""
    # Validate user exists
    result = await db.execute(
        select(User).where(User.id == uuid.UUID(user_client_data.user_id))
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_client_data.user_id} not found"
        )
    
    # Validate client exists
    result = await db.execute(
        select(Client).where(Client.client_id == user_client_data.client_id)
    )
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Client {user_client_data.client_id} not found"
        )
    
    # Validate role exists
    result = await db.execute(
        select(Role).where(Role.id == uuid.UUID(user_client_data.role_id))
    )
    role = result.scalar_one_or_none()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Role {user_client_data.role_id} not found"
        )
    
    # Check if user-client relationship already exists
    result = await db.execute(
        select(UserClient).where(
            and_(
                UserClient.user_id == uuid.UUID(user_client_data.user_id),
                UserClient.client_id == user_client_data.client_id,
                UserClient.status != "deleted"
            )
        )
    )
    existing = result.scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already assigned to this client"
        )
    
    # Validate reports_to if provided
    reports_to_id = None
    if user_client_data.reports_to_user_client_id:
        reports_to_id = uuid.UUID(user_client_data.reports_to_user_client_id)
        result = await db.execute(
            select(UserClient).where(UserClient.id == reports_to_id)
        )
        reports_to = result.scalar_one_or_none()
        if not reports_to:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Reports to user_client {user_client_data.reports_to_user_client_id} not found"
            )
    
    # Create user-client relationship
    try:
        new_user_client = UserClient(
            user_id=uuid.UUID(user_client_data.user_id),
            client_id=user_client_data.client_id,
            role_id=uuid.UUID(user_client_data.role_id),
            reports_to_user_client_id=reports_to_id,
            status=user_client_data.status
        )
        
        db.add(new_user_client)
        await db.commit()
        await db.refresh(new_user_client)
        
        return UserClientResponse.model_validate(new_user_client)
    except HTTPException:
        # Re-raise HTTP exceptions (like duplicate assignment)
        raise
    except Exception as e:
        # Rollback transaction on error
        await db.rollback()
        # Log the full error for debugging
        logger.error(f"Error creating user-client: {e}", exc_info=True)
        # Return a user-friendly error message
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create user-client: {str(e)}"
        )


@app.get("/user-clients/{user_client_id}", response_model=UserClientResponse)
async def get_user_client(
    user_client_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Get user-client relationship by ID"""
    result = await db.execute(
        select(UserClient).where(UserClient.id == uuid.UUID(user_client_id))
    )
    user_client = result.scalar_one_or_none()
    
    if not user_client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User-client relationship {user_client_id} not found"
        )
    
    return UserClientResponse.model_validate(user_client)


@app.get("/user-clients", response_model=List[UserClientsResponse])
async def list_user_clients(
    user_id: Optional[str] = None,
    client_id: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db)
):
    """List user-client relationships with optional filtering"""
    query = select(
        UserClient,
        User.email,
        Client.name.label("client_name"),
        Role.name.label("role_name")
    ).join(
        User, UserClient.user_id == User.id
    ).join(
        Client, UserClient.client_id == Client.client_id
    ).join(
        Role, UserClient.role_id == Role.id
    )
    
    if user_id:
        query = query.where(UserClient.user_id == uuid.UUID(user_id))
    if client_id:
        query = query.where(UserClient.client_id == client_id)
    
    query = query.offset(skip).limit(limit)
    
    result = await db.execute(query)
    rows = result.all()
    
    return [
        UserClientsResponse(
            id=str(row.UserClient.id),
            user_id=str(row.UserClient.user_id),
            email=row.email,
            client_id=row.UserClient.client_id,
            client_name=row.client_name,
            role_id=str(row.UserClient.role_id),
            role_name=row.role_name,
            reports_to_user_client_id=str(row.UserClient.reports_to_user_client_id) if row.UserClient.reports_to_user_client_id else None,
            status=row.UserClient.status
        )
        for row in rows
    ]


@app.put("/user-clients/{user_client_id}", response_model=UserClientResponse)
async def update_user_client(
    user_client_id: str,
    user_client_data: UserClientUpdate,
    db: AsyncSession = Depends(get_db)
):
    """Update user-client relationship"""
    result = await db.execute(
        select(UserClient).where(UserClient.id == uuid.UUID(user_client_id))
    )
    user_client = result.scalar_one_or_none()
    
    if not user_client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User-client relationship {user_client_id} not found"
        )
    
    # Update fields
    if user_client_data.role_id is not None:
        # Validate role exists
        result = await db.execute(
            select(Role).where(Role.id == uuid.UUID(user_client_data.role_id))
        )
        role = result.scalar_one_or_none()
        if not role:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Role {user_client_data.role_id} not found"
            )
        user_client.role_id = uuid.UUID(user_client_data.role_id)
    
    if user_client_data.reports_to_user_client_id is not None:
        reports_to_id = uuid.UUID(user_client_data.reports_to_user_client_id)
        result = await db.execute(
            select(UserClient).where(UserClient.id == reports_to_id)
        )
        reports_to = result.scalar_one_or_none()
        if not reports_to:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Reports to user_client {user_client_data.reports_to_user_client_id} not found"
            )
        user_client.reports_to_user_client_id = reports_to_id
    
    if user_client_data.status is not None:
        user_client.status = user_client_data.status
    
    await db.commit()
    await db.refresh(user_client)
    
    return UserClientResponse.model_validate(user_client)


@app.get("/users/{user_id}/clients", response_model=List[dict])
async def get_user_clients(
    user_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Get all clients for a user"""
    result = await db.execute(
        select(UserClient, Client.name)
        .join(Client, UserClient.client_id == Client.client_id)
        .where(
            and_(
                UserClient.user_id == uuid.UUID(user_id),
                UserClient.status == "active"
            )
        )
    )
    rows = result.all()
    
    return [
        {
            "client_id": row.UserClient.client_id,
            "client_name": row.name,
            "user_client_id": str(row.UserClient.id),
            "role_id": str(row.UserClient.role_id)
        }
        for row in rows
    ]


@app.get("/health")
async def health():
    """Health check"""
    return {"status": "healthy", "service": "user_service"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)

