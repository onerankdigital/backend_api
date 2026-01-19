"""
Permission Service - Dynamic role & permission management
"""
from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from pydantic import BaseModel, field_validator, field_serializer
from typing import Optional, List
from datetime import datetime
import sys
import os
import logging
import uuid

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from shared.database import get_db
from shared.models.base import BaseModel as BaseDBModel
from sqlalchemy import Column, String, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

app = FastAPI(title="Permission Service", version="1.0.0")

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# Database Models
class Role(BaseDBModel):
    __tablename__ = "roles"
    
    name = Column(String, unique=True, nullable=False, index=True)
    level = Column(String, nullable=False)  # Integer level for hierarchy
    description = Column(String, nullable=True)
    status = Column(String, default="active", nullable=False)


class Permission(BaseDBModel):
    __tablename__ = "permissions"
    
    method = Column(String, nullable=False)  # GET, POST, PUT, DELETE
    path = Column(String, nullable=False, index=True)
    description = Column(String, nullable=True)
    
    __table_args__ = (
        {"comment": "Auto-registered permissions for API endpoints"}
    )


class RolePermission(BaseDBModel):
    __tablename__ = "role_permissions"
    
    role_id = Column(UUID(as_uuid=True), ForeignKey("roles.id"), nullable=False, primary_key=True)
    permission_id = Column(UUID(as_uuid=True), ForeignKey("permissions.id"), nullable=False, primary_key=True)
    
    __table_args__ = (
        {"comment": "Many-to-many relationship between roles and permissions"}
    )


# Pydantic Schemas
class RoleCreate(BaseModel):
    name: str
    level: str
    description: Optional[str] = None
    status: str = "active"


class RoleUpdate(BaseModel):
    name: Optional[str] = None
    level: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None


class RoleResponse(BaseModel):
    id: str
    name: str
    level: str
    description: Optional[str]
    status: str
    created_at: datetime
    updated_at: datetime
    
    @field_validator('id', mode='before')
    @classmethod
    def convert_uuid_to_str(cls, v):
        """Convert UUID object to string"""
        if isinstance(v, uuid.UUID):
            return str(v)
        return v
    
    class Config:
        from_attributes = True


class PermissionCreate(BaseModel):
    method: str
    path: str
    description: Optional[str] = None


class PermissionResponse(BaseModel):
    id: str
    method: str
    path: str
    description: Optional[str]
    created_at: datetime
    updated_at: datetime
    
    @field_validator('id', mode='before')
    @classmethod
    def convert_uuid_to_str(cls, v):
        """Convert UUID object to string"""
        if isinstance(v, uuid.UUID):
            return str(v)
        return v
    
    class Config:
        from_attributes = True


class RolePermissionAssign(BaseModel):
    role_id: str
    permission_id: str


# Routes - Roles
@app.post("/roles", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)
async def create_role(role_data: RoleCreate, db: AsyncSession = Depends(get_db)):
    """Create a new role"""
    try:
        # Check if role name exists
        result = await db.execute(select(Role).where(Role.name == role_data.name))
        existing = result.scalar_one_or_none()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Role '{role_data.name}' already exists"
            )
        
        new_role = Role(
            name=role_data.name,
            level=role_data.level,
            description=role_data.description,
            status=role_data.status
        )
        
        db.add(new_role)
        await db.commit()
        await db.refresh(new_role)
        
        return RoleResponse.model_validate(new_role)
    except HTTPException:
        # Re-raise HTTP exceptions (like duplicate role name)
        raise
    except Exception as e:
        # Rollback transaction on error
        await db.rollback()
        # Log the full error for debugging
        logger = logging.getLogger(__name__)
        logger.error(f"Error creating role: {e}", exc_info=True)
        # Return a user-friendly error message
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create role: {str(e)}"
        )


@app.get("/roles", response_model=List[RoleResponse])
async def list_roles(
    skip: int = 0,
    limit: int = 100,
    status_filter: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """List all roles"""
    query = select(Role)
    if status_filter:
        query = query.where(Role.status == status_filter)
    
    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    roles = result.scalars().all()
    
    return [RoleResponse.model_validate(role) for role in roles]


@app.get("/roles/{role_id}", response_model=RoleResponse)
async def get_role(role_id: str, db: AsyncSession = Depends(get_db)):
    """Get role by ID"""
    result = await db.execute(select(Role).where(Role.id == uuid.UUID(role_id)))
    role = result.scalar_one_or_none()
    
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Role {role_id} not found"
        )
    
    return RoleResponse.model_validate(role)


@app.put("/roles/{role_id}", response_model=RoleResponse)
async def update_role(
    role_id: str,
    role_data: RoleUpdate,
    db: AsyncSession = Depends(get_db)
):
    """Update role"""
    result = await db.execute(select(Role).where(Role.id == uuid.UUID(role_id)))
    role = result.scalar_one_or_none()
    
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Role {role_id} not found"
        )
    
    if role_data.name is not None:
        # Check uniqueness if name is being changed
        result = await db.execute(
            select(Role).where(
                and_(Role.name == role_data.name, Role.id != uuid.UUID(role_id))
            )
        )
        existing = result.scalar_one_or_none()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Role '{role_data.name}' already exists"
            )
        role.name = role_data.name
    
    if role_data.level is not None:
        role.level = role_data.level
    if role_data.description is not None:
        role.description = role_data.description
    if role_data.status is not None:
        role.status = role_data.status
    
    await db.commit()
    await db.refresh(role)
    
    return RoleResponse.model_validate(role)


# Routes - Permissions
@app.post("/permissions", response_model=PermissionResponse, status_code=status.HTTP_201_CREATED)
async def create_permission(
    permission_data: PermissionCreate,
    db: AsyncSession = Depends(get_db)
):
    """Create or get existing permission (auto-registration)"""
    # Check if permission exists
    result = await db.execute(
        select(Permission).where(
            and_(
                Permission.method == permission_data.method,
                Permission.path == permission_data.path
            )
        )
    )
    existing = result.scalar_one_or_none()
    
    if existing:
        return PermissionResponse.model_validate(existing)
    
    new_permission = Permission(
        method=permission_data.method,
        path=permission_data.path,
        description=permission_data.description
    )
    
    db.add(new_permission)
    await db.commit()
    await db.refresh(new_permission)
    
    return PermissionResponse.model_validate(new_permission)


@app.get("/permissions", response_model=List[PermissionResponse])
async def list_permissions(
    skip: int = 0,
    limit: int = 100,
    method: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """List all permissions"""
    query = select(Permission)
    if method:
        query = query.where(Permission.method == method.upper())
    
    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    permissions = result.scalars().all()
    
    return [PermissionResponse.model_validate(perm) for perm in permissions]


# Routes - Role Permissions
@app.post("/role-permissions", status_code=status.HTTP_201_CREATED)
async def assign_permission_to_role(
    assignment: RolePermissionAssign,
    db: AsyncSession = Depends(get_db)
):
    """Assign permission to role"""
    # Validate role exists
    result = await db.execute(select(Role).where(Role.id == uuid.UUID(assignment.role_id)))
    role = result.scalar_one_or_none()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Role {assignment.role_id} not found"
        )
    
    # Validate permission exists
    result = await db.execute(
        select(Permission).where(Permission.id == uuid.UUID(assignment.permission_id))
    )
    permission = result.scalar_one_or_none()
    if not permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Permission {assignment.permission_id} not found"
        )
    
    # Check if already assigned
    result = await db.execute(
        select(RolePermission).where(
            and_(
                RolePermission.role_id == uuid.UUID(assignment.role_id),
                RolePermission.permission_id == uuid.UUID(assignment.permission_id)
            )
        )
    )
    existing = result.scalar_one_or_none()
    if existing:
        return {"message": "Permission already assigned to role"}
    
    new_assignment = RolePermission(
        role_id=uuid.UUID(assignment.role_id),
        permission_id=uuid.UUID(assignment.permission_id)
    )
    
    db.add(new_assignment)
    await db.commit()
    
    return {"message": "Permission assigned to role"}


@app.delete("/role-permissions", status_code=status.HTTP_204_NO_CONTENT)
async def remove_permission_from_role(
    assignment: RolePermissionAssign,
    db: AsyncSession = Depends(get_db)
):
    """Remove permission from role"""
    result = await db.execute(
        select(RolePermission).where(
            and_(
                RolePermission.role_id == uuid.UUID(assignment.role_id),
                RolePermission.permission_id == uuid.UUID(assignment.permission_id)
            )
        )
    )
    assignment_obj = result.scalar_one_or_none()
    
    if not assignment_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Permission not assigned to role"
        )
    
    await db.delete(assignment_obj)
    await db.commit()
    
    return None


@app.get("/roles/{role_id}/permissions", response_model=List[PermissionResponse])
async def get_role_permissions(role_id: str, db: AsyncSession = Depends(get_db)):
    """Get all permissions for a role"""
    result = await db.execute(
        select(Permission)
        .join(RolePermission, Permission.id == RolePermission.permission_id)
        .where(RolePermission.role_id == uuid.UUID(role_id))
    )
    permissions = result.scalars().all()
    
    return [PermissionResponse.model_validate(perm) for perm in permissions]


@app.get("/permissions/{permission_id}/roles", response_model=List[RoleResponse])
async def get_permission_roles(permission_id: str, db: AsyncSession = Depends(get_db)):
    """Get all roles with a permission"""
    result = await db.execute(
        select(Role)
        .join(RolePermission, Role.id == RolePermission.role_id)
        .where(RolePermission.permission_id == uuid.UUID(permission_id))
    )
    roles = result.scalars().all()
    
    return [RoleResponse.model_validate(role) for role in roles]


@app.get("/health")
async def health():
    """Health check"""
    return {"status": "healthy", "service": "permission_service"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8008)

