"""
Permission Service - Dynamic role & permission management
"""
from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, delete
from pydantic import BaseModel, field_validator, field_serializer
from typing import Optional, List, Dict
from datetime import datetime
import sys
import os
import logging
import uuid

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from shared.database import get_db, Base
from shared.models.base import BaseModel as BaseDBModel, BaseModelNoID
from sqlalchemy import Column, String, ForeignKey, Boolean
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
    module = Column(String(50), nullable=True, index=True)  # Clients, Transactions, Leads, etc.
    action_type = Column(String(20), nullable=True, index=True)  # read, create, update, delete
    is_cross_client = Column(Boolean, nullable=False, default=False, index=True)  # Cross-client access flag
    
    __table_args__ = (
        {"comment": "Auto-registered permissions for API endpoints"}
    )


class RolePermission(Base):
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
    module: Optional[str] = None
    action_type: Optional[str] = None
    is_cross_client: Optional[bool] = False


class PermissionResponse(BaseModel):
    id: str
    method: str
    path: str
    description: Optional[str]
    module: Optional[str] = None
    action_type: Optional[str] = None
    is_cross_client: bool = False
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


class RolePermissionBulkAssign(BaseModel):
    role_id: str
    permission_ids: List[str]
    action: str  # "assign", "remove", or "replace"


class RolePermissionModuleAssign(BaseModel):
    role_id: str
    module: str
    actions: List[str]  # ["read", "create", "update", "delete"]
    is_cross_client: bool = False


class PermissionSummary(BaseModel):
    module: str
    read: bool
    create: bool
    update: bool
    delete: bool
    cross_client: bool


class RolePermissionSummary(BaseModel):
    role_id: str
    modules: Dict[str, PermissionSummary]


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
        description=permission_data.description,
        module=permission_data.module,
        action_type=permission_data.action_type,
        is_cross_client=permission_data.is_cross_client or False
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
    module: Optional[str] = None,
    action_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """List all permissions"""
    query = select(Permission)
    if method:
        query = query.where(Permission.method == method.upper())
    if module:
        query = query.where(Permission.module == module)
    if action_type:
        query = query.where(Permission.action_type == action_type)
    
    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    permissions = result.scalars().all()
    
    return [PermissionResponse.model_validate(perm) for perm in permissions]


@app.get("/permissions/by-module/{module}", response_model=List[PermissionResponse])
async def get_permissions_by_module(
    module: str,
    db: AsyncSession = Depends(get_db)
):
    """Get all permissions for a specific module"""
    result = await db.execute(
        select(Permission).where(Permission.module == module)
    )
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
    # Check if assignment exists
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

    # Delete the assignment
    await db.execute(
        delete(RolePermission).where(
            and_(
                RolePermission.role_id == uuid.UUID(assignment.role_id),
                RolePermission.permission_id == uuid.UUID(assignment.permission_id)
            )
        )
    )
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


# Bulk Operations
@app.post("/role-permissions/bulk", status_code=status.HTTP_200_OK)
async def bulk_assign_permissions(
    bulk_data: RolePermissionBulkAssign,
    db: AsyncSession = Depends(get_db)
):
    """Bulk assign or remove permissions from a role"""
    # Validate role exists
    result = await db.execute(select(Role).where(Role.id == uuid.UUID(bulk_data.role_id)))
    role = result.scalar_one_or_none()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Role {bulk_data.role_id} not found"
        )
    
    # Validate all permissions exist
    permission_ids = [uuid.UUID(pid) for pid in bulk_data.permission_ids]
    result = await db.execute(
        select(Permission).where(Permission.id.in_(permission_ids))
    )
    permissions = result.scalars().all()
    found_ids = {str(p.id) for p in permissions}
    missing_ids = set(bulk_data.permission_ids) - found_ids
    
    if missing_ids:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Permissions not found: {', '.join(missing_ids)}"
        )
    
    role_uuid = uuid.UUID(bulk_data.role_id)
    
    if bulk_data.action == "replace":
        # Remove all existing permissions for this role
        await db.execute(
            delete(RolePermission).where(RolePermission.role_id == role_uuid)
        )
        # Then assign new ones
        for perm_id in permission_ids:
            new_assignment = RolePermission(
                role_id=role_uuid,
                permission_id=perm_id
            )
            db.add(new_assignment)
    
    elif bulk_data.action == "assign":
        # Get existing assignments
        result = await db.execute(
            select(RolePermission).where(RolePermission.role_id == role_uuid)
        )
        existing = {str(rp.permission_id) for rp in result.scalars().all()}
        
        # Only add new assignments
        for perm_id in permission_ids:
            if str(perm_id) not in existing:
                new_assignment = RolePermission(
                    role_id=role_uuid,
                    permission_id=perm_id
                )
                db.add(new_assignment)
    
    elif bulk_data.action == "remove":
        # Remove specified permissions
        await db.execute(
            delete(RolePermission).where(
                and_(
                    RolePermission.role_id == role_uuid,
                    RolePermission.permission_id.in_(permission_ids)
                )
            )
        )
    
    await db.commit()
    
    return {
        "message": f"Bulk {bulk_data.action} completed",
        "permissions_processed": len(bulk_data.permission_ids)
    }


@app.post("/role-permissions/by-module", status_code=status.HTTP_200_OK)
async def assign_permissions_by_module(
    module_data: RolePermissionModuleAssign,
    db: AsyncSession = Depends(get_db)
):
    """Assign permissions to a role based on module and actions"""
    # Validate role exists
    result = await db.execute(select(Role).where(Role.id == uuid.UUID(module_data.role_id)))
    role = result.scalar_one_or_none()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Role {module_data.role_id} not found"
        )
    
    # Map action types to HTTP methods
    action_to_method = {
        "read": "GET",
        "create": "POST",
        "update": ["PUT", "PATCH"],
        "delete": "DELETE"
    }
    
    # Build query to find matching permissions
    conditions = [Permission.module == module_data.module]
    
    if module_data.is_cross_client:
        conditions.append(Permission.is_cross_client == True)
    else:
        conditions.append(Permission.is_cross_client == False)
    
    # Get methods for requested actions
    methods = []
    for action in module_data.actions:
        method = action_to_method.get(action.lower())
        if method:
            if isinstance(method, list):
                methods.extend(method)
            else:
                methods.append(method)
    
    if methods:
        conditions.append(Permission.method.in_(methods))
    
    # Find matching permissions
    result = await db.execute(
        select(Permission).where(and_(*conditions))
    )
    permissions = result.scalars().all()
    
    if not permissions:
        return {
            "message": f"No permissions found for module '{module_data.module}' with actions {module_data.actions}",
            "permissions_assigned": 0
        }
    
    # Get existing assignments
    role_uuid = uuid.UUID(module_data.role_id)
    result = await db.execute(
        select(RolePermission).where(RolePermission.role_id == role_uuid)
    )
    existing = {str(rp.permission_id) for rp in result.scalars().all()}
    
    # Assign new permissions
    assigned_count = 0
    for perm in permissions:
        if str(perm.id) not in existing:
            new_assignment = RolePermission(
                role_id=role_uuid,
                permission_id=perm.id
            )
            db.add(new_assignment)
            assigned_count += 1
    
    await db.commit()
    
    return {
        "message": f"Assigned {assigned_count} permissions for module '{module_data.module}'",
        "permissions_assigned": assigned_count
    }


@app.get("/roles/{role_id}/permissions/summary", response_model=RolePermissionSummary)
async def get_role_permissions_summary(
    role_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Get a summary of permissions for a role, grouped by module"""
    # Validate role exists
    result = await db.execute(select(Role).where(Role.id == uuid.UUID(role_id)))
    role = result.scalar_one_or_none()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Role {role_id} not found"
        )
    
    # Get all permissions for this role
    result = await db.execute(
        select(Permission)
        .join(RolePermission, Permission.id == RolePermission.permission_id)
        .where(RolePermission.role_id == uuid.UUID(role_id))
    )
    permissions = result.scalars().all()
    
    # Group by module
    modules_dict: dict[str, dict] = {}
    
    for perm in permissions:
        module = perm.module or "Other"
        if module not in modules_dict:
            modules_dict[module] = {
                "read": False,
                "create": False,
                "update": False,
                "delete": False,
                "cross_client": False
            }
        
        # Update action flags
        action_type = perm.action_type or ""
        if action_type == "read" or perm.method == "GET":
            modules_dict[module]["read"] = True
        elif action_type == "create" or perm.method == "POST":
            modules_dict[module]["create"] = True
        elif action_type == "update" or perm.method in ["PUT", "PATCH"]:
            modules_dict[module]["update"] = True
        elif action_type == "delete" or perm.method == "DELETE":
            modules_dict[module]["delete"] = True
        
        # Update cross-client flag
        if perm.is_cross_client:
            modules_dict[module]["cross_client"] = True
    
    # Convert to PermissionSummary objects
    summary_modules = {}
    for module, data in modules_dict.items():
        summary_modules[module] = PermissionSummary(
            module=module,
            read=data["read"],
            create=data["create"],
            update=data["update"],
            delete=data["delete"],
            cross_client=data["cross_client"]
        )
    
    return RolePermissionSummary(
        role_id=role_id,
        modules=summary_modules
    )


@app.get("/health")
async def health():
    """Health check"""
    return {"status": "healthy", "service": "permission_service"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8008)

