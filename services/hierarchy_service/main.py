"""
Hierarchy Service - Hierarchical RBAC enforcement
"""
from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_
from sqlalchemy.orm import aliased
from pydantic import BaseModel
from typing import Optional, List, Set
from datetime import datetime
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from shared.database import get_db
from shared.models.base import BaseModel as BaseDBModel
from sqlalchemy import Column, String, ForeignKey, delete
from sqlalchemy.dialects.postgresql import UUID
import uuid

app = FastAPI(title="Hierarchy Service", version="1.0.0")


# Database Models
class UserClient(BaseDBModel):
    __tablename__ = "user_clients"
    
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    client_id = Column(String, ForeignKey("clients.client_id"), nullable=False, index=True)
    role_id = Column(UUID(as_uuid=True), ForeignKey("roles.id"), nullable=False)
    reports_to_user_client_id = Column(UUID(as_uuid=True), ForeignKey("user_clients.id"), nullable=True)
    status = Column(String, default="active", nullable=False)


class UserClientHierarchy(BaseDBModel):
    """Closure table for efficient hierarchy queries"""
    __tablename__ = "user_client_hierarchy"
    
    ancestor_user_client_id = Column(
        UUID(as_uuid=True),
        ForeignKey("user_clients.id"),
        nullable=False,
        primary_key=True
    )
    descendant_user_client_id = Column(
        UUID(as_uuid=True),
        ForeignKey("user_clients.id"),
        nullable=False,
        primary_key=True
    )
    depth = Column(String, nullable=False)  # Integer as string
    
    __table_args__ = (
        {"comment": "Closure table for user-client hierarchy (includes self-references)"}
    )


# Pydantic Schemas
class HierarchyNode(BaseModel):
    user_client_id: str
    user_id: str
    client_id: str
    role_id: str
    reports_to_user_client_id: Optional[str]
    depth: int


class HierarchyTree(BaseModel):
    root: HierarchyNode
    children: List['HierarchyTree'] = []


HierarchyTree.model_rebuild()


# Helper Functions
async def rebuild_hierarchy_for_client(
    client_id: str,
    db: AsyncSession
):
    """Rebuild hierarchy closure table for a client"""
    # Get all active user_clients for this client
    result = await db.execute(
        select(UserClient).where(
            and_(
                UserClient.client_id == client_id,
                UserClient.status == "active"
            )
        )
    )
    user_clients = result.scalars().all()
    
    # Clear existing hierarchy for this client
    user_client_ids = [uc.id for uc in user_clients]
    if user_client_ids:
        # Delete existing entries
        from sqlalchemy import delete
        await db.execute(
            delete(UserClientHierarchy).where(
                or_(
                    UserClientHierarchy.ancestor_user_client_id.in_(user_client_ids),
                    UserClientHierarchy.descendant_user_client_id.in_(user_client_ids)
                )
            )
        )
    
    # Build closure table using recursive CTE approach
    # For each user_client, add self-reference (depth 0)
    for uc in user_clients:
        self_ref = UserClientHierarchy(
            ancestor_user_client_id=uc.id,
            descendant_user_client_id=uc.id,
            depth="0"
        )
        db.add(self_ref)
    
    # Build parent-child relationships
    for uc in user_clients:
        if uc.reports_to_user_client_id:
            # Add direct parent (depth 1)
            direct_parent = UserClientHierarchy(
                ancestor_user_client_id=uc.reports_to_user_client_id,
                descendant_user_client_id=uc.id,
                depth="1"
            )
            db.add(direct_parent)
            
            # Add all ancestors (transitive closure)
            # Get all ancestors of the parent
            result = await db.execute(
                select(UserClientHierarchy).where(
                    UserClientHierarchy.descendant_user_client_id == uc.reports_to_user_client_id
                )
            )
            ancestors = result.scalars().all()
            
            for ancestor in ancestors:
                if ancestor.ancestor_user_client_id != uc.id:  # Avoid cycles
                    new_depth = int(ancestor.depth) + 1
                    transitive = UserClientHierarchy(
                        ancestor_user_client_id=ancestor.ancestor_user_client_id,
                        descendant_user_client_id=uc.id,
                        depth=str(new_depth)
                    )
                    db.add(transitive)
    
    await db.commit()


async def get_descendants(
    user_client_id: str,
    client_id: str,
    db: AsyncSession,
    include_self: bool = False
) -> Set[str]:
    """Get all descendant user_client IDs"""
    query = select(UserClientHierarchy.descendant_user_client_id).where(
        UserClientHierarchy.ancestor_user_client_id == uuid.UUID(user_client_id)
    )
    
    if not include_self:
        query = query.where(UserClientHierarchy.depth != "0")
    
    result = await db.execute(query)
    descendant_ids = {str(row[0]) for row in result.all()}
    
    return descendant_ids


async def can_access_user_client(
    requester_user_client_id: str,
    target_user_client_id: str,
    client_id: str,
    db: AsyncSession
) -> bool:
    """Check if requester can access target user_client"""
    # Check if target is a descendant of requester
    result = await db.execute(
        select(UserClientHierarchy).where(
            and_(
                UserClientHierarchy.ancestor_user_client_id == uuid.UUID(requester_user_client_id),
                UserClientHierarchy.descendant_user_client_id == uuid.UUID(target_user_client_id)
            )
        )
    )
    return result.scalar_one_or_none() is not None


# Routes
@app.post("/hierarchy/rebuild/{client_id}", status_code=status.HTTP_200_OK)
async def rebuild_hierarchy(
    client_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Rebuild hierarchy for a client"""
    await rebuild_hierarchy_for_client(client_id, db)
    return {"message": f"Hierarchy rebuilt for client {client_id}"}


@app.get("/hierarchy/{user_client_id}/descendants", response_model=List[str])
async def get_descendant_user_clients(
    user_client_id: str,
    include_self: bool = False,
    db: AsyncSession = Depends(get_db)
):
    """Get all descendant user_client IDs"""
    # Get client_id for this user_client
    result = await db.execute(
        select(UserClient.client_id).where(UserClient.id == uuid.UUID(user_client_id))
    )
    client_id_row = result.scalar_one_or_none()
    if not client_id_row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User-client {user_client_id} not found"
        )
    
    client_id = client_id_row[0]
    descendants = await get_descendants(user_client_id, client_id, db, include_self)
    
    return list(descendants)


@app.get("/hierarchy/{user_client_id}/tree", response_model=dict)
async def get_hierarchy_tree(
    user_client_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Get hierarchy tree starting from a user_client"""
    # Get user_client info
    result = await db.execute(
        select(UserClient).where(UserClient.id == uuid.UUID(user_client_id))
    )
    user_client = result.scalar_one_or_none()
    
    if not user_client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User-client {user_client_id} not found"
        )
    
    # Get all descendants
    descendants = await get_descendants(user_client_id, user_client.client_id, db, include_self=True)
    
    # Build tree structure
    result = await db.execute(
        select(UserClient).where(UserClient.id.in_([uuid.UUID(d) for d in descendants]))
    )
    user_clients = {str(uc.id): uc for uc in result.scalars().all()}
    
    def build_tree(node_id: str, depth: int = 0) -> dict:
        uc = user_clients[node_id]
        children_ids = [
            str(uc_child.id) for uc_child in user_clients.values()
            if uc_child.reports_to_user_client_id == uc.id
        ]
        
        return {
            "user_client_id": str(uc.id),
            "user_id": str(uc.user_id),
            "client_id": uc.client_id,
            "role_id": str(uc.role_id),
            "reports_to_user_client_id": str(uc.reports_to_user_client_id) if uc.reports_to_user_client_id else None,
            "depth": depth,
            "children": [build_tree(cid, depth + 1) for cid in children_ids]
        }
    
    return build_tree(user_client_id)


@app.post("/hierarchy/check-access")
async def check_access(
    requester_user_client_id: str,
    target_user_client_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Check if requester can access target"""
    # Get client_id
    result = await db.execute(
        select(UserClient.client_id).where(UserClient.id == uuid.UUID(requester_user_client_id))
    )
    client_id_row = result.scalar_one_or_none()
    if not client_id_row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Requester user-client {requester_user_client_id} not found"
        )
    
    client_id = client_id_row[0]
    can_access = await can_access_user_client(
        requester_user_client_id,
        target_user_client_id,
        client_id,
        db
    )
    
    return {
        "can_access": can_access,
        "requester_user_client_id": requester_user_client_id,
        "target_user_client_id": target_user_client_id
    }


@app.get("/health")
async def health():
    """Health check"""
    return {"status": "healthy", "service": "hierarchy_service"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8009)

