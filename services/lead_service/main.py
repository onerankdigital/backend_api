"""
Lead Service - Lead storage and management with API key ingestion
"""
from fastapi import FastAPI, Depends, HTTPException, status, Header
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from pydantic import BaseModel, EmailStr
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
import sys
import os
import logging

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from shared.database import get_db
from shared.models.base import BaseModel as BaseDBModel, BaseModelNoID
from shared.utils.security import hash_api_key, generate_api_key, encrypt_secret, decrypt_secret
from shared.utils.http_client import ServiceClient
from shared.utils.validation import (
    validate_email_format, validate_phone_format, normalize_phone, is_suspicious_lead
)
from sqlalchemy import Column, String, ForeignKey, JSON, DateTime
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.sql import func
import uuid

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

app = FastAPI(title="Lead Service", version="1.0.0")

# Service clients
INTEGRATION_SERVICE_URL = os.getenv("INTEGRATION_SERVICE_URL", "http://localhost:8006")
integration_client = ServiceClient(INTEGRATION_SERVICE_URL)


# Database Models
class Client(BaseModelNoID):
    __tablename__ = "clients"
    
    client_id = Column(String, primary_key=True, unique=True, nullable=False, index=True)
    name = Column(String, nullable=False)
    status = Column(String, default="active", nullable=False)


class UserClient(BaseDBModel):
    __tablename__ = "user_clients"
    
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    client_id = Column(String, ForeignKey("clients.client_id"), nullable=False, index=True)
    role_id = Column(UUID(as_uuid=True), ForeignKey("roles.id"), nullable=False)
    reports_to_user_client_id = Column(UUID(as_uuid=True), ForeignKey("user_clients.id"), nullable=True)
    status = Column(String, default="active", nullable=False)


class Lead(BaseDBModel):
    __tablename__ = "leads"
    
    client_id = Column(String, ForeignKey("clients.client_id"), nullable=False, index=True)
    created_by_user_client_id = Column(UUID(as_uuid=True), ForeignKey("user_clients.id"), nullable=True)
    name = Column(String, nullable=True)
    email = Column(String, nullable=True, index=True)
    phone = Column(String, nullable=True, index=True)
    source = Column(String, nullable=False, index=True)  # facebook, instagram, website, etc.
    lead_reference_id = Column(String, nullable=True, index=True)  # External reference ID
    raw_payload = Column(JSONB, nullable=True)  # Store unknown fields here


class ClientAPIKey(BaseDBModel):
    __tablename__ = "client_api_keys"
    
    client_id = Column(String, ForeignKey("clients.client_id"), nullable=False, index=True)
    key_hash = Column(String, nullable=False, unique=True, index=True)
    key_prefix = Column(String, nullable=False, index=True)
    scopes = Column(JSONB, nullable=True)  # JSON array of scopes
    status = Column(String, default="active", nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)


# Pydantic Schemas
class LeadCreate(BaseModel):
    client_id: str
    name: Optional[str] = None
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    source: str
    lead_reference_id: Optional[str] = None
    raw_payload: Optional[Dict[str, Any]] = None


class OrdPanelLeadCreate(BaseModel):
    """Lead creation for ordpanel (no client_id, always source=ordpanel)"""
    name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    product_name: Optional[str] = None  # Product name for product page leads
    client_name: Optional[str] = None  # Client name for client page leads
    message: Optional[str] = None  # Message/description field
    form_type: Optional[str] = None  # 'product' or 'client' - to identify form type


class LeadResponse(BaseModel):
    id: str
    client_id: str
    created_by_user_client_id: Optional[str] = None
    name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    source: str
    lead_reference_id: Optional[str] = None
    raw_payload: Optional[Dict[str, Any]] = None
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class APIKeyCreate(BaseModel):
    client_id: str
    scopes: Optional[List[str]] = None
    expires_at: Optional[datetime] = None


class APIKeyUpdate(BaseModel):
    status: Optional[str] = None
    scopes: Optional[List[str]] = None
    expires_at: Optional[datetime] = None


class APIKeyResponse(BaseModel):
    id: str
    client_id: str
    key_prefix: str
    scopes: Optional[List[str]] = None
    status: str
    expires_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    created_at: datetime
    
    class Config:
        from_attributes = True


class APIKeyGenerateResponse(BaseModel):
    api_key: str  # Only shown once
    key_prefix: str
    client_id: str
    expires_at: Optional[datetime] = None


# Helper Functions
async def validate_api_key(api_key: str, db: AsyncSession) -> Optional[ClientAPIKey]:
    """Validate API key and return client_api_key object"""
    key_hash = hash_api_key(api_key)
    
    result = await db.execute(
        select(ClientAPIKey).where(
            and_(
                ClientAPIKey.key_hash == key_hash,
                ClientAPIKey.status == "active"
            )
        )
    )
    api_key_obj = result.scalar_one_or_none()
    
    if not api_key_obj:
        return None
    
    # Check expiration
    now = datetime.now(timezone.utc)
    if api_key_obj.expires_at:
        # Handle timezone-aware comparison
        if api_key_obj.expires_at.tzinfo is None:
            expires_at_utc = api_key_obj.expires_at.replace(tzinfo=timezone.utc)
        else:
            expires_at_utc = api_key_obj.expires_at.astimezone(timezone.utc)
        if expires_at_utc < now:
            return None
    
    # Update last_used_at
    api_key_obj.last_used_at = now
    await db.commit()
    
    return api_key_obj


# Routes - API Keys
@app.post("/api-keys/generate", response_model=APIKeyGenerateResponse, status_code=status.HTTP_201_CREATED)
async def generate_api_key_for_client(
    key_data: APIKeyCreate,
    db: AsyncSession = Depends(get_db)
):
    """Generate a new API key for a client"""
    # Validate client exists
    result = await db.execute(
        select(Client).where(Client.client_id == key_data.client_id)
    )
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Client {key_data.client_id} not found"
        )
    
    # Generate API key
    full_key, key_hash, key_prefix = generate_api_key(prefix="lead")
    
    new_api_key = ClientAPIKey(
        client_id=key_data.client_id,
        key_hash=key_hash,
        key_prefix=key_prefix,
        scopes=key_data.scopes or ["leads:create"],
        status="active",
        expires_at=key_data.expires_at
    )
    
    db.add(new_api_key)
    await db.commit()
    await db.refresh(new_api_key)
    
    return APIKeyGenerateResponse(
        api_key=full_key,  # Show only once
        key_prefix=key_prefix,
        client_id=key_data.client_id,
        expires_at=key_data.expires_at
    )


@app.get("/api-keys", response_model=List[APIKeyResponse])
async def list_api_keys(
    client_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """List API keys (without showing full keys)"""
    query = select(ClientAPIKey)
    if client_id:
        query = query.where(ClientAPIKey.client_id == client_id)
    
    result = await db.execute(query)
    api_keys = result.scalars().all()
    
    return [
        APIKeyResponse(
            id=str(ak.id),
            client_id=ak.client_id,
            key_prefix=ak.key_prefix,
            scopes=ak.scopes,
            status=ak.status,
            expires_at=ak.expires_at,
            last_used_at=ak.last_used_at,
            created_at=ak.created_at
        )
        for ak in api_keys
    ]


@app.patch("/api-keys/{api_key_id}", response_model=APIKeyResponse)
async def update_api_key(
    api_key_id: str,
    key_data: APIKeyUpdate,
    db: AsyncSession = Depends(get_db)
):
    """Update API key (e.g., disable/enable)"""
    result = await db.execute(
        select(ClientAPIKey).where(ClientAPIKey.id == api_key_id)
    )
    api_key = result.scalar_one_or_none()
    
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"API key with id '{api_key_id}' not found"
        )
    
    if key_data.status is not None:
        if key_data.status not in ["active", "disabled", "revoked"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Status must be one of: active, disabled, revoked"
            )
        api_key.status = key_data.status
    
    if key_data.scopes is not None:
        api_key.scopes = key_data.scopes
    
    if key_data.expires_at is not None:
        api_key.expires_at = key_data.expires_at
    
    await db.commit()
    await db.refresh(api_key)
    
    return APIKeyResponse(
        id=str(api_key.id),
        client_id=api_key.client_id,
        key_prefix=api_key.key_prefix,
        scopes=api_key.scopes,
        status=api_key.status,
        expires_at=api_key.expires_at,
        last_used_at=api_key.last_used_at,
        created_at=api_key.created_at
    )


@app.get("/api-keys/{api_key_id}", response_model=APIKeyResponse)
async def get_api_key(
    api_key_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Get API key details by ID"""
    result = await db.execute(
        select(ClientAPIKey).where(ClientAPIKey.id == uuid.UUID(api_key_id))
    )
    api_key = result.scalar_one_or_none()
    
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"API key with id '{api_key_id}' not found"
        )
    
    return APIKeyResponse(
        id=str(api_key.id),
        client_id=api_key.client_id,
        key_prefix=api_key.key_prefix,
        scopes=api_key.scopes,
        status=api_key.status,
        expires_at=api_key.expires_at,
        last_used_at=api_key.last_used_at,
        created_at=api_key.created_at
    )


@app.delete("/api-keys/{api_key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_api_key(
    api_key_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Delete API key permanently"""
    result = await db.execute(
        select(ClientAPIKey).where(ClientAPIKey.id == uuid.UUID(api_key_id))
    )
    api_key = result.scalar_one_or_none()
    
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"API key with id '{api_key_id}' not found"
        )
    
    await db.delete(api_key)
    await db.commit()
    
    return None


# Routes - Leads
@app.post("/leads/ingest", response_model=LeadResponse, status_code=status.HTTP_201_CREATED)
async def ingest_lead_via_api_key(
    lead_data: LeadCreate,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    db: AsyncSession = Depends(get_db)
):
    """Ingest lead via API key (for website forms) with anti-spam protection"""
    logger = logging.getLogger(__name__)
    
    try:
        if not x_api_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="X-API-Key header required"
            )
        
        # Validate API key
        api_key_obj = await validate_api_key(x_api_key, db)
        if not api_key_obj:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired API key"
            )
        
        # Ensure client_id matches
        if lead_data.client_id != api_key_obj.client_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="API key does not belong to this client"
            )
        
        # Validate client exists and is active
        result = await db.execute(
            select(Client).where(Client.client_id == lead_data.client_id)
        )
        client = result.scalar_one_or_none()
        if not client or client.status != "active":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Client {lead_data.client_id} not found or inactive"
            )
        
        # Anti-spam checks
        
        # 1. Validate email format if provided
        if lead_data.email and not validate_email_format(lead_data.email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email format"
            )
        
        # 2. Validate phone format if provided
        if lead_data.phone and not validate_phone_format(lead_data.phone):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid phone number format"
            )
        
        # 3. Check for suspicious patterns
        is_suspicious, reason = is_suspicious_lead({
            "name": lead_data.name or "",
            "email": lead_data.email or ""
        })
        if is_suspicious:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Suspicious lead data detected: {reason}"
            )
        
        # Normalize phone number
        normalized_phone = normalize_phone(lead_data.phone) if lead_data.phone else None
        
        # Create lead
        new_lead = Lead(
            client_id=lead_data.client_id,
            name=lead_data.name,
            email=lead_data.email.lower() if lead_data.email else None,
            phone=normalized_phone,
            source=lead_data.source or "website",
            lead_reference_id=lead_data.lead_reference_id,
            raw_payload=lead_data.raw_payload
        )
        
        db.add(new_lead)
        await db.commit()
        await db.refresh(new_lead)
        
        # Trigger background processing (via integration service)
        try:
            integration_response = await integration_client.post(
                "/process-lead",
                json={
                    "lead_id": str(new_lead.id),
                    "client_id": new_lead.client_id
                }
            )
            # Log the integration service response for debugging
            logger.info(f"Integration service response for lead {new_lead.id}: {integration_response}")
            
            # Check if there were any errors in the response
            if isinstance(integration_response, dict):
                if integration_response.get("whatsapp") and integration_response["whatsapp"].get("error"):
                    logger.warning(f"WhatsApp notification failed: {integration_response['whatsapp']['error']}")
                if integration_response.get("emails"):
                    for email_type, email_result in integration_response["emails"].items():
                        if email_result and email_result.get("error"):
                            logger.warning(f"Email notification failed ({email_type}): {email_result['error']}")
        except Exception as e:
            # Log error but don't fail the request
            logger.error(f"Failed to trigger background processing: {e}", exc_info=True)
        
        # Convert Lead model to LeadResponse
        try:
            logger.info(f"Creating LeadResponse for lead {new_lead.id}")
            response = LeadResponse(
                id=str(new_lead.id),
                client_id=new_lead.client_id,
                created_by_user_client_id=str(new_lead.created_by_user_client_id) if new_lead.created_by_user_client_id else None,
                name=new_lead.name,
                email=new_lead.email,
                phone=new_lead.phone,
                source=new_lead.source,
                lead_reference_id=new_lead.lead_reference_id,
                raw_payload=new_lead.raw_payload,
                created_at=new_lead.created_at,
                updated_at=new_lead.updated_at
            )
            logger.info(f"Successfully created LeadResponse for lead {new_lead.id}")
            return response
        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            logger.error(f"Error creating LeadResponse: {e}\n{error_trace}")
            logger.error(f"Lead data: id={new_lead.id}, created_at={new_lead.created_at}, updated_at={new_lead.updated_at}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error processing lead: {str(e)}"
            )
    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        logger.error(f"Error in ingest_lead_via_api_key: {e}\n{error_trace}")
        # Return more detailed error in development, generic in production
        error_detail = str(e) if os.getenv("DEBUG", "false").lower() == "true" else "Internal server error"
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {error_detail}"
        )


# System client ID for ordpanel leads
ORD_PANEL_CLIENT_ID = "ORD_PANEL"


@app.post("/leads/ordpanel", response_model=LeadResponse, status_code=status.HTTP_201_CREATED)
async def create_ordpanel_lead(
    lead_data: OrdPanelLeadCreate,
    db: AsyncSession = Depends(get_db)
):
    """Create lead from ordpanel (public endpoint, no API key required)"""
    logger = logging.getLogger(__name__)
    
    try:
        # Ensure ORD_PANEL client exists
        result = await db.execute(
            select(Client).where(Client.client_id == ORD_PANEL_CLIENT_ID)
        )
        ord_panel_client = result.scalar_one_or_none()
        
        if not ord_panel_client:
            # Create the system client if it doesn't exist
            ord_panel_client = Client(
                client_id=ORD_PANEL_CLIENT_ID,
                name="Order Panel Portal",
                status="active"
            )
            db.add(ord_panel_client)
            await db.commit()
            await db.refresh(ord_panel_client)
            logger.info(f"Created system client: {ORD_PANEL_CLIENT_ID}")
        
        # Validate email format (only if provided)
        if lead_data.email and not validate_email_format(lead_data.email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email format"
            )
        
        # Validate phone format (only if provided)
        if lead_data.phone and not validate_phone_format(lead_data.phone):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid phone number format"
            )
        
        # Check for suspicious patterns (only if name or email provided)
        if lead_data.name or lead_data.email:
            is_suspicious, reason = is_suspicious_lead({
                "name": lead_data.name or "",
                "email": lead_data.email or ""
            })
            if is_suspicious:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Suspicious lead data detected: {reason}"
                )
        
        # Normalize phone number (only if provided)
        normalized_phone = normalize_phone(lead_data.phone) if lead_data.phone else None
        
        # Prepare raw payload with additional info
        raw_payload = {
            "product_name": lead_data.product_name,
            "client_name": lead_data.client_name,
            "message": lead_data.message,
            "form_type": lead_data.form_type,
            "source": "ordpanel"
        }
        
        # Create lead with source=ordpanel
        new_lead = Lead(
            client_id=ORD_PANEL_CLIENT_ID,
            name=lead_data.name,
            email=lead_data.email.lower() if lead_data.email else None,
            phone=normalized_phone,
            source="ordpanel",
            lead_reference_id=None,
            raw_payload=raw_payload
        )
        
        db.add(new_lead)
        await db.commit()
        await db.refresh(new_lead)
        
        # Note: We don't trigger integration service for ordpanel leads
        # They should be handled differently in the frontend UI
        
        return LeadResponse(
            id=str(new_lead.id),
            client_id=new_lead.client_id,
            created_by_user_client_id=str(new_lead.created_by_user_client_id) if new_lead.created_by_user_client_id else None,
            name=new_lead.name,
            email=new_lead.email,
            phone=new_lead.phone,
            source=new_lead.source,
            lead_reference_id=new_lead.lead_reference_id,
            raw_payload=new_lead.raw_payload,
            created_at=new_lead.created_at,
            updated_at=new_lead.updated_at
        )
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        logger.error(f"Error in create_ordpanel_lead: {e}\n{error_trace}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error creating lead: {str(e)}"
        )


@app.post("/leads", response_model=LeadResponse, status_code=status.HTTP_201_CREATED)
async def create_lead(
    lead_data: LeadCreate,
    db: AsyncSession = Depends(get_db)
):
    """Create lead (internal API, requires authentication)"""
    # Validate client exists
    result = await db.execute(
        select(Client).where(Client.client_id == lead_data.client_id)
    )
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Client {lead_data.client_id} not found"
        )
    
    new_lead = Lead(
        client_id=lead_data.client_id,
        name=lead_data.name,
        email=lead_data.email,
        phone=lead_data.phone,
        source=lead_data.source,
        lead_reference_id=lead_data.lead_reference_id,
        raw_payload=lead_data.raw_payload
    )
    
    db.add(new_lead)
    await db.commit()
    await db.refresh(new_lead)
    
    # Trigger background processing
    try:
        await integration_client.post(
            "/process-lead",
            json={
                "lead_id": str(new_lead.id),
                "client_id": new_lead.client_id
            }
        )
    except Exception as e:
        print(f"Failed to trigger background processing: {e}")
    
    # Manually construct LeadResponse to handle UUID and datetime serialization
    return LeadResponse(
        id=str(new_lead.id),
        client_id=new_lead.client_id,
        created_by_user_client_id=str(new_lead.created_by_user_client_id) if new_lead.created_by_user_client_id else None,
        name=new_lead.name,
        email=new_lead.email,
        phone=new_lead.phone,
        source=new_lead.source,
        lead_reference_id=new_lead.lead_reference_id,
        raw_payload=new_lead.raw_payload,
        created_at=new_lead.created_at,
        updated_at=new_lead.updated_at
    )


@app.get("/leads", response_model=List[LeadResponse])
async def list_leads(
    client_id: Optional[str] = None,
    source: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db)
):
    """List leads with optional filtering"""
    try:
        query = select(Lead)
        
        if client_id:
            query = query.where(Lead.client_id == client_id)
        if source:
            query = query.where(Lead.source == source)
        
        query = query.order_by(Lead.created_at.desc()).offset(skip).limit(limit)
        result = await db.execute(query)
        leads = result.scalars().all()
        
        # Manually construct LeadResponse to handle UUID and datetime serialization
        return [
            LeadResponse(
                id=str(lead.id),
                client_id=lead.client_id,
                created_by_user_client_id=str(lead.created_by_user_client_id) if lead.created_by_user_client_id else None,
                name=lead.name,
                email=lead.email,
                phone=lead.phone,
                source=lead.source,
                lead_reference_id=lead.lead_reference_id,
                raw_payload=lead.raw_payload,
                created_at=lead.created_at,
                updated_at=lead.updated_at
            )
            for lead in leads
        ]
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        logger.error(f"Error in list_leads: {e}\n{error_trace}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@app.get("/leads/{lead_id}", response_model=LeadResponse)
async def get_lead(lead_id: str, db: AsyncSession = Depends(get_db)):
    """Get lead by ID"""
    try:
        result = await db.execute(select(Lead).where(Lead.id == uuid.UUID(lead_id)))
        lead = result.scalar_one_or_none()
        
        if not lead:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Lead {lead_id} not found"
            )
        
        # Manually construct LeadResponse to handle UUID and datetime serialization
        return LeadResponse(
            id=str(lead.id),
            client_id=lead.client_id,
            created_by_user_client_id=str(lead.created_by_user_client_id) if lead.created_by_user_client_id else None,
            name=lead.name,
            email=lead.email,
            phone=lead.phone,
            source=lead.source,
            lead_reference_id=lead.lead_reference_id,
            raw_payload=lead.raw_payload,
            created_at=lead.created_at,
            updated_at=lead.updated_at
        )
    except HTTPException:
        raise
    except ValueError as e:
        # Invalid UUID format
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid lead ID format: {lead_id}"
        )
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        logger.error(f"Error in get_lead: {e}\n{error_trace}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )


@app.get("/health")
async def health():
    """Health check"""
    return {"status": "healthy", "service": "lead_service"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8004)

