"""
Client Service - Client management with client-provided IDs
"""
from fastapi import FastAPI, Depends, HTTPException, status, Header, UploadFile, File, Form, Request
from fastapi.staticfiles import StaticFiles
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from pydantic import BaseModel, EmailStr
from typing import Optional, List, Tuple, Dict, Any
from datetime import datetime, date
from decimal import Decimal
import sys
import os
import logging
import shutil
import uuid
import json
from pathlib import Path

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from shared.database import get_db
from shared.models.base import BaseModel as BaseDBModel, BaseModelNoID

from sqlalchemy import Column, String, ForeignKey, Numeric, Date, DateTime, Integer, JSON, Boolean
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.sql import func
import uuid

# Define User model for foreign key reference
# This is needed because Transaction.verified_by_user_id references users.id
# Since all services share the same database, we need SQLAlchemy to know about the users table
# We define a minimal User model here - the full definition is in auth_service
class User(BaseDBModel):
    __tablename__ = "users"
    # Minimal definition - just enough for foreign key reference and email lookup
    # The id column is inherited from BaseDBModel, which is what the foreign key references
    # Full definition is in auth_service, but we need email here to fetch user emails
    email = Column(String, nullable=False)

app = FastAPI(title="Client Service", version="1.0.0")

# GST rate (18%)
GST_RATE = Decimal("0.18")

# Create upload directory for client logos
# In Docker, files are at /app/uploads/images (volume mounted from ./uploads)
# In local dev, files are at backend_api/uploads/images
UPLOAD_DIR = Path("/app/uploads/images") if Path("/app/uploads").exists() else Path(__file__).parent.parent.parent / "uploads" / "images"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# Mount static files for serving images
app.mount("/static/images", StaticFiles(directory=str(UPLOAD_DIR)), name="images")


async def save_uploaded_file(file: UploadFile, subfolder: str = "") -> str:
    """Save uploaded file and return relative path"""
    # Create subfolder if specified
    target_dir = UPLOAD_DIR / subfolder
    target_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate unique filename
    file_ext = Path(file.filename).suffix if file.filename else ".bin"
    filename = f"{uuid.uuid4()}{file_ext}"
    file_path = target_dir / filename
    
    # Read file content in binary mode
    contents = await file.read()
    
    # Save file
    with open(file_path, "wb") as buffer:
        buffer.write(contents)
    
    # Return relative path for storage in database
    relative_path = f"/static/images/{subfolder}/{filename}" if subfolder else f"/static/images/{filename}"
    return relative_path


# Database Models
class Client(BaseModelNoID):
    __tablename__ = "clients"
    
    client_id = Column(String, primary_key=True, unique=True, nullable=False, index=True)
    name = Column(String, nullable=False)
    status = Column(String, default="active", nullable=False)
    is_premium = Column(Boolean, default=False, nullable=False)
    # Order form fields
    company_name = Column(String, nullable=True)
    contact_person = Column(String, nullable=True)
    designation = Column(String, nullable=True)
    address = Column(String, nullable=True)
    phone = Column(String, nullable=True)
    email = Column(String, nullable=True)
    domain_name = Column(String, nullable=True)
    gst_no = Column(String, nullable=True)
    logo = Column(String, nullable=True)  # Logo file path
    city = Column(String, nullable=True)
    state = Column(String, nullable=True)
    description = Column(String, nullable=True)  # Company description
    package_amount = Column(Numeric(precision=12, scale=2), nullable=True)
    gst_amount = Column(Numeric(precision=12, scale=2), nullable=True)
    total_amount = Column(Numeric(precision=12, scale=2), nullable=True)
    customer_no = Column(String, nullable=True, index=True)
    order_date = Column(Date, nullable=True)
    order_data = Column(JSONB, nullable=True)  # Store guidelines, SEO, Adwords, and other special instructions


class Service(BaseDBModel):
    __tablename__ = "services"
    
    name = Column(String, nullable=False, unique=True, index=True)
    code = Column(String, nullable=True, unique=True, index=True)
    category = Column(String, nullable=True)
    description = Column(String, nullable=True)
    status = Column(String, default="active", nullable=False)


class ClientService(BaseDBModel):
    __tablename__ = "client_services"
    
    client_id = Column(String, ForeignKey("clients.client_id"), nullable=False, index=True)
    service_id = Column(UUID(as_uuid=True), ForeignKey("services.id"), nullable=False, index=True)
    quantity = Column(Integer, nullable=True)
    status = Column(String, default="active", nullable=False)


class Transaction(BaseDBModel):
    __tablename__ = "transactions"
    
    client_id = Column(String, ForeignKey("clients.client_id"), nullable=False, index=True)
    transaction_id = Column(String, nullable=False, unique=True, index=True)
    amount = Column(Numeric(precision=12, scale=2), nullable=False)
    payment_method = Column(String, nullable=True)  # e.g., "UPI", "Bank Transfer", "Cash", "Credit Card", etc.
    status = Column(String, nullable=False, default="pending")  # pending, verified, rejected
    created_by_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)  # Who created the transaction
    verified_by_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)  # Who approved/rejected
    verified_at = Column(DateTime(timezone=True), nullable=True)
    rejection_reason = Column(String, nullable=True)  # Required when status is "rejected"
    notes = Column(String, nullable=True)


class ClientIntegration(BaseModelNoID):
    """Client integration settings for WhatsApp, Google Sheets, etc."""
    __tablename__ = "client_integrations"
    
    client_id = Column(String, ForeignKey("clients.client_id"), nullable=False, primary_key=True)
    whatsapp_enabled = Column(String, default="false", nullable=False)  # Boolean as string
    google_sheets_enabled = Column(String, default="false", nullable=False)
    google_sheet_id = Column(String, nullable=True)
    meta_page_id = Column(String, nullable=True)
    meta_form_id = Column(String, nullable=True)
    config = Column(JSONB, nullable=True)  # Additional configuration
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


# Pydantic Schemas
class ClientCreate(BaseModel):
    client_id: str  # Provided by frontend
    name: str
    status: str = "active"
    is_premium: bool = False
    # Order form fields (optional)
    company_name: Optional[str] = None
    contact_person: Optional[str] = None
    designation: Optional[str] = None
    address: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None
    domain_name: Optional[str] = None
    gst_no: Optional[str] = None
    logo: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    description: Optional[str] = None
    package_amount: Optional[Decimal] = None
    gst_amount: Optional[Decimal] = None
    total_amount: Optional[Decimal] = None
    customer_no: Optional[str] = None
    order_date: Optional[datetime] = None


class ClientUpdate(BaseModel):
    name: Optional[str] = None
    status: Optional[str] = None
    is_premium: Optional[bool] = None
    company_name: Optional[str] = None
    contact_person: Optional[str] = None
    designation: Optional[str] = None
    address: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None
    domain_name: Optional[str] = None
    gst_no: Optional[str] = None
    logo: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    description: Optional[str] = None
    package_amount: Optional[Decimal] = None
    gst_amount: Optional[Decimal] = None
    total_amount: Optional[Decimal] = None
    customer_no: Optional[str] = None
    order_date: Optional[datetime] = None


class ClientResponse(BaseModel):
    client_id: str
    name: str
    status: str
    is_premium: bool
    company_name: Optional[str] = None
    contact_person: Optional[str] = None
    designation: Optional[str] = None
    address: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None
    domain_name: Optional[str] = None
    gst_no: Optional[str] = None
    logo: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    description: Optional[str] = None
    package_amount: Optional[Decimal] = None
    gst_amount: Optional[Decimal] = None
    total_amount: Optional[Decimal] = None
    customer_no: Optional[str] = None
    order_date: Optional[datetime] = None
    order_data: Optional[Dict[str, Any]] = None
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class OrderFormData(BaseModel):
    """Order form submission data"""
    # Client Information
    company_name: Optional[str] = None
    full_name: Optional[str] = None  # contact_person
    designation: Optional[str] = None
    address: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[EmailStr] = None
    domain_name: Optional[str] = None
    gst_no: Optional[str] = None
    
    # Form Details
    form_no: Optional[str] = None  # customer_no
    form_date: Optional[str] = None  # order_date (DD/MM/YYYY format)
    total_package: Optional[Decimal] = None  # package_amount
    
    # Services (array of service codes)
    services: Optional[List[str]] = None
    email_services: Optional[List[str]] = None
    pop_id_count: Optional[int] = None
    g_suite_id_count: Optional[int] = None
    
    # Special instructions (stored in order_data JSONB)
    guidelines: Optional[str] = None
    seo_keyword_range: Optional[List[str]] = None
    seo_location: Optional[List[str]] = None
    seo_keywords_list: Optional[str] = None
    adwords_keywords: Optional[str] = None
    adwords_period: Optional[str] = None
    adwords_location: Optional[str] = None
    adwords_keywords_list: Optional[str] = None
    special_guidelines: Optional[str] = None


class OrderResponse(BaseModel):
    client_id: str
    customer_no: str
    package_amount: Decimal
    gst_amount: Decimal
    total_amount: Decimal
    services_count: int
    created_at: datetime


class TransactionCreate(BaseModel):
    client_id: str
    transaction_id: str  # Manually entered transaction ID
    amount: Decimal
    payment_method: Optional[str] = None  # e.g., "UPI", "Bank Transfer", "Cash", "Credit Card", etc.
    created_by_user_id: Optional[str] = None  # User who is creating the transaction
    notes: Optional[str] = None


class TransactionUpdate(BaseModel):
    status: str  # verified or rejected
    verified_by_user_id: Optional[str] = None
    rejection_reason: Optional[str] = None  # Required when status is "rejected"
    notes: Optional[str] = None


class TransactionResponse(BaseModel):
    id: str
    client_id: str
    transaction_id: str
    amount: Decimal
    payment_method: Optional[str] = None
    status: str
    created_by_user_id: Optional[str] = None
    created_by_user_email: Optional[str] = None  # Email of user who created the transaction
    verified_by_user_id: Optional[str] = None
    verified_by_user_email: Optional[str] = None  # Email of user who approved/rejected
    verified_at: Optional[datetime] = None
    rejection_reason: Optional[str] = None  # Stored in database - reason for rejection
    notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


# Helper Functions
def calculate_gst(package_amount: Decimal) -> Tuple[Decimal, Decimal]:
    """Calculate GST (18%) and total amount"""
    if package_amount is None or package_amount <= 0:
        return Decimal("0"), Decimal("0")
    
    gst_amount = package_amount * GST_RATE
    total_amount = package_amount + gst_amount
    return gst_amount, total_amount


def parse_date(date_str: Optional[str]) -> Optional[date]:
    """Parse date from DD/MM/YYYY format"""
    if not date_str:
        return None
    try:
        parts = date_str.split("/")
        if len(parts) == 3:
            return date(int(parts[2]), int(parts[1]), int(parts[0]))
    except:
        pass
    return None


async def get_or_create_service(code: str, name: str, category: str, db: AsyncSession) -> Service:
    """Get existing service or create new one"""
    result = await db.execute(select(Service).where(Service.code == code))
    service = result.scalar_one_or_none()
    
    if not service:
        service = Service(
            id=uuid.uuid4(),
            code=code,
            name=name,
            category=category,
            status="active"
        )
        db.add(service)
        await db.flush()
    return service


async def get_client_services(client_id: str, db: AsyncSession) -> List[Dict[str, Any]]:
    """Get list of services for a client with codes and quantities"""
    services_result = await db.execute(
        select(ClientService, Service).join(
            Service, ClientService.service_id == Service.id
        ).where(
            and_(
                ClientService.client_id == client_id,
                ClientService.status == "active"
            )
        )
    )
    client_services = services_result.all()
    
    # Build services list with service codes and quantities
    services_list = []
    for client_service, service in client_services:
        if service.code:
            service_info = {
                "code": service.code,
                "name": service.name,
            }
            # Include quantity if it exists
            if client_service.quantity is not None:
                service_info["quantity"] = client_service.quantity
            services_list.append(service_info)
    
    return services_list


def enrich_client_response(client: Client, services_list: List[Dict[str, Any]]) -> ClientResponse:
    """Create ClientResponse with services included in order_data"""
    # Update order_data to include services if it exists, or create it
    order_data = client.order_data or {}
    if services_list:
        # Store services as list of objects with code, name, and quantity
        order_data["services"] = services_list
        # Also store simple list of codes for backward compatibility
        order_data["service_codes"] = [s["code"] for s in services_list]
    
    # Create response with updated order_data
    response = ClientResponse.from_orm(client)
    response.order_data = order_data if order_data else None
    
    return response


# Routes
@app.post("/clients", response_model=ClientResponse, status_code=status.HTTP_201_CREATED)
async def create_client(
    client_id: str = Form(...),
    name: str = Form(...),
    status: str = Form("active"),
    is_premium: str = Form("false"),  # Receive as string, convert to bool
    company_name: Optional[str] = Form(None),
    contact_person: Optional[str] = Form(None),
    designation: Optional[str] = Form(None),
    address: Optional[str] = Form(None),
    phone: Optional[str] = Form(None),
    email: Optional[str] = Form(None),
    domain_name: Optional[str] = Form(None),
    gst_no: Optional[str] = Form(None),
    city: Optional[str] = Form(None),
    state: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    package_amount: Optional[str] = Form(None),  # Receive as string, convert to Decimal
    customer_no: Optional[str] = Form(None),
    logo: Optional[UploadFile] = File(None),
    db: AsyncSession = Depends(get_db)
):
    """Create a new client with provided client_id"""
    # Validate client_id format (basic validation)
    if not client_id or len(client_id.strip()) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="client_id is required and cannot be empty"
        )
    
    # Check uniqueness
    result = await db.execute(
        select(Client).where(Client.client_id == client_id)
    )
    existing_client = result.scalar_one_or_none()
    
    if existing_client:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Client with client_id '{client_id}' already exists"
        )
    
    # Convert is_premium from string to boolean
    is_premium_bool = is_premium.lower() in ("true", "1", "yes") if is_premium else False
    
    # Save logo if provided
    logo_path = None
    if logo:
        try:
            logo_path = await save_uploaded_file(logo, "clients/logos")
        except Exception as e:
            logging.error(f"Error saving logo: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to save logo: {str(e)}"
            )
    
    # Calculate GST and total if package_amount is provided
    gst_amount = None
    total_amount = None
    package_amount_decimal = None
    if package_amount:
        try:
            package_amount_decimal = Decimal(str(package_amount))
            gst_amount = package_amount_decimal * GST_RATE
            total_amount = package_amount_decimal + gst_amount
        except (ValueError, TypeError):
            logging.error(f"Invalid package_amount: {package_amount}")
    
    # Create client
    new_client = Client(
        client_id=client_id,
        name=name,
        status=status,
        is_premium=is_premium_bool,
        company_name=company_name,
        contact_person=contact_person,
        designation=designation,
        address=address,
        phone=phone,
        email=email,
        domain_name=domain_name,
        gst_no=gst_no,
        logo=logo_path,
        city=city,
        state=state,
        description=description,
        package_amount=package_amount_decimal,
        gst_amount=gst_amount,
        total_amount=total_amount,
        customer_no=customer_no,
        order_date=None,  # Can be set separately
        order_data=None  # Can be set separately
    )
    
    db.add(new_client)
    await db.commit()
    await db.refresh(new_client)
    
    # Automatically create ClientIntegration record with default values
    try:
        # Check if integration already exists (shouldn't, but just in case)
        integration_result = await db.execute(
            select(ClientIntegration).where(ClientIntegration.client_id == new_client.client_id)
        )
        existing_integration = integration_result.scalar_one_or_none()
        
        if not existing_integration:
            # Create default integration record (WhatsApp disabled by default)
            new_integration = ClientIntegration(
                client_id=new_client.client_id,
                whatsapp_enabled="false",  # Disabled by default - user can enable later
                google_sheets_enabled="false",
                google_sheet_id=None,
                meta_page_id=None,
                meta_form_id=None,
                config=None
            )
            db.add(new_integration)
            await db.commit()
    except Exception as e:
        # Log error but don't fail client creation if integration creation fails
        logger = logging.getLogger(__name__)
        logger.warning(f"Failed to create ClientIntegration for client {new_client.client_id}: {e}")
        # Continue with client creation even if integration creation fails
    
    return ClientResponse.from_orm(new_client)


@app.get("/clients", response_model=List[ClientResponse])
async def list_clients(
    skip: int = 0,
    limit: int = 100,
    status_filter: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """List all clients with optional filtering"""
    query = select(Client)
    
    if status_filter:
        query = query.where(Client.status == status_filter)
    
    query = query.offset(skip).limit(limit)
    
    result = await db.execute(query)
    clients = result.scalars().all()
    
    # Fetch services for all clients and include in order_data
    client_responses = []
    for client in clients:
        # Fetch services for this client
        services_list = await get_client_services(client.client_id, db)
        
        # Create response with services included in order_data
        response = enrich_client_response(client, services_list)
        client_responses.append(response)
    
    return client_responses


@app.get("/clients/premium", response_model=List[ClientResponse])
async def get_premium_clients(
    db: AsyncSession = Depends(get_db)
):
    """Get all premium clients (for ordpanel display)"""
    query = select(Client).where(
        and_(
            Client.is_premium == True,
            Client.status == "active"
        )
    ).order_by(Client.name)
    
    result = await db.execute(query)
    clients = result.scalars().all()
    
    # Fetch services for all clients and include in order_data
    client_responses = []
    for client in clients:
        # Fetch services for this client
        services_list = await get_client_services(client.client_id, db)
        
        # Create response with services included in order_data
        response = enrich_client_response(client, services_list)
        client_responses.append(response)
    
    return client_responses


@app.put("/clients/{client_id}", response_model=ClientResponse)
async def update_client(
    client_id: str,
    request: Request,
    name: Optional[str] = Form(None),
    status: Optional[str] = Form(None),
    is_premium: Optional[str] = Form(None),  # Receive as string, convert to bool
    company_name: Optional[str] = Form(None),
    contact_person: Optional[str] = Form(None),
    designation: Optional[str] = Form(None),
    address: Optional[str] = Form(None),
    phone: Optional[str] = Form(None),
    email: Optional[str] = Form(None),
    domain_name: Optional[str] = Form(None),
    gst_no: Optional[str] = Form(None),
    city: Optional[str] = Form(None),
    state: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    package_amount: Optional[str] = Form(None),  # Receive as string, convert to Decimal
    customer_no: Optional[str] = Form(None),
    logo: Optional[UploadFile] = File(None),
    db: AsyncSession = Depends(get_db)
):
    """Update client (client_id cannot be changed)"""
    # Check content type
    content_type = request.headers.get("content-type", "")
    
    # For JSON requests, FastAPI won't parse Form parameters (they'll be None)
    # For Form requests, Form parameters will have values
    # Parse JSON if it's a JSON request
    json_data = None
    if "application/json" in content_type:
        # FastAPI should not consume body for JSON when Form params are present
        # But to be safe, try to parse JSON
        try:
            json_data = await request.json()
            logging.info(f"Parsed JSON data: {json_data}")
        except Exception as e:
            logging.error(f"Could not parse JSON: {e}")
            # If parsing fails, Form params should be None for JSON requests anyway
    
    # Extract fields - use JSON if available, otherwise use Form params
    if json_data:
        # Extract from JSON (Form params will be None for JSON requests)
        name = json_data.get("name") if name is None else name
        status = json_data.get("status") if status is None else status
        is_premium = json_data.get("is_premium") if is_premium is None else is_premium
        if is_premium is not None and not isinstance(is_premium, str):
            is_premium = str(is_premium).lower()
        company_name = json_data.get("company_name") if company_name is None else company_name
        contact_person = json_data.get("contact_person") if contact_person is None else contact_person
        designation = json_data.get("designation") if designation is None else designation
        address = json_data.get("address") if address is None else address
        phone = json_data.get("phone") if phone is None else phone
        email = json_data.get("email") if email is None else email
        domain_name = json_data.get("domain_name") if domain_name is None else domain_name
        gst_no = json_data.get("gst_no") if gst_no is None else gst_no
        city = json_data.get("city") if city is None else city
        state = json_data.get("state") if state is None else state
        if description is None:
            description = json_data.get("description")
            logging.info(f"JSON description: {description}")
        package_amount = json_data.get("package_amount") if package_amount is None else package_amount
        if package_amount is not None and not isinstance(package_amount, str):
            package_amount = str(package_amount)
        customer_no = json_data.get("customer_no") if customer_no is None else customer_no
    else:
        # Form request - use Form parameters (already set)
        logging.info(f"Form request - description: {description}")
    
    result = await db.execute(select(Client).where(Client.client_id == client_id))
    client = result.scalar_one_or_none()
    
    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Client with client_id '{client_id}' not found"
        )
    
    # Update fields
    if name is not None:
        client.name = name
    if status is not None:
        client.status = status
    if is_premium is not None:
        # Convert string "true"/"false" to boolean
        client.is_premium = is_premium.lower() in ("true", "1", "yes")
    if company_name is not None:
        client.company_name = company_name
    if contact_person is not None:
        client.contact_person = contact_person
    if designation is not None:
        client.designation = designation
    if address is not None:
        client.address = address
    if phone is not None:
        client.phone = phone
    if email is not None:
        client.email = email
    if domain_name is not None:
        client.domain_name = domain_name
    if gst_no is not None:
        client.gst_no = gst_no
    if city is not None:
        client.city = city
    if state is not None:
        client.state = state
    # Update description - handle both JSON and Form requests
    # For JSON requests, description comes from json_data (parsed earlier)
    # For Form requests, description comes from Form parameter
    logging.info(f"Updating description: value={description}, is_not_none={description is not None}, type={type(description)}")
    if description is not None:
        client.description = description
        logging.info(f"Set client.description to: {client.description}")
    else:
        logging.warning(f"Description is None - not updating. Content type: {content_type}")
    # If description is None and it's a JSON request, we already checked json_data above
    # so if it's None here, it means description wasn't in the JSON or was explicitly None
    if package_amount is not None:
        try:
            package_amount_decimal = Decimal(str(package_amount))
            client.package_amount = package_amount_decimal
            # Auto-calculate GST and total
            client.gst_amount = package_amount_decimal * GST_RATE
            client.total_amount = package_amount_decimal + client.gst_amount
        except (ValueError, TypeError):
            logging.error(f"Invalid package_amount: {package_amount}")
    if customer_no is not None:
        client.customer_no = customer_no
    
    # Handle logo upload if provided
    if logo:
        try:
            logo_path = await save_uploaded_file(logo, "clients/logos")
            client.logo = logo_path
        except Exception as e:
            logging.error(f"Error saving logo: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to save logo: {str(e)}"
            )
    # Note: order_data is not in ClientUpdate model, so we don't update it here
    # If order_data needs to be updated, it should be added to ClientUpdate model
    
    await db.commit()
    await db.refresh(client)
    
    # Fetch services for this client and include in response
    services_list = await get_client_services(client.client_id, db)
    return enrich_client_response(client, services_list)


@app.delete("/clients/{client_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_client(client_id: str, db: AsyncSession = Depends(get_db)):
    """Delete client (soft delete by setting status to deleted)"""
    result = await db.execute(select(Client).where(Client.client_id == client_id))
    client = result.scalar_one_or_none()
    
    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Client with client_id '{client_id}' not found"
        )
    
    client.status = "deleted"
    await db.commit()
    
    return None


@app.get("/clients/{client_id}/exists")
async def check_client_exists(client_id: str, db: AsyncSession = Depends(get_db)):
    """Check if client_id exists"""
    result = await db.execute(select(Client).where(Client.client_id == client_id))
    exists = result.scalar_one_or_none() is not None
    
    return {"client_id": client_id, "exists": exists}


@app.get("/clients/{client_id}", response_model=ClientResponse)
async def get_client(client_id: str, db: AsyncSession = Depends(get_db)):
    """Get a single client by client_id"""
    result = await db.execute(select(Client).where(Client.client_id == client_id))
    client = result.scalar_one_or_none()
    
    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Client with client_id '{client_id}' not found"
        )
    
    # Fetch services for this client
    services_list = await get_client_services(client.client_id, db)
    
    # Create response with services included in order_data
    return enrich_client_response(client, services_list)


# Order Form Submission
@app.post("/orders/submit", response_model=OrderResponse, status_code=status.HTTP_201_CREATED)
async def submit_order(
    order_data: OrderFormData,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    db: AsyncSession = Depends(get_db)
):
    """Submit order form and store as client data"""
    # Customer No = Client ID (same thing)
    customer_no = order_data.form_no or f"ORD-{datetime.now().strftime('%d%m%Y')}-{uuid.uuid4().hex[:6].upper()}"
    client_id = customer_no  # Customer No and Client ID are the same
    
    # Check if client already exists
    result = await db.execute(select(Client).where(Client.client_id == client_id))
    existing_client = result.scalar_one_or_none()
    
    # Calculate amounts
    package_amount = order_data.total_package or Decimal("0")
    gst_amount, total_amount = calculate_gst(package_amount)
    
    # Parse order date
    order_date = parse_date(order_data.form_date)
    
    # Collect all special instructions in order_data JSONB
    special_instructions = {}
    
    # Store services in order_data for easy access in UI
    # Build service objects with codes, names, and quantities
    all_services = []
    service_map = {
        "domain-hosting": "Domain & Hosting",
        "pop-id": "POP ID",
        "g-suite-id": "G Suite ID",
        "website-design-development": "Website Design / Development",
        "website-maintenance": "Website Maintenance",
        "app-development": "App Development",
        "seo": "Search Engine Optimization",
        "google-ads": "Google Ads / PPC",
        "google-my-business": "Google My Business (Local)",
        "ai-chatbot": "AI Chatbot",
        "youtube-promotion": "YouTube Promotion",
        "email-marketing": "Email Marketing",
    }
    
    if order_data.services:
        for service_code in order_data.services:
            service_name = service_map.get(service_code, service_code)
            all_services.append({
                "code": service_code,
                "name": service_name
            })
    
    if order_data.email_services:
        for service_code in order_data.email_services:
            service_name = service_map.get(service_code, service_code)
            service_obj = {
                "code": service_code,
                "name": service_name
            }
            # Add quantity if applicable
            if service_code == "pop-id" and order_data.pop_id_count:
                service_obj["quantity"] = order_data.pop_id_count
            elif service_code == "g-suite-id" and order_data.g_suite_id_count:
                service_obj["quantity"] = order_data.g_suite_id_count
            all_services.append(service_obj)
    
    if all_services:
        special_instructions["services"] = all_services
    
    if order_data.guidelines:
        special_instructions["guidelines"] = order_data.guidelines
    if order_data.seo_keyword_range:
        special_instructions["seo_keyword_range"] = order_data.seo_keyword_range
    if order_data.seo_location:
        special_instructions["seo_location"] = order_data.seo_location
    if order_data.seo_keywords_list:
        special_instructions["seo_keywords_list"] = order_data.seo_keywords_list
    if order_data.adwords_keywords:
        special_instructions["adwords_keywords"] = order_data.adwords_keywords
    if order_data.adwords_period:
        special_instructions["adwords_period"] = order_data.adwords_period
    if order_data.adwords_location:
        special_instructions["adwords_location"] = order_data.adwords_location
    if order_data.adwords_keywords_list:
        special_instructions["adwords_keywords_list"] = order_data.adwords_keywords_list
    if order_data.special_guidelines:
        special_instructions["special_guidelines"] = order_data.special_guidelines
    
    order_data_jsonb = special_instructions if special_instructions else None
    
    # Client name and company name are the same - use company_name if provided, otherwise use full_name
    client_name = order_data.company_name or order_data.full_name or "Unknown"
    
    if existing_client:
        # Update existing client
        existing_client.name = client_name  # Name = Company Name (same thing)
        existing_client.company_name = order_data.company_name or existing_client.company_name
        existing_client.contact_person = order_data.full_name or existing_client.contact_person
        existing_client.designation = order_data.designation or existing_client.designation
        existing_client.address = order_data.address or existing_client.address
        existing_client.phone = order_data.phone or existing_client.phone
        existing_client.email = order_data.email or existing_client.email
        existing_client.domain_name = order_data.domain_name or existing_client.domain_name
        existing_client.gst_no = order_data.gst_no or existing_client.gst_no
        existing_client.package_amount = package_amount
        existing_client.gst_amount = gst_amount
        existing_client.total_amount = total_amount
        existing_client.customer_no = customer_no
        existing_client.order_date = order_date or existing_client.order_date
        existing_client.order_data = order_data_jsonb or existing_client.order_data
        client = existing_client
    else:
        # Create new client
        client = Client(
            client_id=client_id,
            name=client_name,  # Name = Company Name (same thing)
            status="active",
            company_name=order_data.company_name or client_name,  # Use same value
            contact_person=order_data.full_name,
            designation=order_data.designation,
            address=order_data.address,
            phone=order_data.phone,
            email=order_data.email,
            domain_name=order_data.domain_name,
            gst_no=order_data.gst_no,
            package_amount=package_amount,
            gst_amount=gst_amount,
            total_amount=total_amount,
            customer_no=customer_no,
            order_date=order_date,
            order_data=order_data_jsonb
        )
        db.add(client)
        await db.flush()
    
    # Handle services
    services_count = 0
    
    # Service mapping from form codes to service names and categories
    service_map = {
        "domain-hosting": ("Domain & Hosting", "Domain & Hosting"),
        "pop-id": ("POP ID", "Domain & Hosting"),
        "g-suite-id": ("G Suite ID", "Domain & Hosting"),
        "website-design-development": ("Website Design / Development", "Web Design"),
        "website-maintenance": ("Website Maintenance", "Web Design"),
        "app-development": ("App Development", "Web Design"),
        "seo": ("Search Engine Optimization", "SEO"),
        "google-ads": ("Google Ads / PPC", "SEO"),
        "google-my-business": ("Google My Business (Local)", "SEO"),
        "ai-chatbot": ("AI Chatbot", "Additional Services"),
        "youtube-promotion": ("YouTube Promotion", "Additional Services"),
        "email-marketing": ("Email Marketing", "Additional Services"),
    }
    
    # Process main services
    if order_data.services:
        for service_code in order_data.services:
            if service_code in service_map:
                name, category = service_map[service_code]
                service = await get_or_create_service(service_code, name, category, db)
                
                # Check if client-service already exists
                result = await db.execute(
                    select(ClientService).where(
                        and_(
                            ClientService.client_id == client_id,
                            ClientService.service_id == service.id
                        )
                    )
                )
                existing = result.scalar_one_or_none()
                
                if not existing:
                    client_service = ClientService(
                        id=uuid.uuid4(),
                        client_id=client_id,
                        service_id=service.id,
                        quantity=None,
                        status="active"
                    )
                    db.add(client_service)
                    services_count += 1
    
    # Process email services with quantities
    if order_data.email_services:
        for service_code in order_data.email_services:
            if service_code == "pop-id" and order_data.pop_id_count:
                service = await get_or_create_service("pop-id", "POP ID", "Domain & Hosting", db)
                result = await db.execute(
                    select(ClientService).where(
                        and_(
                            ClientService.client_id == client_id,
                            ClientService.service_id == service.id
                        )
                    )
                )
                existing = result.scalar_one_or_none()
                if not existing:
                    client_service = ClientService(
                        id=uuid.uuid4(),
                        client_id=client_id,
                        service_id=service.id,
                        quantity=order_data.pop_id_count,
                        status="active"
                    )
                    db.add(client_service)
                    services_count += 1
            elif service_code == "g-suite-id" and order_data.g_suite_id_count:
                service = await get_or_create_service("g-suite-id", "G Suite ID", "Domain & Hosting", db)
                result = await db.execute(
                    select(ClientService).where(
                        and_(
                            ClientService.client_id == client_id,
                            ClientService.service_id == service.id
                        )
                    )
                )
                existing = result.scalar_one_or_none()
                if not existing:
                    client_service = ClientService(
                        id=uuid.uuid4(),
                        client_id=client_id,
                        service_id=service.id,
                        quantity=order_data.g_suite_id_count,
                        status="active"
                    )
                    db.add(client_service)
                    services_count += 1
    
    await db.commit()
    await db.refresh(client)
    
    return OrderResponse(
        client_id=client.client_id,
        customer_no=customer_no,
        package_amount=package_amount,
        gst_amount=gst_amount,
        total_amount=total_amount,
        services_count=services_count,
        created_at=client.created_at
    )


# Transaction Routes
@app.post("/transactions", response_model=TransactionResponse, status_code=status.HTTP_201_CREATED)
async def create_transaction(
    transaction_data: TransactionCreate,
    db: AsyncSession = Depends(get_db)
):
    """Create a new transaction (pending verification)"""
    # Validate client exists
    result = await db.execute(select(Client).where(Client.client_id == transaction_data.client_id))
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Client {transaction_data.client_id} not found"
        )
    
    # Check if transaction_id already exists
    result = await db.execute(
        select(Transaction).where(Transaction.transaction_id == transaction_data.transaction_id)
    )
    existing = result.scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Transaction ID '{transaction_data.transaction_id}' already exists"
        )
    
    # Create transaction
    created_by_user_id = None
    if transaction_data.created_by_user_id:
        try:
            created_by_user_id = uuid.UUID(transaction_data.created_by_user_id)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid created_by_user_id format"
            )
    
    new_transaction = Transaction(
        id=uuid.uuid4(),
        client_id=transaction_data.client_id,
        transaction_id=transaction_data.transaction_id,
        amount=transaction_data.amount,
        payment_method=transaction_data.payment_method,
        status="pending",
        created_by_user_id=created_by_user_id,
        notes=transaction_data.notes
    )
    
    db.add(new_transaction)
    await db.commit()
    await db.refresh(new_transaction)
    
    # Fetch user email for created_by
    created_by_email = None
    if new_transaction.created_by_user_id:
        from sqlalchemy import select as sql_select
        user_result = await db.execute(sql_select(User).where(User.id == new_transaction.created_by_user_id))
        user = user_result.scalar_one_or_none()
        created_by_email = user.email if user else None
    
    return TransactionResponse(
        id=str(new_transaction.id),
        client_id=new_transaction.client_id,
        transaction_id=new_transaction.transaction_id,
        amount=new_transaction.amount,
        payment_method=new_transaction.payment_method,
        status=new_transaction.status,
        created_by_user_id=str(new_transaction.created_by_user_id) if new_transaction.created_by_user_id else None,
        created_by_user_email=created_by_email,
        verified_by_user_id=str(new_transaction.verified_by_user_id) if new_transaction.verified_by_user_id else None,
        verified_by_user_email=None,
        verified_at=new_transaction.verified_at,
        rejection_reason=new_transaction.rejection_reason,
        notes=new_transaction.notes,
        created_at=new_transaction.created_at,
        updated_at=new_transaction.updated_at
    )


@app.get("/transactions", response_model=List[TransactionResponse])
async def list_transactions(
    client_id: Optional[str] = None,
    status_filter: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db)
):
    """List transactions with optional filtering"""
    query = select(Transaction)
    
    if client_id:
        query = query.where(Transaction.client_id == client_id)
    if status_filter:
        query = query.where(Transaction.status == status_filter)
    
    query = query.order_by(Transaction.created_at.desc()).offset(skip).limit(limit)
    result = await db.execute(query)
    transactions = result.scalars().all()
    
    # Fetch user emails for created_by and verified_by
    user_ids = set()
    for t in transactions:
        if t.created_by_user_id:
            user_ids.add(t.created_by_user_id)
        if t.verified_by_user_id:
            user_ids.add(t.verified_by_user_id)
    
    # Get user emails
    user_emails = {}
    if user_ids:
        from sqlalchemy import select as sql_select
        user_query = sql_select(User).where(User.id.in_(user_ids))
        user_result = await db.execute(user_query)
        users = user_result.scalars().all()
        user_emails = {str(user.id): user.email for user in users}
    
    return [
        TransactionResponse(
            id=str(t.id),
            client_id=t.client_id,
            transaction_id=t.transaction_id,
            amount=t.amount,
            payment_method=t.payment_method,
            status=t.status,
            created_by_user_id=str(t.created_by_user_id) if t.created_by_user_id else None,
            created_by_user_email=user_emails.get(str(t.created_by_user_id)) if t.created_by_user_id else None,
            verified_by_user_id=str(t.verified_by_user_id) if t.verified_by_user_id else None,
            verified_by_user_email=user_emails.get(str(t.verified_by_user_id)) if t.verified_by_user_id else None,
            verified_at=t.verified_at,
            rejection_reason=t.rejection_reason,
            notes=t.notes,
            created_at=t.created_at,
            updated_at=t.updated_at
        )
        for t in transactions
    ]


@app.get("/transactions/{transaction_id}", response_model=TransactionResponse)
async def get_transaction(transaction_id: str, db: AsyncSession = Depends(get_db)):
    """Get transaction by ID"""
    result = await db.execute(select(Transaction).where(Transaction.id == uuid.UUID(transaction_id)))
    transaction = result.scalar_one_or_none()
    
    if not transaction:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Transaction {transaction_id} not found"
        )
    
    # Fetch user emails for created_by and verified_by
    created_by_email = None
    verified_by_email = None
    
    if transaction.created_by_user_id:
        from sqlalchemy import select as sql_select
        user_result = await db.execute(sql_select(User).where(User.id == transaction.created_by_user_id))
        user = user_result.scalar_one_or_none()
        created_by_email = user.email if user else None
    
    if transaction.verified_by_user_id:
        from sqlalchemy import select as sql_select
        user_result = await db.execute(sql_select(User).where(User.id == transaction.verified_by_user_id))
        user = user_result.scalar_one_or_none()
        verified_by_email = user.email if user else None
    
    return TransactionResponse(
        id=str(transaction.id),
        client_id=transaction.client_id,
        transaction_id=transaction.transaction_id,
        amount=transaction.amount,
        payment_method=transaction.payment_method,
        status=transaction.status,
        created_by_user_id=str(transaction.created_by_user_id) if transaction.created_by_user_id else None,
        created_by_user_email=created_by_email,
        verified_by_user_id=str(transaction.verified_by_user_id) if transaction.verified_by_user_id else None,
        verified_by_user_email=verified_by_email,
        verified_at=transaction.verified_at,
        rejection_reason=transaction.rejection_reason,
        notes=transaction.notes,
        created_at=transaction.created_at,
        updated_at=transaction.updated_at
    )


@app.patch("/transactions/{transaction_id}/verify", response_model=TransactionResponse)
async def verify_transaction(
    transaction_id: str,
    transaction_data: TransactionUpdate,
    db: AsyncSession = Depends(get_db)
):
    """Verify or reject a transaction (admin only)"""
    result = await db.execute(select(Transaction).where(Transaction.id == uuid.UUID(transaction_id)))
    transaction = result.scalar_one_or_none()
    
    if not transaction:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Transaction {transaction_id} not found"
        )
    
    if transaction.status != "pending":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Transaction is already {transaction.status}"
        )
    
    if transaction_data.status not in ["verified", "rejected"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Status must be 'verified' or 'rejected'"
        )
    
    # Validate rejection_reason is provided when rejecting
    if transaction_data.status == "rejected" and not transaction_data.rejection_reason:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Rejection reason is required when rejecting a transaction"
        )
    
    # Update transaction status and verification details
    transaction.status = transaction_data.status
    if transaction_data.verified_by_user_id:
        transaction.verified_by_user_id = uuid.UUID(transaction_data.verified_by_user_id)
    transaction.verified_at = datetime.now()
    
    # Set rejection reason if provided
    if transaction_data.rejection_reason:
        transaction.rejection_reason = transaction_data.rejection_reason
    
    # Update notes if provided
    if transaction_data.notes:
        transaction.notes = transaction_data.notes
    
    await db.commit()
    await db.refresh(transaction)
    
    # Fetch user emails for created_by and verified_by
    created_by_email = None
    verified_by_email = None
    
    if transaction.created_by_user_id:
        from sqlalchemy import select as sql_select
        user_result = await db.execute(sql_select(User).where(User.id == transaction.created_by_user_id))
        user = user_result.scalar_one_or_none()
        created_by_email = user.email if user else None
    
    if transaction.verified_by_user_id:
        from sqlalchemy import select as sql_select
        user_result = await db.execute(sql_select(User).where(User.id == transaction.verified_by_user_id))
        user = user_result.scalar_one_or_none()
        verified_by_email = user.email if user else None
    
    return TransactionResponse(
        id=str(transaction.id),
        client_id=transaction.client_id,
        transaction_id=transaction.transaction_id,
        amount=transaction.amount,
        payment_method=transaction.payment_method,
        status=transaction.status,
        created_by_user_id=str(transaction.created_by_user_id) if transaction.created_by_user_id else None,
        created_by_user_email=created_by_email,
        verified_by_user_id=str(transaction.verified_by_user_id) if transaction.verified_by_user_id else None,
        verified_by_user_email=verified_by_email,
        verified_at=transaction.verified_at,
        rejection_reason=transaction.rejection_reason,
        notes=transaction.notes,
        created_at=transaction.created_at,
        updated_at=transaction.updated_at
    )


@app.get("/clients/{client_id}/balance")
async def get_client_balance(client_id: str, db: AsyncSession = Depends(get_db)):
    """Get client's payment balance (total amount, paid amount, remaining)"""
    # Get client
    result = await db.execute(select(Client).where(Client.client_id == client_id))
    client = result.scalar_one_or_none()
    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Client {client_id} not found"
        )
    
    # Get all verified transactions
    result = await db.execute(
        select(Transaction).where(
            and_(
                Transaction.client_id == client_id,
                Transaction.status == "verified"
            )
        )
    )
    transactions = result.scalars().all()
    
    total_amount = client.total_amount or Decimal("0")
    paid_amount = sum(t.amount for t in transactions)
    remaining_amount = total_amount - paid_amount
    
    return {
        "client_id": client_id,
        "total_amount": float(total_amount),
        "paid_amount": float(paid_amount),
        "remaining_amount": float(remaining_amount),
        "transactions_count": len(transactions)
    }


@app.get("/health")
async def health():
    """Health check"""
    return {"status": "healthy", "service": "client_service"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)

