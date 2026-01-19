"""
Content Service - About Us and Contact Details for Order Panel
"""
from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, EmailStr
from typing import Optional, List, Dict, Any
from datetime import datetime
import sys
import os
import logging

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from shared.database import get_db
from shared.models.base import BaseModel as BaseDBModel
from sqlalchemy import Column, String, DateTime, JSON
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
from sqlalchemy.sql import func
import uuid

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Content Service", version="1.0.0")


# Database Models
class AboutUs(BaseDBModel):
    __tablename__ = "about_us"
    
    title = Column(String, nullable=True)
    subtitle = Column(String, nullable=True)
    description = Column(String, nullable=True)
    status = Column(String, default="active", nullable=False)


class ContactDetails(BaseDBModel):
    __tablename__ = "contact_details"
    
    company_name = Column(String, nullable=True)
    email = Column(ARRAY(String), nullable=True)  # Array of emails
    phone = Column(ARRAY(String), nullable=True)  # Array of phones
    address = Column(String, nullable=True)
    website = Column(ARRAY(String), nullable=True)  # Array of websites
    social_media = Column(JSONB, nullable=True)  # JSON object: {facebook: "url", linkedin: "url", instagram: "url", youtube: "url"}
    status = Column(String, default="active", nullable=False)


# Pydantic Schemas
class AboutUsResponse(BaseModel):
    id: str
    title: Optional[str] = None
    subtitle: Optional[str] = None
    description: Optional[str] = None
    status: str
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class ContactDetailsResponse(BaseModel):
    id: str
    company_name: Optional[str] = None
    email: Optional[List[str]] = None  # Array of emails
    phone: Optional[List[str]] = None  # Array of phones
    address: Optional[str] = None
    website: Optional[List[str]] = None  # Array of websites
    social_media: Optional[Dict[str, Any]] = None  # {facebook: "url", linkedin: "url", etc.}
    status: str
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class AboutUsCreate(BaseModel):
    title: Optional[str] = None
    subtitle: Optional[str] = None
    description: Optional[str] = None
    status: str = "active"


class AboutUsUpdate(BaseModel):
    title: Optional[str] = None
    subtitle: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None


class ContactDetailsCreate(BaseModel):
    company_name: Optional[str] = None
    email: Optional[List[str]] = None  # Array of emails
    phone: Optional[List[str]] = None  # Array of phones
    address: Optional[str] = None
    website: Optional[List[str]] = None  # Array of websites
    social_media: Optional[Dict[str, Any]] = None  # {facebook: "url", linkedin: "url", instagram: "url", youtube: "url"}
    status: str = "active"


class ContactDetailsUpdate(BaseModel):
    company_name: Optional[str] = None
    email: Optional[List[str]] = None
    phone: Optional[List[str]] = None
    address: Optional[str] = None
    website: Optional[List[str]] = None
    social_media: Optional[Dict[str, Any]] = None
    status: Optional[str] = None


# Routes
@app.get("/about-us", response_model=AboutUsResponse)
async def get_about_us(db: AsyncSession = Depends(get_db)):
    """Get About Us content (public endpoint for ordpanel)"""
    try:
        query = select(AboutUs).where(AboutUs.status == "active").order_by(AboutUs.created_at.desc())
        result = await db.execute(query)
        about_us = result.scalar_one_or_none()
        
        if not about_us:
            # Return empty response if no data
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="About Us content not found"
            )
        
        return AboutUsResponse(
            id=str(about_us.id),
            title=about_us.title,
            subtitle=about_us.subtitle,
            description=about_us.description,
            status=about_us.status,
            created_at=about_us.created_at,
            updated_at=about_us.updated_at
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching about us: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error fetching about us content: {str(e)}"
        )


@app.post("/about-us", response_model=AboutUsResponse)
async def create_about_us(about_us_data: AboutUsCreate, db: AsyncSession = Depends(get_db)):
    """Create About Us content (admin only)"""
    try:
        # Check if about_us already exists
        existing = await db.execute(select(AboutUs).where(AboutUs.status == "active"))
        if existing.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="About Us content already exists. Use PUT to update."
            )
        
        about_us = AboutUs(
            id=uuid.uuid4(),
            title=about_us_data.title,
            subtitle=about_us_data.subtitle,
            description=about_us_data.description,
            status=about_us_data.status
        )
        
        db.add(about_us)
        await db.commit()
        await db.refresh(about_us)
        
        return AboutUsResponse(
            id=str(about_us.id),
            title=about_us.title,
            subtitle=about_us.subtitle,
            description=about_us.description,
            status=about_us.status,
            created_at=about_us.created_at,
            updated_at=about_us.updated_at
        )
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Error creating about us: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error creating about us content: {str(e)}"
        )


@app.put("/about-us/{about_us_id}", response_model=AboutUsResponse)
async def update_about_us(about_us_id: str, about_us_data: AboutUsUpdate, db: AsyncSession = Depends(get_db)):
    """Update About Us content (admin only)"""
    try:
        result = await db.execute(select(AboutUs).where(AboutUs.id == uuid.UUID(about_us_id)))
        about_us = result.scalar_one_or_none()
        
        if not about_us:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="About Us content not found"
            )
        
        # Update fields
        if about_us_data.title is not None:
            about_us.title = about_us_data.title
        if about_us_data.subtitle is not None:
            about_us.subtitle = about_us_data.subtitle
        if about_us_data.description is not None:
            about_us.description = about_us_data.description
        if about_us_data.status is not None:
            about_us.status = about_us_data.status
        
        about_us.updated_at = func.now()
        
        await db.commit()
        await db.refresh(about_us)
        
        return AboutUsResponse(
            id=str(about_us.id),
            title=about_us.title,
            subtitle=about_us.subtitle,
            description=about_us.description,
            status=about_us.status,
            created_at=about_us.created_at,
            updated_at=about_us.updated_at
        )
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Error updating about us: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error updating about us content: {str(e)}"
        )


@app.get("/contact-details", response_model=ContactDetailsResponse)
async def get_contact_details(db: AsyncSession = Depends(get_db)):
    """Get Contact Details (public endpoint for ordpanel)"""
    try:
        query = select(ContactDetails).where(ContactDetails.status == "active").order_by(ContactDetails.created_at.desc())
        result = await db.execute(query)
        contact = result.scalar_one_or_none()
        
        if not contact:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Contact details not found"
            )
        
        return ContactDetailsResponse(
            id=str(contact.id),
            company_name=contact.company_name,
            email=contact.email,
            phone=contact.phone,
            address=contact.address,
            website=contact.website,
            social_media=contact.social_media,
            status=contact.status,
            created_at=contact.created_at,
            updated_at=contact.updated_at
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching contact details: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error fetching contact details: {str(e)}"
        )


@app.post("/contact-details", response_model=ContactDetailsResponse)
async def create_contact_details(contact_data: ContactDetailsCreate, db: AsyncSession = Depends(get_db)):
    """Create Contact Details (admin only)"""
    try:
        # Check if contact details already exist
        existing = await db.execute(select(ContactDetails).where(ContactDetails.status == "active"))
        if existing.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Contact details already exist. Use PUT to update."
            )
        
        contact = ContactDetails(
            id=uuid.uuid4(),
            company_name=contact_data.company_name,
            email=contact_data.email,  # Array of emails
            phone=contact_data.phone,  # Array of phones
            address=contact_data.address,
            website=contact_data.website,  # Array of websites
            social_media=contact_data.social_media,  # JSON object
            status=contact_data.status
        )
        
        db.add(contact)
        await db.commit()
        await db.refresh(contact)
        
        return ContactDetailsResponse(
            id=str(contact.id),
            company_name=contact.company_name,
            email=contact.email,
            phone=contact.phone,
            address=contact.address,
            website=contact.website,
            social_media=contact.social_media,
            status=contact.status,
            created_at=contact.created_at,
            updated_at=contact.updated_at
        )
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Error creating contact details: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error creating contact details: {str(e)}"
        )


@app.put("/contact-details/{contact_id}", response_model=ContactDetailsResponse)
async def update_contact_details(contact_id: str, contact_data: ContactDetailsUpdate, db: AsyncSession = Depends(get_db)):
    """Update Contact Details (admin only)"""
    try:
        result = await db.execute(select(ContactDetails).where(ContactDetails.id == uuid.UUID(contact_id)))
        contact = result.scalar_one_or_none()
        
        if not contact:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Contact details not found"
            )
        
        # Update fields
        if contact_data.company_name is not None:
            contact.company_name = contact_data.company_name
        if contact_data.email is not None:
            contact.email = contact_data.email  # Array of emails
        if contact_data.phone is not None:
            contact.phone = contact_data.phone  # Array of phones
        if contact_data.address is not None:
            contact.address = contact_data.address
        if contact_data.website is not None:
            contact.website = contact_data.website  # Array of websites
        if contact_data.social_media is not None:
            contact.social_media = contact_data.social_media  # JSON object
        if contact_data.status is not None:
            contact.status = contact_data.status
        
        contact.updated_at = func.now()
        
        await db.commit()
        await db.refresh(contact)
        
        return ContactDetailsResponse(
            id=str(contact.id),
            company_name=contact.company_name,
            email=contact.email,
            phone=contact.phone,
            address=contact.address,
            website=contact.website,
            social_media=contact.social_media,
            status=contact.status,
            created_at=contact.created_at,
            updated_at=contact.updated_at
        )
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        logger.error(f"Error updating contact details: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error updating contact details: {str(e)}"
        )


@app.get("/health")
async def health():
    """Health check"""
    return {"status": "healthy", "service": "content_service"}

