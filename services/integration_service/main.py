"""
Integration Service - Twilio WhatsApp and Google Sheets integration
"""
from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from datetime import datetime
import sys
import os
import httpx
import json
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from twilio.rest import Client as TwilioClient

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from shared.database import get_db
from shared.models.base import BaseModel as BaseDBModel, BaseModelNoID
from shared.utils.http_client import ServiceClient
from sqlalchemy import Column, String, ForeignKey, JSON, DateTime
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import UUID, JSONB
import uuid

app = FastAPI(title="Integration Service", version="1.0.0")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration - Twilio WhatsApp
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_WHATSAPP_FROM = os.getenv("TWILIO_WHATSAPP_FROM")  # Format: whatsapp:+14155238886
GOOGLE_SERVICE_ACCOUNT_FILE = os.getenv("GOOGLE_SERVICE_ACCOUNT_FILE")

# Email Configuration (using SMTP - free)
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")  # Email address for SMTP auth
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")  # App password or regular password
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", SMTP_USER)  # From email address
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")  # Admin email to receive notifications

# Service clients
LEAD_SERVICE_URL = os.getenv("LEAD_SERVICE_URL", "http://lead_service:8004")
CLIENT_SERVICE_URL = os.getenv("CLIENT_SERVICE_URL", "http://client_service:8002")
lead_client = ServiceClient(LEAD_SERVICE_URL)
client_client = ServiceClient(CLIENT_SERVICE_URL)
client_client = ServiceClient(CLIENT_SERVICE_URL)


# Database Models
class Client(BaseModelNoID):
    __tablename__ = "clients"
    
    client_id = Column(String, primary_key=True, unique=True, nullable=False, index=True)
    name = Column(String, nullable=False)
    status = Column(String, default="active", nullable=False)


class Lead(BaseDBModel):
    __tablename__ = "leads"
    
    client_id = Column(String, ForeignKey("clients.client_id"), nullable=False, index=True)
    created_by_user_client_id = Column(UUID(as_uuid=True), ForeignKey("user_clients.id"), nullable=True)
    name = Column(String, nullable=True)
    email = Column(String, nullable=True, index=True)
    phone = Column(String, nullable=True, index=True)
    source = Column(String, nullable=False, index=True)
    lead_reference_id = Column(String, nullable=True, index=True)
    raw_payload = Column(JSONB, nullable=True)


class ClientIntegration(BaseModelNoID):
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
class ProcessLeadRequest(BaseModel):
    lead_id: str
    client_id: str


class WhatsAppMessageRequest(BaseModel):
    phone_number: str
    message_body: str  # Changed from template_name to message_body for Twilio
    template_name: Optional[str] = None  # Keep for backward compatibility
    template_params: Optional[Dict[str, Any]] = None
    lead_reference_id: Optional[str] = None


class ClientIntegrationUpdate(BaseModel):
    whatsapp_enabled: Optional[str] = None
    google_sheets_enabled: Optional[str] = None
    google_sheet_id: Optional[str] = None
    meta_page_id: Optional[str] = None
    meta_form_id: Optional[str] = None
    config: Optional[Dict[str, Any]] = None


class ClientIntegrationResponse(BaseModel):
    client_id: str
    whatsapp_enabled: str
    google_sheets_enabled: str
    google_sheet_id: Optional[str] = None
    meta_page_id: Optional[str] = None
    meta_form_id: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


# Helper Functions
def format_raw_payload_readable(raw_payload: Optional[Dict[str, Any]], exclude_fields: Optional[set] = None) -> str:
    """Format raw_payload into readable text, excluding security fields and duplicate fields"""
    if not raw_payload:
        return ""
    
    # Security fields to exclude
    security_fields = {
        'csrf_token', 'csrf', 'csrf_token_field', 'csrfmiddlewaretoken',
        'captcha', 'recaptcha', 'recaptcha_token', 'recaptcha_response',
        'hcaptcha', 'hcaptcha_token', 'hcaptcha_response',
        'g-recaptcha-response', 'g_recaptcha_response',
        'token', 'security_token', 'auth_token',
        '_token', '__token', '__csrf',
        'session_id', 'sessionid',
        'file_upload_url', 'file_upload_id'  # File upload references
    }
    
    # Fields that are already shown in the main message (to avoid duplicates)
    duplicate_fields = {
        'email', 'mobile', 'phone', 'full_name', 'name', 
        'domain', 'form_timestamp', 'owner_emails'
    }
    
    # Merge exclude_fields if provided
    if exclude_fields:
        duplicate_fields.update(exclude_fields)
    
    formatted_lines = []
    for key, value in raw_payload.items():
        # Skip security fields (case-insensitive)
        if any(sec_field.lower() in key.lower() for sec_field in security_fields):
            continue
        
        # Skip duplicate fields (case-insensitive)
        if any(dup_field.lower() == key.lower() for dup_field in duplicate_fields):
            continue
        
        # Skip empty values
        if value is None or value == "":
            continue
        
        # Format key (make it readable)
        formatted_key = key.replace('_', ' ').title()
        
        # Format value
        if isinstance(value, (list, dict)):
            # For arrays/objects, convert to readable format
            if isinstance(value, list):
                formatted_value = ", ".join(str(v) for v in value if v)
            else:
                formatted_value = ", ".join(f"{k}: {v}" for k, v in value.items() if v)
        else:
            formatted_value = str(value)
        
        formatted_lines.append(f"{formatted_key}: {formatted_value}")
    
    return "\n".join(formatted_lines)


def send_email_smtp(
    to_email: str,
    subject: str,
    body_text: str,
    body_html: Optional[str] = None
) -> Dict[str, Any]:
    """Send email using SMTP (free library)"""
    if not SMTP_USER or not SMTP_PASSWORD:
        return {"error": "SMTP not configured"}
    
    try:
        # Create message
        msg = MIMEMultipart('alternative')
        msg['From'] = SMTP_FROM_EMAIL
        msg['To'] = to_email
        msg['Subject'] = subject
        
        # Add text and HTML parts
        text_part = MIMEText(body_text, 'plain')
        msg.attach(text_part)
        
        if body_html:
            html_part = MIMEText(body_html, 'html')
            msg.attach(html_part)
        
        # Connect to SMTP server and send
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        
        return {"status": "sent", "to": to_email}
    except Exception as e:
        return {"error": str(e), "to": to_email}


# Twilio WhatsApp Functions
async def send_whatsapp_message(
    phone_number: str,
    message_body: str
) -> Dict[str, Any]:
    """Send WhatsApp message via Twilio"""
    if not TWILIO_ACCOUNT_SID or not TWILIO_AUTH_TOKEN or not TWILIO_WHATSAPP_FROM:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Twilio WhatsApp not configured"
        )
    
    try:
        # Initialize Twilio client
        twilio_client = TwilioClient(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        
        # Format phone number - ensure it starts with whatsapp: prefix
        if not phone_number.startswith("whatsapp:"):
            # Remove any existing +, spaces, dashes
            clean_phone = phone_number.replace("+", "").replace(" ", "").replace("-", "")
            # Add + if not present and whatsapp: prefix
            if not clean_phone.startswith("+"):
                clean_phone = "+" + clean_phone
            phone_number = f"whatsapp:{clean_phone}"
        
        # Send WhatsApp message
        message = twilio_client.messages.create(
            body=message_body,
            from_=TWILIO_WHATSAPP_FROM,  # Format: whatsapp:+14155238886
            to=phone_number
        )
        
        return {
            "status": "sent",
            "message_sid": message.sid,
            "to": message.to,
            "from": message.from_,
            "status_detail": message.status
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Twilio WhatsApp error: {str(e)}"
        )


# Google Sheets Functions
async def append_to_google_sheets(
    client_id: str,
    lead_data: Dict[str, Any],
    db: AsyncSession
) -> Dict[str, Any]:
    """Append lead to Google Sheets using Service Account"""
    if not GOOGLE_SERVICE_ACCOUNT_FILE:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Google Sheets not configured"
        )
    
    try:
        from google.oauth2 import service_account
        from googleapiclient.discovery import build
        from googleapiclient.errors import HttpError
        import json
        
        # Load service account credentials
        if not os.path.exists(GOOGLE_SERVICE_ACCOUNT_FILE):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Service account file not found: {GOOGLE_SERVICE_ACCOUNT_FILE}"
            )
        
        credentials = service_account.Credentials.from_service_account_file(
            GOOGLE_SERVICE_ACCOUNT_FILE,
            scopes=['https://www.googleapis.com/auth/spreadsheets']
        )
        
        # Build Sheets API client
        service = build('sheets', 'v4', credentials=credentials)
        
        # Get sheet ID from client integration
        result = await db.execute(
            select(ClientIntegration).where(ClientIntegration.client_id == client_id)
        )
        integration = result.scalar_one_or_none()
        
        if not integration or not integration.google_sheet_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Google Sheet ID not configured for client {client_id}"
            )
        
        sheet_id = integration.google_sheet_id
        
        # Prepare row data
        # Columns: Lead ID, Name, Email, Phone, Source, Created At, Extra Data (JSON)
        row_data = [
            lead_data.get("lead_id", ""),
            lead_data.get("name", ""),
            lead_data.get("email", ""),
            lead_data.get("phone", ""),
            lead_data.get("source", ""),
            lead_data.get("created_at", ""),
            json.dumps(lead_data.get("raw_payload", {})) if lead_data.get("raw_payload") else ""
        ]
        
        # Append to sheet
        body = {
            'values': [row_data]
        }
        
        result = service.spreadsheets().values().append(
            spreadsheetId=sheet_id,
            range='A1',  # Append to first sheet, starting at A1
            valueInputOption='USER_ENTERED',
            insertDataOption='INSERT_ROWS',
            body=body
        ).execute()
        
        return {
            "success": True,
            "lead_id": lead_data.get("lead_id"),
            "client_id": client_id,
            "updated_cells": result.get('updates', {}).get('updatedCells', 0),
            "updated_range": result.get('updates', {}).get('updatedRange', '')
        }
        
    except HttpError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Google Sheets API error: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Google Sheets error: {str(e)}"
        )


# Routes
@app.post("/process-lead", status_code=status.HTTP_202_ACCEPTED)
async def process_lead(
    request: ProcessLeadRequest,
    db: AsyncSession = Depends(get_db)
):
    """Process a lead (triggered by lead creation)"""
    # Get lead data
    result = await db.execute(
        select(Lead).where(Lead.id == uuid.UUID(request.lead_id))
    )
    lead = result.scalar_one_or_none()
    
    if not lead:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Lead {request.lead_id} not found"
        )
    
    # Get client integration config
    # Explicitly select columns to avoid id column issue
    result = await db.execute(
        select(
            ClientIntegration.client_id,
            ClientIntegration.whatsapp_enabled,
            ClientIntegration.google_sheets_enabled,
            ClientIntegration.google_sheet_id,
            ClientIntegration.meta_page_id,
            ClientIntegration.meta_form_id,
            ClientIntegration.config,
            ClientIntegration.created_at,
            ClientIntegration.updated_at
        ).where(ClientIntegration.client_id == request.client_id)
    )
    integration_row = result.first()
    
    # Convert row to object-like structure
    integration = None
    if integration_row:
        integration = type('ClientIntegration', (), {
            'client_id': integration_row.client_id,
            'whatsapp_enabled': integration_row.whatsapp_enabled,
            'google_sheets_enabled': integration_row.google_sheets_enabled,
            'google_sheet_id': integration_row.google_sheet_id,
            'meta_page_id': integration_row.meta_page_id,
            'meta_form_id': integration_row.meta_form_id,
            'config': integration_row.config,
            'created_at': integration_row.created_at,
            'updated_at': integration_row.updated_at
        })()
    
    # Trigger Celery background tasks for async processing
    from celery import Celery
    
    # Initialize Celery client (same config as celery_worker)
    REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
    celery_app = Celery(
        "integration_service",
        broker=REDIS_URL,
        backend=REDIS_URL
    )
    celery_app.conf.update(
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        timezone="UTC",
        enable_utc=True,
    )
    
    # Prepare lead data for background processing
    lead_data_dict = {
        "lead_id": str(lead.id),
        "name": lead.name,
        "email": lead.email,
        "phone": lead.phone,
        "source": lead.source,
        "lead_reference_id": lead.lead_reference_id,
        "client_id": lead.client_id,
        "created_at": lead.created_at.isoformat() if lead.created_at else None,
        "raw_payload": lead.raw_payload
    }
    
    # Get client data (for phone and email)
    client_data = None
    try:
        logger.info(f"Fetching client data for client_id: {request.client_id}")
        client_response = await client_client.get(f"/clients/{request.client_id}")
        logger.info(f"Client service response: {client_response}")
        
        # Handle different response structures
        if isinstance(client_response, dict):
            # Try different possible response structures
            client_data = (
                client_response.get("data") or 
                client_response.get("client") or 
                client_response
            )
        else:
            client_data = client_response
            
        logger.info(f"Extracted client_data: {client_data}")
        
        if not client_data:
            logger.warning(f"No client data found for client_id: {request.client_id}")
        elif not client_data.get("email") and not client_data.get("phone"):
            logger.warning(f"Client data found but missing email and phone: {client_data}")
    except Exception as e:
        logger.error(f"Failed to fetch client data from client service: {e}", exc_info=True)
        client_data = None
    
    # Check if file_link exists in raw_payload
    file_link = lead.raw_payload.get('file_link') if lead.raw_payload else None
    
    # Build base message content
    lead_name = lead.name or "Customer"
    lead_email = lead.email or "N/A"
    lead_phone = lead.phone or "N/A"
    lead_source = lead.source or "Unknown"
    
    base_message = f"""🎉 New Lead Received!

Name: {lead_name}
Email: {lead_email}
Phone: {lead_phone}
Source: {lead_source}
Lead ID: {str(lead.id)[:8]}"""
    
    # Add file link prominently if present
    if file_link:
        base_message += f"\n\n📎 File Attachment: {file_link}"
    
    # Format raw payload into readable text, excluding fields already shown in base message
    # Exclude: email, mobile, phone, full_name, name, domain, form_timestamp, owner_emails, file_link
    # Note: file_link is excluded from Form Details since it's shown above
    exclude_fields = {'email', 'mobile', 'phone', 'full_name', 'name', 'domain', 'form_timestamp', 'owner_emails', 'file_link'}
    formatted_raw_data = format_raw_payload_readable(lead.raw_payload, exclude_fields=exclude_fields)
    
    # Add formatted raw data if available (only if there's additional data beyond what's already shown)
    if formatted_raw_data:
        base_message += f"\n\n📋 Form Details:\n{formatted_raw_data}"
    
    base_message += "\n\nPlease follow up soon!"
    
    # Build HTML email version
    file_link_html = ""
    if file_link:
        file_link_html = f'<tr><td style="padding: 8px; font-weight: bold;">📎 File Attachment:</td><td style="padding: 8px;"><a href="{file_link}" style="color: #2196F3; text-decoration: none;">{file_link}</a></td></tr>'
    
    html_message = f"""
    <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <h2 style="color: #4CAF50;">🎉 New Lead Received!</h2>
            <table style="border-collapse: collapse; width: 100%; margin: 20px 0;">
                <tr><td style="padding: 8px; font-weight: bold;">Name:</td><td style="padding: 8px;">{lead_name}</td></tr>
                <tr><td style="padding: 8px; font-weight: bold;">Email:</td><td style="padding: 8px;">{lead_email}</td></tr>
                <tr><td style="padding: 8px; font-weight: bold;">Phone:</td><td style="padding: 8px;">{lead_phone}</td></tr>
                <tr><td style="padding: 8px; font-weight: bold;">Source:</td><td style="padding: 8px;">{lead_source}</td></tr>
                <tr><td style="padding: 8px; font-weight: bold;">Lead ID:</td><td style="padding: 8px;">{str(lead.id)[:8]}</td></tr>
                {file_link_html}
            </table>
            {f'<div style="margin: 20px 0;"><h3 style="color: #2196F3;">📋 Form Details:</h3><pre style="background: #f5f5f5; padding: 15px; border-radius: 5px; white-space: pre-wrap;">{formatted_raw_data}</pre></div>' if formatted_raw_data else ''}
            <p style="margin-top: 20px;">Please follow up soon!</p>
        </body>
    </html>
    """
    
    # Process WhatsApp (if enabled) - Send to CLIENT's phone number
    whatsapp_result = None
    logger.info(f"Checking WhatsApp configuration - integration exists: {integration is not None}, whatsapp_enabled: {integration.whatsapp_enabled if integration else 'N/A'}")
    
    if integration and integration.whatsapp_enabled == "true":
        try:
            if client_data and client_data.get("phone"):
                client_phone = client_data["phone"]
                logger.info(f"Queuing WhatsApp message to client phone: {client_phone}")
                
                task = celery_app.send_task(
                    "tasks.send_whatsapp_message",
                    kwargs={
                        "phone_number": client_phone,
                        "message_body": base_message
                    }
                )
                whatsapp_result = {"status": "queued", "task_id": task.id, "message": f"WhatsApp message queued to client phone: {client_phone}"}
                logger.info(f"WhatsApp message queued successfully - task_id: {task.id}, phone: {client_phone}")
            else:
                whatsapp_result = {"error": "Client phone number not found", "client_id": request.client_id, "client_data_keys": list(client_data.keys()) if client_data else None}
                logger.warning(f"Client phone number not found for client_id: {request.client_id}, client_data: {client_data}")
        except Exception as e:
            whatsapp_result = {"error": str(e)}
            logger.error(f"Failed to queue WhatsApp message: {e}", exc_info=True)
    else:
        if not integration:
            whatsapp_result = {"error": "ClientIntegration not found - WhatsApp disabled"}
            logger.info(f"ClientIntegration not found for client_id: {request.client_id}, WhatsApp not enabled")
        elif integration.whatsapp_enabled != "true":
            whatsapp_result = {"error": f"WhatsApp not enabled for this client (current value: '{integration.whatsapp_enabled}')"}
            logger.info(f"WhatsApp not enabled for client_id: {request.client_id}, current value: '{integration.whatsapp_enabled}'")
    
    # Process Emails - Send to 3 recipients
    # Note: Emails should be sent regardless of integration config
    email_result = {"client": None, "admin": None, "auto_reply": None}
    
    logger.info(f"Processing emails - client_data exists: {client_data is not None}, client_email: {client_data.get('email') if client_data else 'N/A'}")
    
    # Email 1: To Client Email (always try to send if client email exists)
    if client_data and client_data.get("email"):
        try:
            client_email = client_data["email"]
            logger.info(f"Queuing email to client: {client_email}")
            
            task = celery_app.send_task(
                "tasks.send_email",
                kwargs={
                    "to_email": client_email,
                    "subject": f"New Lead Received - {lead_name}",
                    "body_text": base_message,
                    "body_html": html_message
                }
            )
            email_result["client"] = {"status": "queued", "task_id": task.id, "to": client_email}
            logger.info(f"Email queued successfully to client - task_id: {task.id}, email: {client_email}")
        except Exception as e:
            email_result["client"] = {"error": str(e)}
            logger.error(f"Failed to queue email to client: {e}", exc_info=True)
    else:
        email_result["client"] = {
            "error": f"Client email not found for client_id: {request.client_id}",
            "client_data_keys": list(client_data.keys()) if client_data else None,
            "client_data": client_data
        }
        logger.warning(f"Client email not found for client_id: {request.client_id}, client_data: {client_data}")
    
    # Email 2: To Admin Email
    if ADMIN_EMAIL:
        try:
            task = celery_app.send_task(
                "tasks.send_email",
                kwargs={
                    "to_email": ADMIN_EMAIL,
                    "subject": f"[Admin] New Lead - {lead_name} - Client: {request.client_id}",
                    "body_text": base_message,
                    "body_html": html_message
                }
            )
            email_result["admin"] = {"status": "queued", "task_id": task.id, "to": ADMIN_EMAIL}
        except Exception as e:
            email_result["admin"] = {"error": str(e)}
    
    # Email 3: Auto-reply to Lead (if lead has email)
    if lead.email:
        auto_reply_message = f"""Thank you for your interest!

Dear {lead_name},

Thank you for contacting us. We have received your inquiry and our team will get back to you soon.

Your Lead ID: {str(lead.id)[:8]}

Best regards,
Team"""
        
        auto_reply_html = f"""
        <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <p>Thank you for your interest!</p>
                <p>Dear {lead_name},</p>
                <p>Thank you for contacting us. We have received your inquiry and our team will get back to you soon.</p>
                <p><strong>Your Lead ID:</strong> {str(lead.id)[:8]}</p>
                <p>Best regards,<br>Team</p>
            </body>
        </html>
        """
        
        try:
            task = celery_app.send_task(
                "tasks.send_email",
                kwargs={
                    "to_email": lead.email,
                    "subject": "Thank you for contacting us!",
                    "body_text": auto_reply_message,
                    "body_html": auto_reply_html
                }
            )
            email_result["auto_reply"] = {"status": "queued", "task_id": task.id, "to": lead.email}
        except Exception as e:
            email_result["auto_reply"] = {"error": str(e)}
    
    # Process Google Sheets (if enabled) - via Celery
    sheets_result = None
    if integration and integration.google_sheets_enabled == "true":
        try:
            task = celery_app.send_task(
                "tasks.append_to_google_sheets",
                kwargs={
                    "client_id": request.client_id,
                    "sheet_id": integration.google_sheet_id,
                    "lead_data": lead_data_dict
                }
            )
            sheets_result = {"status": "queued", "task_id": task.id, "message": "Google Sheets append queued for background processing"}
        except Exception as e:
            sheets_result = {"error": str(e)}
    
    # Log final summary
    logger.info(f"Lead processing completed for lead_id: {request.lead_id}")
    logger.info(f"  WhatsApp: {whatsapp_result}")
    logger.info(f"  Emails: {email_result}")
    logger.info(f"  Google Sheets: {sheets_result}")
    
    return {
        "status": "accepted",
        "message": "Lead processing queued",
        "lead_id": request.lead_id,
        "client_id": request.client_id,
        "whatsapp": whatsapp_result,
        "emails": email_result,
        "google_sheets": sheets_result,
        "debug": {
            "client_data_retrieved": client_data is not None,
            "client_data_keys": list(client_data.keys()) if client_data else None,
            "integration_exists": integration is not None,
            "integration_whatsapp_enabled": integration.whatsapp_enabled if integration else None,
            "celery_redis_url": REDIS_URL
        }
    }


@app.post("/whatsapp/send", status_code=status.HTTP_200_OK)
async def send_whatsapp(
    request: WhatsAppMessageRequest,
    db: AsyncSession = Depends(get_db)
):
    """Send WhatsApp message directly via Twilio"""
    # Use message_body if provided, otherwise build from template params
    message_body = request.message_body
    
    if not message_body and request.template_name:
        # Build message body from template params if provided
        message_body = request.template_name
        
        if request.template_params:
            # Format message with template params
            params_str = "\n".join([f"{k}: {v}" for k, v in request.template_params.items()])
            message_body = f"{request.template_name}\n\n{params_str}"
        
        if request.lead_reference_id:
            message_body += f"\n\nLead Reference ID: {request.lead_reference_id}"
    
    if not message_body:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="message_body is required"
        )
    
    result = await send_whatsapp_message(
        phone_number=request.phone_number,
        message_body=message_body
    )
    
    return result


@app.get("/client-integrations/{client_id}", response_model=ClientIntegrationResponse)
async def get_client_integration(
    client_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Get client integration settings"""
    result = await db.execute(
        select(
            ClientIntegration.client_id,
            ClientIntegration.whatsapp_enabled,
            ClientIntegration.google_sheets_enabled,
            ClientIntegration.google_sheet_id,
            ClientIntegration.meta_page_id,
            ClientIntegration.meta_form_id,
            ClientIntegration.config,
            ClientIntegration.created_at,
            ClientIntegration.updated_at
        ).where(ClientIntegration.client_id == client_id)
    )
    integration_row = result.first()
    
    if not integration_row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Client integration not found for client_id: {client_id}"
        )
    
    return ClientIntegrationResponse(
        client_id=integration_row.client_id,
        whatsapp_enabled=integration_row.whatsapp_enabled,
        google_sheets_enabled=integration_row.google_sheets_enabled,
        google_sheet_id=integration_row.google_sheet_id,
        meta_page_id=integration_row.meta_page_id,
        meta_form_id=integration_row.meta_form_id,
        config=integration_row.config,
        created_at=integration_row.created_at,
        updated_at=integration_row.updated_at
    )


@app.put("/client-integrations/{client_id}", response_model=ClientIntegrationResponse)
async def update_client_integration(
    client_id: str,
    integration_data: ClientIntegrationUpdate,
    db: AsyncSession = Depends(get_db)
):
    """Update client integration settings"""
    result = await db.execute(
        select(ClientIntegration).where(ClientIntegration.client_id == client_id)
    )
    integration = result.scalar_one_or_none()
    
    if not integration:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Client integration not found for client_id: {client_id}"
        )
    
    # Update fields
    if integration_data.whatsapp_enabled is not None:
        integration.whatsapp_enabled = integration_data.whatsapp_enabled
    if integration_data.google_sheets_enabled is not None:
        integration.google_sheets_enabled = integration_data.google_sheets_enabled
    if integration_data.google_sheet_id is not None:
        integration.google_sheet_id = integration_data.google_sheet_id
    if integration_data.meta_page_id is not None:
        integration.meta_page_id = integration_data.meta_page_id
    if integration_data.meta_form_id is not None:
        integration.meta_form_id = integration_data.meta_form_id
    if integration_data.config is not None:
        integration.config = integration_data.config
    
    await db.commit()
    await db.refresh(integration)
    
    return ClientIntegrationResponse(
        client_id=integration.client_id,
        whatsapp_enabled=integration.whatsapp_enabled,
        google_sheets_enabled=integration.google_sheets_enabled,
        google_sheet_id=integration.google_sheet_id,
        meta_page_id=integration.meta_page_id,
        meta_form_id=integration.meta_form_id,
        config=integration.config,
        created_at=integration.created_at,
        updated_at=integration.updated_at
    )


@app.get("/health")
async def health():
    """Health check"""
    return {
        "status": "healthy",
        "service": "integration_service",
        "whatsapp_configured": bool(TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_WHATSAPP_FROM),
        "google_sheets_configured": bool(GOOGLE_SERVICE_ACCOUNT_FILE)
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8006)

