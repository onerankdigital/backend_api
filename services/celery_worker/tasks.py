"""
Celery tasks for background processing
"""
from celery import Celery
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy import select
from typing import Dict, Any, Optional
import os
import httpx
import json
import asyncio
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from twilio.rest import Client as TwilioClient

# Celery configuration
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://leaduser:leadpass@localhost:5432/leadplatform")

celery_app = Celery(
    "lead_platform",
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

# Database setup
engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


# Twilio WhatsApp configuration
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_WHATSAPP_FROM = os.getenv("TWILIO_WHATSAPP_FROM")  # Format: whatsapp:+14155238886
GOOGLE_SERVICE_ACCOUNT_FILE = os.getenv("GOOGLE_SERVICE_ACCOUNT_FILE")

# Email SMTP configuration
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", SMTP_USER)


@celery_app.task(name="tasks.send_email")
def send_email(to_email: str, subject: str, body_text: str, body_html: Optional[str] = None):
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


@celery_app.task(name="tasks.send_whatsapp_message")
def send_whatsapp_message(phone_number: str, message_body: str):
    """Send WhatsApp message via Twilio"""
    if not TWILIO_ACCOUNT_SID or not TWILIO_AUTH_TOKEN or not TWILIO_WHATSAPP_FROM:
        return {"error": "Twilio WhatsApp not configured"}
    
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
        return {"error": str(e)}


@celery_app.task(name="tasks.append_to_google_sheets")
def append_to_google_sheets(client_id: str, sheet_id: str, lead_data: Dict[str, Any]):
    """Append lead to Google Sheets using Service Account"""
    if not GOOGLE_SERVICE_ACCOUNT_FILE:
        return {"error": "Google Sheets not configured"}
    
    try:
        from google.oauth2 import service_account
        from googleapiclient.discovery import build
        from googleapiclient.errors import HttpError
        
        # Load service account credentials
        if not os.path.exists(GOOGLE_SERVICE_ACCOUNT_FILE):
            return {"error": f"Service account file not found: {GOOGLE_SERVICE_ACCOUNT_FILE}"}
        
        credentials = service_account.Credentials.from_service_account_file(
            GOOGLE_SERVICE_ACCOUNT_FILE,
            scopes=['https://www.googleapis.com/auth/spreadsheets']
        )
        
        # Build Sheets API client
        service = build('sheets', 'v4', credentials=credentials)
        
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
        return {"error": f"Google Sheets API error: {str(e)}"}
    except Exception as e:
        return {"error": f"Google Sheets error: {str(e)}"}


@celery_app.task(name="tasks.fetch_meta_lead")
def fetch_meta_lead(lead_id: str, access_token: str):
    """Fetch lead data from Meta Graph API"""
    url = f"https://graph.facebook.com/v18.0/{lead_id}"
    params = {
        "access_token": access_token,
        "fields": "id,created_time,field_data"
    }
    
    try:
        response = httpx.get(url, params=params, timeout=30)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {"error": str(e)}


@celery_app.task(name="tasks.process_lead")
def process_lead(lead_id: str, client_id: str, lead_data: Dict[str, Any],
                 phone: Optional[str] = None, 
                 template_name: str = "lead_notification", 
                 sheet_id: Optional[str] = None,
                 whatsapp_enabled: bool = False,
                 sheets_enabled: bool = False):
    """Process a lead (send WhatsApp, append to Sheets)"""
    results = {
        "lead_id": lead_id,
        "client_id": client_id,
        "whatsapp": None,
        "google_sheets": None
    }
    
    # Send WhatsApp if enabled and phone available
    if whatsapp_enabled and phone:
        try:
            whatsapp_result = send_whatsapp_message.delay(
                phone_number=phone,
                template_name=template_name,
                template_params={"lead_id": lead_id},
                lead_reference_id=lead_data.get("lead_reference_id", lead_id)
            )
            results["whatsapp"] = {"task_id": whatsapp_result.id, "status": "queued"}
        except Exception as e:
            results["whatsapp"] = {"error": str(e)}
    
    # Append to Google Sheets if enabled
    if sheets_enabled and sheet_id and lead_data:
        try:
            sheets_result = append_to_google_sheets.delay(
                client_id=client_id,
                sheet_id=sheet_id,
                lead_data=lead_data
            )
            results["google_sheets"] = {"task_id": sheets_result.id, "status": "queued"}
        except Exception as e:
            results["google_sheets"] = {"error": str(e)}
    
    return results

