"""
Webhook Service - Facebook/Instagram webhook handling
"""
from fastapi import FastAPI, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime
import sys
import os
import hmac
import hashlib
import httpx

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from shared.database import get_db
from shared.models.base import BaseModel as BaseDBModel, BaseModelNoID
from shared.utils.http_client import ServiceClient
from sqlalchemy import Column, String, ForeignKey, JSON
from sqlalchemy.dialects.postgresql import UUID, JSONB
import uuid

app = FastAPI(title="Webhook Service", version="1.0.0")

# Configuration
META_APP_SECRET = os.getenv("META_APP_SECRET")
META_APP_ID = os.getenv("META_APP_ID")

# Service clients
LEAD_SERVICE_URL = os.getenv("LEAD_SERVICE_URL", "http://localhost:8004")
lead_client = ServiceClient(LEAD_SERVICE_URL)


# Database Models
class Client(BaseModelNoID):
    __tablename__ = "clients"
    
    client_id = Column(String, primary_key=True, unique=True, nullable=False, index=True)
    name = Column(String, nullable=False)
    status = Column(String, default="active", nullable=False)


class ClientIntegration(BaseDBModel):
    __tablename__ = "client_integrations"
    
    client_id = Column(String, ForeignKey("clients.client_id"), nullable=False, primary_key=True)
    whatsapp_enabled = Column(String, default="false", nullable=False)
    google_sheets_enabled = Column(String, default="false", nullable=False)
    google_sheet_id = Column(String, nullable=True)
    meta_page_id = Column(String, nullable=True)
    meta_form_id = Column(String, nullable=True)
    config = Column(JSONB, nullable=True)


# Helper Functions
def verify_meta_signature(payload: bytes, signature: str) -> bool:
    """Verify Meta webhook signature"""
    if not META_APP_SECRET:
        return False
    
    expected_signature = hmac.new(
        META_APP_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(f"sha256={expected_signature}", signature)


async def get_client_from_meta_ids(
    page_id: Optional[str],
    form_id: Optional[str],
    db: AsyncSession
) -> Optional[str]:
    """Get client_id from Meta page_id or form_id"""
    query = select(ClientIntegration).where(
        (ClientIntegration.meta_page_id == page_id) |
        (ClientIntegration.meta_form_id == form_id)
    )
    result = await db.execute(query)
    integration = result.scalar_one_or_none()
    
    return integration.client_id if integration else None


async def fetch_lead_from_meta(lead_id: str, access_token: str) -> Dict[str, Any]:
    """Fetch lead data from Meta Graph API"""
    url = f"https://graph.facebook.com/v18.0/{lead_id}"
    params = {
        "access_token": access_token,
        "fields": "id,created_time,field_data"
    }
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, params=params)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Meta API error: {str(e)}"
            )


# Routes
@app.get("/webhook/meta")
async def meta_webhook_verification(
    hub_mode: str,
    hub_verify_token: str,
    hub_challenge: str
):
    """Meta webhook verification (GET request)"""
    # Verify token (configure per client)
    verify_token = os.getenv("META_VERIFY_TOKEN", "your-verify-token")
    
    if hub_mode == "subscribe" and hub_verify_token == verify_token:
        return int(hub_challenge)
    else:
        raise HTTPException(status_code=403, detail="Verification failed")


@app.post("/webhook/meta")
async def meta_webhook_handler(
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """
    Meta webhook handler (POST request)
    Webhook responses must be < 5 seconds. Process lead creation asynchronously.
    """
    # Verify signature
    signature = request.headers.get("X-Hub-Signature-256", "")
    body = await request.body()
    
    if not verify_meta_signature(body, signature):
        raise HTTPException(status_code=403, detail="Invalid signature")
    
    # Parse webhook data
    data = await request.json()
    
    # Respond quickly (< 5 seconds) and process asynchronously
    import asyncio
    from celery import Celery
    
    # Get Celery app for async task processing
    celery_app = Celery(
        "lead_platform",
        broker=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
        backend=os.getenv("REDIS_URL", "redis://localhost:6379/0")
    )
    
    # Handle different webhook types
    if data.get("object") == "page":
        entries = data.get("entry", [])
        
        for entry in entries:
            changes = entry.get("changes", [])
            
            for change in changes:
                if change.get("field") == "leadgen":
                    # Lead generation event
                    leadgen_id = change.get("value", {}).get("leadgen_id")
                    page_id = change.get("value", {}).get("page_id")
                    form_id = change.get("value", {}).get("form_id")
                    
                    if leadgen_id:
                        # Get client_id from page_id/form_id mapping (quick DB lookup)
                        client_id = await get_client_from_meta_ids(page_id, form_id, db)
                        
                        if not client_id:
                            # Log unknown webhook
                            print(f"Unknown Meta webhook: page_id={page_id}, form_id={form_id}")
                            continue
                        
                        # Process lead creation asynchronously via Celery
                        # This ensures webhook responds quickly
                        try:
                            # Trigger async lead fetch and creation
                            celery_app.send_task(
                                "tasks.fetch_meta_lead",
                                args=[leadgen_id, os.getenv("META_ACCESS_TOKEN", "")],
                                kwargs={
                                    "client_id": client_id,
                                    "source": "facebook" if "facebook" in str(change) else "instagram",
                                    "raw_payload": change.get("value", {})
                                }
                            )
                        except Exception as e:
                            print(f"Failed to queue lead processing: {e}")
                            # Fallback: create lead directly (but this should be fast)
                            try:
                                await lead_client.post(
                                    "/leads",
                                    json={
                                        "client_id": client_id,
                                        "source": "facebook" if "facebook" in str(change) else "instagram",
                                        "lead_reference_id": leadgen_id,
                                        "raw_payload": change.get("value", {})
                                    }
                                )
                            except Exception as e2:
                                print(f"Failed to create lead: {e2}")
    
    # Return immediately (< 5 seconds requirement)
    return {"status": "ok", "message": "Webhook received, processing asynchronously"}


@app.get("/health")
async def health():
    """Health check"""
    return {
        "status": "healthy",
        "service": "webhook_service",
        "meta_configured": bool(META_APP_SECRET and META_APP_ID)
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8007)

