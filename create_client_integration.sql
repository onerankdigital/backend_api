-- Create ClientIntegration record for ORD-20260116-001
-- This enables WhatsApp and email notifications

INSERT INTO client_integrations (
    client_id,
    whatsapp_enabled,
    google_sheets_enabled,
    google_sheet_id,
    meta_page_id,
    meta_form_id,
    config,
    created_at,
    updated_at
) VALUES (
    'ORD-20260116-001',
    'true',  -- Enable WhatsApp
    'false', -- Disable Google Sheets (or set to 'true' if you want it)
    NULL,
    NULL,
    NULL,
    NULL,
    NOW(),
    NOW()
)
ON CONFLICT (client_id) 
DO UPDATE SET
    whatsapp_enabled = 'true',
    updated_at = NOW();

-- Also make sure the client has email and phone
-- Check if client exists and update if needed
UPDATE clients 
SET 
    email = COALESCE(email, 'dhananjayphirke@gmail.com'),  -- Replace with your client email
    phone = COALESCE(phone, '+919119510726'),  -- Replace with your client phone
    updated_at = NOW()
WHERE client_id = 'ORD-20260116-001';

