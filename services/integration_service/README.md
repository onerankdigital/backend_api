# Integration Service - Google Sheets Setup

## Google Service Account Configuration

To enable Google Sheets integration, you need to set up a Google Service Account.

### Step-by-Step Guide

1. **Create Google Cloud Project**
   - Go to https://console.cloud.google.com/
   - Create a new project (or use existing)

2. **Enable Google Sheets API**
   - Navigate to: APIs & Services > Library
   - Search for "Google Sheets API"
   - Click "Enable"

3. **Create Service Account**
   - Go to: APIs & Services > Credentials
   - Click "Create Credentials" > "Service Account"
   - Name: `lead-platform-service` (or any name)
   - Click "Create and Continue"
   - Skip role assignment (optional)
   - Click "Done"

4. **Generate JSON Key**
   - Click on the service account you just created
   - Go to "Keys" tab
   - Click "Add Key" > "Create new key"
   - Select "JSON" format
   - Click "Create"
   - JSON file will be downloaded automatically

5. **Configure the Service**
   - Save the downloaded JSON file as `service_account.json`
   - Place it in this directory (`services/integration_service/`)
   - Or update `GOOGLE_SERVICE_ACCOUNT_FILE` in `.env` to point to the file

6. **Share Google Sheet**
   - Open your Google Sheet
   - Click "Share" button
   - Add the service account email (from JSON file: `client_email` field)
   - Give it "Editor" permissions
   - Save the Sheet ID (from the URL: `https://docs.google.com/spreadsheets/d/{SHEET_ID}/edit`)

### Environment Variables

```env
GOOGLE_SERVICE_ACCOUNT_FILE=/app/service_account.json
```

### Example JSON Structure

The service account JSON file looks like this:
```json
{
  "type": "service_account",
  "project_id": "your-project-id",
  "private_key_id": "...",
  "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
  "client_email": "lead-platform-service@your-project.iam.gserviceaccount.com",
  "client_id": "...",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "..."
}
```

### Testing

Once configured, the service will automatically append leads to Google Sheets when:
- A lead is created via API key ingestion
- A lead is created via webhook
- Background processing is triggered

### Troubleshooting

- **Permission denied**: Make sure you shared the Google Sheet with the service account email
- **File not found**: Check the `GOOGLE_SERVICE_ACCOUNT_FILE` path in `.env`
- **API not enabled**: Ensure Google Sheets API is enabled in Google Cloud Console

