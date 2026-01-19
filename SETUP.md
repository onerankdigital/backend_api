# Setup Guide

## Prerequisites

- Docker and Docker Compose installed
- Python 3.11+ (for local development)
- PostgreSQL 15+ (if running locally without Docker)

## Quick Start

1. **Clone and navigate to the project directory**

2. **Create environment file**
   ```bash
   cp env.example .env
   ```
   Edit `.env` and configure:
   - Database credentials
   - JWT secret keys
   - WhatsApp API credentials
   - Meta (Facebook/Instagram) credentials
   - Google Service Account file path (optional - see below)

3. **Start all services**
   ```bash
   docker-compose up -d
   ```

4. **Run database migrations**
   
   First, rebuild the api_gateway container to include Alembic:
   ```bash
   docker-compose build api_gateway
   docker-compose up -d api_gateway
   ```
   
   Wait a few seconds for the container to start, then run migrations:
   ```bash
   # Option 1: Run from api_gateway container (change to /app directory first)
   docker-compose exec api_gateway sh -c "cd /app && python -m alembic upgrade head"
   
   # Option 2: Run from host (if you have Python and dependencies installed)
   alembic upgrade head
   
   # Option 3: Use a temporary container (recommended)
   docker-compose run --rm api_gateway sh -c "cd /app && python -m alembic upgrade head"
   ```
   
   **Note**: The alembic.ini file should be in the project root, and the working directory should be set correctly.

5. **Access the API**
   - API Gateway: http://localhost:8000
   - API Documentation: http://localhost:8000/docs
   - Auth Service: http://localhost:8001/docs
   - Client Service: http://localhost:8002/docs
   - User Service: http://localhost:8003/docs
   - Lead Service: http://localhost:8004/docs
   - Product Service: http://localhost:8005/docs
   - Integration Service: http://localhost:8006/docs
   - Webhook Service: http://localhost:8007/docs

## Google Service Account Setup (Optional)

If you want to use Google Sheets integration, you need to create a Google Service Account:

1. **Go to Google Cloud Console**
   - Visit https://console.cloud.google.com/
   - Create a new project or select an existing one

2. **Enable Google Sheets API**
   - Navigate to "APIs & Services" > "Library"
   - Search for "Google Sheets API"
   - Click "Enable"

3. **Create Service Account**
   - Go to "APIs & Services" > "Credentials"
   - Click "Create Credentials" > "Service Account"
   - Enter a name (e.g., "lead-platform-service")
   - Click "Create and Continue"
   - Skip role assignment (or assign "Editor" if needed)
   - Click "Done"

4. **Create and Download Key**
   - Click on the created service account
   - Go to "Keys" tab
   - Click "Add Key" > "Create new key"
   - Select "JSON" format
   - Download the JSON file

5. **Place the JSON file**
   - Save the downloaded JSON file as `service_account.json`
   - Place it in the `services/integration_service/` directory
   - Or update `GOOGLE_SERVICE_ACCOUNT_FILE` in `.env` to point to the file location

6. **Share Google Sheet with Service Account**
   - Open your Google Sheet
   - Click "Share" button
   - Add the service account email (found in the JSON file as `client_email`)
   - Give it "Editor" permissions

**Note**: Google Sheets integration is optional. You can skip this step if you don't need Google Sheets functionality.

## Initial Setup

### 1. Create Admin User

```bash
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "password": "SecurePassword123!",
    "is_admin": true
  }'
```

### 2. Create Client

```bash
curl -X POST http://localhost:8000/api/clients \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -d '{
    "client_id": "CLIENT-ACME-001",
    "name": "Acme Corporation",
    "status": "active"
  }'
```

### 3. Create Roles

```bash
curl -X POST http://localhost:8005/roles \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Sales Director",
    "level": "100",
    "description": "Sales Director Role"
  }'
```

### 4. Generate API Key for Lead Ingestion

```bash
curl -X POST http://localhost:8004/api-keys/generate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -d '{
    "client_id": "CLIENT-ACME-001",
    "scopes": ["leads:create"]
  }'
```

**Save the `api_key` returned - it's shown only once!**

### 5. Create Industry → Category → Product

```bash
# Create Industry
curl -X POST http://localhost:8005/industries \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Technology",
    "description": "Technology Industry"
  }'

# Create Category
curl -X POST http://localhost:8005/product-categories \
  -H "Content-Type: application/json" \
  -d '{
    "industry_id": "INDUSTRY_UUID",
    "name": "Software",
    "description": "Software Products"
  }'

# Create Product
curl -X POST http://localhost:8005/products \
  -H "Content-Type: application/json" \
  -d '{
    "category_id": "CATEGORY_UUID",
    "name": "CRM Software",
    "description": "Customer Relationship Management"
  }'

# Attach Product to Client
curl -X POST http://localhost:8005/client-products \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "CLIENT-ACME-001",
    "product_id": "PRODUCT_UUID",
    "enabled": true
  }'
```

## Testing Lead Ingestion

### Via API Key (Website Form)

```bash
curl -X POST http://localhost:8000/api/leads/ingest \
  -H "Content-Type: application/json" \
  -H "X-API-Key: lead_live_YOUR_API_KEY" \
  -d '{
    "client_id": "CLIENT-ACME-001",
    "name": "John Doe",
    "email": "john@example.com",
    "phone": "+1234567890",
    "source": "website",
    "raw_payload": {
      "custom_field": "value"
    }
  }'
```

## Service Architecture

- **API Gateway (8000)**: Main entry point, routing, authentication
- **Auth Service (8001)**: JWT token management
- **Client Service (8002)**: Client management
- **User Service (8003)**: Multi-client user management
- **Lead Service (8004)**: Lead storage and API key ingestion
- **Product Service (8005)**: Industry → Category → Product hierarchy
- **Integration Service (8006)**: WhatsApp and Google Sheets
- **Webhook Service (8007)**: Facebook/Instagram webhooks
- **Celery Worker**: Background processing

## Database Migrations

Run migrations:
```bash
docker-compose exec api_gateway alembic upgrade head
```

Create new migration:
```bash
docker-compose exec api_gateway alembic revision --autogenerate -m "Description"
```

## Troubleshooting

1. **Services not starting**: Check logs with `docker-compose logs`
2. **Database connection errors**: Verify PostgreSQL is running and credentials are correct
3. **JWT errors**: Ensure JWT_SECRET_KEY is set in `.env`
4. **WhatsApp errors**: Verify WHATSAPP_API_TOKEN and WHATSAPP_PHONE_NUMBER_ID are set

## Production Deployment

1. Use environment-specific `.env` files
2. Configure proper CORS origins
3. Use secrets management (AWS Secrets Manager, HashiCorp Vault)
4. Set up proper logging and monitoring
5. Configure rate limiting
6. Use HTTPS/TLS
7. Set up database backups
8. Configure horizontal scaling per service

