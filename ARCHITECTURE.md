# Lead Automation Platform - Architecture Documentation

## Overview

This is a production-ready, microservice-based Lead Automation Platform designed for internal enterprise use. The system supports multi-client operations, hierarchical RBAC, and automated lead processing from multiple sources.

## Core Principles

1. **True Microservices**: Each service is independently deployable with its own responsibility
2. **Client-Provided IDs**: `client_id` is provided by the frontend, not auto-generated
3. **Multi-Client Users**: Users can belong to multiple clients with different roles per client
4. **Hierarchical RBAC**: Dynamic, multi-level role-based access control
5. **Industry → Category → Product**: Mandatory hierarchy for product management
6. **Secure API Keys**: API key-based lead ingestion for website forms
7. **Event-Driven Processing**: Background processing for WhatsApp, Google Sheets, and Meta API

## Service Architecture

### 1. API Gateway (Port 8000)
- **Purpose**: Single entry point, routing, authentication, RBAC enforcement
- **Responsibilities**:
  - Route requests to appropriate microservices
  - Validate JWT tokens
  - Enforce permissions
  - Rate limiting
  - CORS handling

### 2. Auth Service (Port 8001)
- **Purpose**: Authentication and JWT token management
- **Endpoints**:
  - `POST /register` - User registration
  - `POST /login` - User login (returns access + refresh tokens)
  - `POST /refresh` - Refresh access token
  - `GET /me` - Get current user info

### 3. Client Service (Port 8002)
- **Purpose**: Client management with client-provided IDs
- **Key Features**:
  - `client_id` validation and uniqueness checking
  - Client CRUD operations
  - Client status management

### 4. User Service (Port 8003)
- **Purpose**: Multi-client user management
- **Key Features**:
  - User-Client junction table (`user_clients`)
  - Role assignment per client
  - Hierarchy management (reports_to)
  - User can belong to multiple clients

### 5. Permission Service (Port 8008)
- **Purpose**: Dynamic role and permission management
- **Key Features**:
  - Auto-registration of API endpoints as permissions
  - Role-Permission mapping
  - Dynamic permission assignment

### 6. Hierarchy Service (Port 8009)
- **Purpose**: Hierarchical RBAC enforcement
- **Key Features**:
  - Closure table for efficient hierarchy queries
  - Access control based on hierarchy
  - Manager-subordinate relationships

### 7. Product Service (Port 8005)
- **Purpose**: Industry → Category → Product hierarchy
- **Key Features**:
  - Global product catalog
  - Client-product attachment
  - Reusable products across clients

### 8. Lead Service (Port 8004)
- **Purpose**: Lead storage and API key-based ingestion
- **Key Features**:
  - Lead CRUD operations
  - API key generation and validation
  - Lead ingestion endpoint (`POST /leads/ingest`)
  - Normalization (known fields vs raw_payload)

### 9. Integration Service (Port 8006)
- **Purpose**: Third-party integrations
- **Integrations**:
  - WhatsApp Cloud API (template messages)
  - Google Sheets API (append leads)
  - Meta Graph API (lead fetching)

### 10. Webhook Service (Port 8007)
- **Purpose**: Facebook/Instagram webhook handling
- **Key Features**:
  - Webhook verification
  - Signature validation
  - Lead generation event processing
  - page_id/form_id → client_id mapping

### 11. Celery Worker
- **Purpose**: Background task processing
- **Tasks**:
  - WhatsApp message sending
  - Google Sheets appending
  - Meta lead fetching
  - Lead processing

## Database Schema

### Core Tables

1. **users** (Global)
   - `id` (UUID, PK)
   - `email` (unique)
   - `password_hash`
   - `is_admin` (boolean)
   - `status`

2. **clients**
   - `client_id` (String, PK) - Provided by frontend
   - `name`
   - `status`

3. **user_clients** (Junction)
   - `id` (UUID, PK)
   - `user_id` (FK → users.id)
   - `client_id` (FK → clients.client_id)
   - `role_id` (FK → roles.id)
   - `reports_to_user_client_id` (self FK, nullable)

4. **roles**
   - `id` (UUID, PK)
   - `name` (unique)
   - `level` (integer as string)
   - `description`

5. **permissions**
   - `id` (UUID, PK)
   - `method` (GET/POST/PUT/DELETE)
   - `path`
   - `description`

6. **role_permissions** (Junction)
   - `role_id` (FK → roles.id)
   - `permission_id` (FK → permissions.id)

7. **user_client_hierarchy** (Closure Table)
   - `ancestor_user_client_id` (FK → user_clients.id)
   - `descendant_user_client_id` (FK → user_clients.id)
   - `depth`

8. **industries**
   - `id` (UUID, PK)
   - `name` (unique)

9. **product_categories**
   - `id` (UUID, PK)
   - `industry_id` (FK → industries.id)
   - `name`

10. **products**
    - `id` (UUID, PK)
    - `category_id` (FK → product_categories.id)
    - `name`

11. **client_products** (Junction)
    - `client_id` (FK → clients.client_id)
    - `product_id` (FK → products.id)
    - `enabled`

12. **leads**
    - `id` (UUID, PK)
    - `client_id` (FK → clients.client_id)
    - `name`, `email`, `phone`
    - `source`
    - `lead_reference_id`
    - `raw_payload` (JSONB)

13. **client_api_keys**
    - `id` (UUID, PK)
    - `client_id` (FK → clients.client_id)
    - `key_hash` (unique)
    - `key_prefix`
    - `scopes` (JSONB)
    - `expires_at`
    - `last_used_at`

14. **client_integrations**
    - `client_id` (FK → clients.client_id, PK)
    - `whatsapp_enabled`
    - `google_sheets_enabled`
    - `google_sheet_id`
    - `meta_page_id`
    - `meta_form_id`
    - `config` (JSONB)

## Authentication & Authorization

### JWT Tokens
- **Access Token**: Short-lived (30 minutes default)
- **Refresh Token**: Long-lived (7 days default)
- **Token Payload**: `{user_id, email, is_admin, type}`

### API Keys
- Format: `{prefix}_live_{random}`
- Stored as SHA-256 hash
- Scoped permissions
- Expiration support

### RBAC Flow
1. User authenticates → receives JWT
2. Request includes JWT in Authorization header
3. API Gateway validates token
4. Permission service checks role permissions
5. Hierarchy service checks access scope
6. Request allowed/denied

## Lead Processing Flow

### Website Lead Ingestion
1. Website form submits to `/api/leads/ingest` with `X-API-Key` header
2. Lead Service validates API key
3. Lead stored in database
4. Integration Service triggered (async)
5. WhatsApp message sent (if enabled)
6. Google Sheets updated (if enabled)

### Facebook/Instagram Lead
1. Meta webhook received at `/webhook/meta`
2. Webhook Service validates signature
3. Lead ID extracted from webhook
4. Lead data fetched from Meta Graph API
5. Lead created in database
6. Background processing triggered

## Security Considerations

1. **Password Hashing**: bcrypt with configurable rounds
2. **JWT Security**: HS256 with secret key
3. **API Key Security**: SHA-256 hashing, shown only once
4. **Webhook Security**: HMAC signature verification
5. **Encryption**: Fernet for sensitive data
6. **Rate Limiting**: Gateway-level and API-key level
7. **Client Isolation**: Enforced at query level

## Deployment

### Docker Compose
- All services containerized
- Shared PostgreSQL database
- Shared Redis for Celery
- Independent scaling per service

### Environment Variables
- Database credentials
- JWT secrets
- Third-party API tokens
- Service URLs

### Migrations
- Alembic for database migrations
- Single migration file for initial schema
- Run migrations on startup or manually

## Scalability

- **Horizontal Scaling**: Each service can scale independently
- **Database**: Shared PostgreSQL (can be split per service in production)
- **Caching**: Redis for session/task queue
- **Load Balancing**: API Gateway can be load balanced
- **Background Processing**: Celery workers can scale horizontally

## Monitoring & Logging

- Structured JSON logs
- Service health endpoints (`/health`)
- Error tracking (integrate with Sentry, etc.)
- Performance monitoring (integrate with APM tools)

## Future Enhancements

1. Separate databases per microservice
2. Event bus (Kafka/RabbitMQ) for inter-service communication
3. GraphQL API layer
4. Real-time notifications (WebSockets)
5. Advanced analytics and reporting
6. Multi-region deployment
7. Service mesh (Istio/Linkerd)

