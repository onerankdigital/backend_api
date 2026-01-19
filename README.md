# Lead Automation Platform - Microservices Architecture

A production-ready, internal, microservice-based Lead Automation Platform supporting multi-client operations, hierarchical RBAC, and automated lead processing.

## Architecture

```
┌──────────────┐
│ API Gateway  │
│ Auth + RBAC  │
└──────┬───────┘
       │
┌──────┼─────────────────────────┐
│      │                         │
▼      ▼                         ▼
Auth   Client           Lead
Service Service         Service
│      │                 │
▼      ▼                 ▼
User   Product    Integration
Service Service   Service
│                 │
▼                 ▼
Permission  Webhook
Service     Service
│                 │
▼                 ▼
Hierarchy   Notification
Service     Service
```

## Services

1. **API Gateway** - Routing, authentication, rate limiting
2. **Auth Service** - JWT token management, authentication
3. **Client Service** - Client management, client_id validation
4. **User Service** - Multi-client user management
5. **Permission Service** - Dynamic role & permission management
6. **Hierarchy Service** - Hierarchical RBAC enforcement
7. **Product Service** - Industry → Category → Product hierarchy
8. **Lead Service** - Lead storage and management
9. **Integration Service** - WhatsApp, Google Sheets, Meta API
10. **Webhook Service** - Facebook/Instagram webhook handling
11. **Notification Service** - Background notification processing

## Tech Stack

- **Language**: Python 3.11+
- **Framework**: FastAPI
- **Database**: PostgreSQL (with JSONB)
- **ORM**: SQLAlchemy (Async)
- **Migrations**: Alembic
- **Task Queue**: Celery
- **Message Broker**: Redis
- **Containerization**: Docker & Docker Compose

## Getting Started

1. Copy `env.example` to `.env` and configure
2. Run `docker-compose up -d` to start all services
3. Access API Gateway at `http://localhost:8000`
4. API docs available at `http://localhost:8000/docs`

## Key Features

- ✅ Client-provided IDs (not auto-generated)
- ✅ Multi-client users (many-to-many)
- ✅ Hierarchical RBAC (dynamic, multi-level)
- ✅ Industry → Category → Product hierarchy
- ✅ Secure API key-based lead ingestion
- ✅ WhatsApp Cloud API integration
- ✅ Google Sheets integration
- ✅ Facebook/Instagram webhooks
- ✅ Event-driven background processing

