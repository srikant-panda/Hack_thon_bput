"""CYBERGUARD API entrypoint.

Refactored with:
- Async SQLAlchemy database engine and session management.
- Multi-tenancy: Single-User personal workspaces & Organization-based RBAC.
- Unified error handlers for database and validation errors.
- Async endpoints across all modules.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import (
    routes_actions,
    routes_alerts,
    routes_analysis,
    routes_assistant,
    routes_audit,
    routes_auth,
    routes_dashboard,
    routes_db,
    routes_events,
    routes_health,
    routes_incidents,
    routes_integrations,
    routes_organizations,
    routes_policies,
    routes_response,
)
from app.ai.key_rotator import get_key_rotator
from app.core.config import get_settings
from app.core.errors import register_error_handlers
from app.db.session import init_db

logger = logging.getLogger("cyberguard")
logging.basicConfig(level=logging.INFO)

settings = get_settings()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Application lifespan: initialize database schema, seed data, and start background workers."""
    logger.info("Starting CYBERGUARD backend...")
    await init_db()
    rotator = get_key_rotator()
    rotator.log_startup_summary()
    rotator.start_background_task()
    yield
    logger.info("Shutting down CYBERGUARD backend...")
    rotator.stop_background_task()


app = FastAPI(
    title=settings.APP_TITLE,
    version=settings.APP_VERSION,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routers under /api/v1
app.include_router(routes_health.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_auth.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_organizations.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_db.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_events.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_analysis.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_alerts.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_actions.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_policies.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_incidents.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_integrations.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_response.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_dashboard.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_audit.router, prefix=settings.API_V1_PREFIX)
app.include_router(routes_assistant.router, prefix=settings.API_V1_PREFIX)

# Register unified exception handlers
register_error_handlers(app)
