from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
import os

from src.api.routers import admin, auth, content, gdpr, messaging, profiles, ws

openapi_tags = [
    {"name": "Auth", "description": "JWT authentication: register/login/refresh/me."},
    {"name": "Profiles", "description": "Resident profile CRUD and directory search (privacy-aware)."},
    {"name": "Content", "description": "Announcements and events."},
    {"name": "Messaging", "description": "Conversations and message history."},
    {"name": "WebSocket", "description": "Real-time messaging channel."},
    {"name": "Admin", "description": "Admin management and audit logs."},
    {"name": "GDPR", "description": "GDPR export/delete request handling."},
]

app = FastAPI(
    title="Resident Directory Backend API",
    description=(
        "Backend APIs for Resident Directory App: auth, profiles with privacy, "
        "directory search, announcements/events, messaging + WebSocket, admin, audit, GDPR."
    ),
    version="0.1.0",
    openapi_tags=openapi_tags,
)

cors_origins = os.getenv("CORS_ALLOW_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in cors_origins] if cors_origins else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", tags=["Auth"])
def health_check():
    """Health check endpoint."""
    return {"message": "Healthy"}


@app.get(
    "/docs/websocket",
    response_class=PlainTextResponse,
    tags=["WebSocket"],
)
def websocket_usage_help() -> str:
    """
    WebSocket usage help.

    Returns a plain text guide for connecting to the messaging WebSocket.
    """
    return (
        "WebSocket endpoint:\\n"
        "  /ws/messages?token=<ACCESS_JWT>&conversation_id=<UUID>\\n\\n"
        "Client -> server JSON:\\n"
        '  {\"type\":\"message\",\"body\":\"hello\"}\\n'
        '  {\"type\":\"ping\"}\\n\\n'
        "Server -> client JSON:\\n"
        '  {\"type\":\"joined\",...}\\n'
        '  {\"type\":\"message\",\"conversation_id\":\"...\",\"message\":{...}}\\n'
        '  {\"type\":\"error\",\"detail\":\"...\"}\\n'
    )


# Routers
app.include_router(auth.router)
app.include_router(profiles.router)
app.include_router(content.router)
app.include_router(messaging.router)
app.include_router(admin.router)
app.include_router(gdpr.router)

# WebSocket router must be included too (APIRouter supports websocket routes)
app.include_router(ws.router)
