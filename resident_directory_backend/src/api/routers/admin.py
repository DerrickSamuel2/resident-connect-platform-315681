from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from src.api.db import get_db
from src.api.routers.auth import require_admin
from src.api.schemas import AuditLogResponse, UserMe

router = APIRouter(prefix="/admin", tags=["Admin"])


def _audit(
    db: Session,
    *,
    actor_user_id: UUID | None,
    action: str,
    entity_type: str | None = None,
    entity_id: UUID | None = None,
    ip: str | None = None,
    ua: str | None = None,
    metadata: dict | None = None,
) -> None:
    db.execute(
        text(
            """
            INSERT INTO audit_logs(actor_user_id, action, entity_type, entity_id, ip_address, user_agent, metadata)
            VALUES (:actor_user_id, :action, :entity_type, :entity_id, :ip, :ua, COALESCE(:metadata, '{}'::jsonb))
            """
        ),
        {
            "actor_user_id": actor_user_id,
            "action": action,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "ip": ip,
            "ua": ua,
            "metadata": metadata,
        },
    )


# PUBLIC_INTERFACE
@router.get(
    "/users",
    summary="List users (admin)",
    description="Admin-only: list users (basic fields).",
)
def list_users(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    admin: UserMe = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """List users."""
    rows = db.execute(
        text(
            """
            SELECT id, email, role, is_active, is_email_verified, created_at
            FROM users
            ORDER BY created_at DESC
            LIMIT :limit OFFSET :offset
            """
        ),
        {"limit": limit, "offset": offset},
    ).fetchall()
    return {"results": [dict(r._mapping) for r in rows]}


# PUBLIC_INTERFACE
@router.patch(
    "/users/{user_id}",
    summary="Update user (admin)",
    description="Admin-only: update role and/or is_active.",
)
def update_user(
    user_id: UUID,
    request: Request,
    role: str | None = Query(None, description="New role: resident|admin"),
    is_active: bool | None = Query(None, description="Set active flag"),
    admin: UserMe = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Update user role/active."""
    if role is not None:
        db.execute(text("UPDATE users SET role=:role WHERE id=:id"), {"role": role, "id": str(user_id)})
    if is_active is not None:
        db.execute(text("UPDATE users SET is_active=:a WHERE id=:id"), {"a": is_active, "id": str(user_id)})

    _audit(
        db,
        actor_user_id=admin.id,
        action="admin.users.update",
        entity_type="users",
        entity_id=user_id,
        ip=request.client.host if request.client else None,
        ua=request.headers.get("user-agent"),
        metadata={"role": role, "is_active": is_active},
    )
    db.commit()
    row = db.execute(
        text("SELECT id, email, role, is_active, is_email_verified, created_at FROM users WHERE id=:id"),
        {"id": str(user_id)},
    ).fetchone()
    return {"user": dict(row._mapping) if row else None}


# PUBLIC_INTERFACE
@router.get(
    "/audit-logs",
    response_model=list[AuditLogResponse],
    summary="List audit logs (admin)",
    description="Admin-only: list audit logs (latest first).",
)
def list_audit_logs(
    limit: int = Query(100, ge=1, le=500),
    admin: UserMe = Depends(require_admin),
    db: Session = Depends(get_db),
) -> list[AuditLogResponse]:
    """List audit logs."""
    rows = db.execute(
        text(
            """
            SELECT id, actor_user_id, action, entity_type, entity_id, ip_address, user_agent, metadata, created_at
            FROM audit_logs
            ORDER BY created_at DESC
            LIMIT :limit
            """
        ),
        {"limit": limit},
    ).fetchall()

    return [
        AuditLogResponse(
            id=r.id,
            actor_user_id=r.actor_user_id,
            action=r.action,
            entity_type=r.entity_type,
            entity_id=r.entity_id,
            ip_address=r.ip_address,
            user_agent=r.user_agent,
            metadata=r.metadata or {},
            created_at=r.created_at,
        )
        for r in rows
    ]
