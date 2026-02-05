from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from src.api.db import get_db
from src.api.routers.auth import get_current_user, require_admin
from src.api.schemas import GDPRRequestCreate, GDPRRequestResponse, UserMe

router = APIRouter(prefix="/gdpr", tags=["GDPR"])


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


def _export_user_data(db: Session, user_id: UUID) -> dict:
    """Best-effort export of user-related tables; adjust as schema evolves."""
    user = db.execute(
        text("SELECT id, email, role, is_active, is_email_verified, created_at FROM users WHERE id=:id"),
        {"id": str(user_id)},
    ).fetchone()
    profile = db.execute(
        text("SELECT * FROM resident_profiles WHERE user_id=:id"),
        {"id": str(user_id)},
    ).fetchone()
    sessions = db.execute(
        text("SELECT id, created_at, expires_at, revoked_at, ip_address, user_agent FROM user_sessions WHERE user_id=:id"),
        {"id": str(user_id)},
    ).fetchall()
    consent_events = db.execute(
        text("SELECT id, consent_type, old_value, new_value, created_at FROM consent_events WHERE user_id=:id ORDER BY created_at DESC"),
        {"id": str(user_id)},
    ).fetchall()
    gdpr_requests = db.execute(
        text("SELECT id, request_type, status, requested_at, completed_at FROM gdpr_requests WHERE user_id=:id ORDER BY requested_at DESC"),
        {"id": str(user_id)},
    ).fetchall()
    return {
        "user": dict(user._mapping) if user else None,
        "resident_profile": dict(profile._mapping) if profile else None,
        "user_sessions": [dict(r._mapping) for r in sessions],
        "consent_events": [dict(r._mapping) for r in consent_events],
        "gdpr_requests": [dict(r._mapping) for r in gdpr_requests],
    }


# PUBLIC_INTERFACE
@router.post(
    "/requests",
    response_model=GDPRRequestResponse,
    status_code=201,
    summary="Create GDPR request (export/delete)",
    description="Creates a GDPR request for the authenticated user. For export, the payload is generated immediately.",
)
def create_gdpr_request(
    req: GDPRRequestCreate,
    request: Request,
    user: UserMe = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> GDPRRequestResponse:
    """Create GDPR request."""
    if req.request_type not in ("export", "delete"):
        raise HTTPException(status_code=400, detail="request_type must be export or delete")

    export_data = None
    status_val = "pending"
    completed_at = None

    if req.request_type == "export":
        status_val = "completed"
        export_data = _export_user_data(db, user.id)
        completed_at = "now()"

    row = db.execute(
        text(
            f"""
            INSERT INTO gdpr_requests(user_id, request_type, status, export_data, processed_by, completed_at)
            VALUES (:uid, :rt, :st, :export_data, NULL, {completed_at if completed_at else 'NULL'})
            RETURNING id, user_id, request_type, status, requested_at, completed_at, export_data
            """
        ),
        {
            "uid": str(user.id),
            "rt": req.request_type,
            "st": status_val,
            "export_data": export_data,
        },
    ).fetchone()
    assert row is not None

    _audit(
        db,
        actor_user_id=user.id,
        action="gdpr.request.create",
        entity_type="gdpr_requests",
        entity_id=row.id,
        ip=request.client.host if request.client else None,
        ua=request.headers.get("user-agent"),
        metadata={"request_type": req.request_type},
    )
    db.commit()

    return GDPRRequestResponse(
        id=row.id,
        user_id=row.user_id,
        request_type=row.request_type,
        status=row.status,
        requested_at=row.requested_at,
        completed_at=row.completed_at,
        export_data=row.export_data,
    )


# PUBLIC_INTERFACE
@router.post(
    "/requests/{request_id}/process-delete",
    response_model=GDPRRequestResponse,
    summary="Process a GDPR delete request (admin)",
    description="Admin-only: processes a delete request by deleting the user (cascade). Marks request completed.",
)
def process_delete_request(
    request_id: UUID,
    request: Request,
    admin: UserMe = Depends(require_admin),
    db: Session = Depends(get_db),
) -> GDPRRequestResponse:
    """Process delete request by deleting user."""
    row = db.execute(
        text(
            """
            SELECT id, user_id, request_type, status, requested_at, completed_at, export_data
            FROM gdpr_requests
            WHERE id=:id
            """
        ),
        {"id": str(request_id)},
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="GDPR request not found")
    if row.request_type != "delete":
        raise HTTPException(status_code=400, detail="Not a delete request")
    if row.status == "completed":
        raise HTTPException(status_code=409, detail="Already completed")

    # Delete user (CASCADE removes resident_profile, sessions, etc.)
    db.execute(text("DELETE FROM users WHERE id=:uid"), {"uid": str(row.user_id)})

    updated = db.execute(
        text(
            """
            UPDATE gdpr_requests
            SET status='completed', processed_by=:admin_id, completed_at=now()
            WHERE id=:id
            RETURNING id, user_id, request_type, status, requested_at, completed_at, export_data
            """
        ),
        {"id": str(request_id), "admin_id": str(admin.id)},
    ).fetchone()
    assert updated is not None

    _audit(
        db,
        actor_user_id=admin.id,
        action="gdpr.request.process_delete",
        entity_type="gdpr_requests",
        entity_id=request_id,
        ip=request.client.host if request.client else None,
        ua=request.headers.get("user-agent"),
        metadata={"deleted_user_id": str(row.user_id)},
    )
    db.commit()

    return GDPRRequestResponse(
        id=updated.id,
        user_id=updated.user_id,
        request_type=updated.request_type,
        status=updated.status,
        requested_at=updated.requested_at,
        completed_at=updated.completed_at,
        export_data=updated.export_data,
    )
