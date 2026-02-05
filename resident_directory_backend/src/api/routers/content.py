from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

from src.api.db import get_db
from src.api.routers.auth import get_current_user, require_admin
from src.api.schemas import (
    AnnouncementCreateRequest,
    AnnouncementResponse,
    EventCreateRequest,
    EventResponse,
    UserMe,
)

router = APIRouter(prefix="/content", tags=["Content"])


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
    "/announcements",
    response_model=list[AnnouncementResponse],
    summary="List announcements",
    description="Returns latest announcements; optionally filter by building_id.",
)
def list_announcements(
    building_id: UUID | None = Query(None, description="Optional building filter."),
    limit: int = Query(20, ge=1, le=100),
    user: UserMe = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[AnnouncementResponse]:
    """List announcements."""
    where = ""
    params = {"limit": limit}
    if building_id:
        where = "WHERE building_id = :bid OR building_id IS NULL"
        params["bid"] = str(building_id)

    rows = db.execute(
        text(
            f"""
            SELECT id, title, body, author_id, building_id, is_pinned, published_at
            FROM announcements
            {where}
            ORDER BY is_pinned DESC, published_at DESC
            LIMIT :limit
            """
        ),
        params,
    ).fetchall()

    return [
        AnnouncementResponse(
            id=r.id,
            title=r.title,
            body=r.body,
            author_id=r.author_id,
            building_id=r.building_id,
            is_pinned=r.is_pinned,
            published_at=r.published_at,
        )
        for r in rows
    ]


# PUBLIC_INTERFACE
@router.post(
    "/announcements",
    response_model=AnnouncementResponse,
    summary="Create announcement (admin)",
    description="Admin-only: creates an announcement; can be global (no building) or building-specific.",
)
def create_announcement(
    req: AnnouncementCreateRequest,
    request: Request,
    admin: UserMe = Depends(require_admin),
    db: Session = Depends(get_db),
) -> AnnouncementResponse:
    """Create announcement (admin)."""
    row = db.execute(
        text(
            """
            INSERT INTO announcements(title, body, author_id, building_id, is_pinned, published_at)
            VALUES (:title, :body, :author_id, :building_id, :is_pinned, now())
            RETURNING id, title, body, author_id, building_id, is_pinned, published_at
            """
        ),
        {
            "title": req.title,
            "body": req.body,
            "author_id": str(admin.id),
            "building_id": str(req.building_id) if req.building_id else None,
            "is_pinned": req.is_pinned,
        },
    ).fetchone()
    assert row is not None
    _audit(
        db,
        actor_user_id=admin.id,
        action="announcements.create",
        entity_type="announcements",
        entity_id=row.id,
        ip=request.client.host if request.client else None,
        ua=request.headers.get("user-agent"),
    )
    db.commit()
    return AnnouncementResponse(
        id=row.id,
        title=row.title,
        body=row.body,
        author_id=row.author_id,
        building_id=row.building_id,
        is_pinned=row.is_pinned,
        published_at=row.published_at,
    )


# PUBLIC_INTERFACE
@router.get(
    "/events",
    response_model=list[EventResponse],
    summary="List events",
    description="Returns upcoming events; optionally filter by building_id.",
)
def list_events(
    building_id: UUID | None = Query(None, description="Optional building filter."),
    limit: int = Query(50, ge=1, le=200),
    user: UserMe = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[EventResponse]:
    """List events."""
    where = ""
    params = {"limit": limit}
    if building_id:
        where = "WHERE building_id = :bid OR building_id IS NULL"
        params["bid"] = str(building_id)

    rows = db.execute(
        text(
            f"""
            SELECT id, title, description, building_id, starts_at, ends_at, location, created_by
            FROM events
            {where}
            ORDER BY starts_at ASC
            LIMIT :limit
            """
        ),
        params,
    ).fetchall()

    return [
        EventResponse(
            id=r.id,
            title=r.title,
            description=r.description,
            building_id=r.building_id,
            starts_at=r.starts_at,
            ends_at=r.ends_at,
            location=r.location,
            created_by=r.created_by,
        )
        for r in rows
    ]


# PUBLIC_INTERFACE
@router.post(
    "/events",
    response_model=EventResponse,
    summary="Create event (admin)",
    description="Admin-only: creates an event.",
)
def create_event(
    req: EventCreateRequest,
    request: Request,
    admin: UserMe = Depends(require_admin),
    db: Session = Depends(get_db),
) -> EventResponse:
    """Create event (admin)."""
    if req.ends_at and req.ends_at < req.starts_at:
        raise HTTPException(status_code=400, detail="ends_at must be >= starts_at")

    row = db.execute(
        text(
            """
            INSERT INTO events(title, description, building_id, starts_at, ends_at, location, created_by)
            VALUES (:title, :description, :building_id, :starts_at, :ends_at, :location, :created_by)
            RETURNING id, title, description, building_id, starts_at, ends_at, location, created_by
            """
        ),
        {
            "title": req.title,
            "description": req.description,
            "building_id": str(req.building_id) if req.building_id else None,
            "starts_at": req.starts_at,
            "ends_at": req.ends_at,
            "location": req.location,
            "created_by": str(admin.id),
        },
    ).fetchone()
    assert row is not None
    _audit(
        db,
        actor_user_id=admin.id,
        action="events.create",
        entity_type="events",
        entity_id=row.id,
        ip=request.client.host if request.client else None,
        ua=request.headers.get("user-agent"),
    )
    db.commit()
    return EventResponse(
        id=row.id,
        title=row.title,
        description=row.description,
        building_id=row.building_id,
        starts_at=row.starts_at,
        ends_at=row.ends_at,
        location=row.location,
        created_by=row.created_by,
    )
