from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from src.api.db import get_db
from src.api.routers.auth import get_current_user
from src.api.schemas import (
    DirectorySearchResponse,
    ProfileResponse,
    ProfileUpdateRequest,
    UserMe,
)

router = APIRouter(prefix="/profiles", tags=["Profiles"])


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


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _redact_profile(row, viewer: UserMe, *, is_self: bool) -> ProfileResponse:
    """Apply privacy rules to profile output for directory viewers."""
    # Self sees everything.
    if is_self or viewer.role == "admin":
        email = row.email
        phone = row.phone
        building_id = row.building_id
        unit_id = row.unit_id
    else:
        email = row.email if row.show_email else None
        phone = row.phone if row.show_phone else None
        building_id = row.building_id if row.show_unit else None
        unit_id = row.unit_id if row.show_unit else None

    return ProfileResponse(
        user_id=row.user_id,
        email=email,
        first_name=row.first_name,
        last_name=row.last_name,
        phone=phone,
        bio=row.bio,
        building_id=building_id,
        unit_id=unit_id,
        is_directory_visible=row.is_directory_visible,
        show_email=row.show_email,
        show_phone=row.show_phone,
        show_unit=row.show_unit,
        consent_directory=row.consent_directory,
        consent_messaging=row.consent_messaging,
        consent_marketing=row.consent_marketing,
        updated_at=row.updated_at,
    )


# PUBLIC_INTERFACE
@router.get(
    "/me",
    response_model=ProfileResponse,
    summary="Get my profile",
    description="Returns the authenticated user's own profile (not redacted). Creates a default profile row if missing.",
)
def get_my_profile(
    request: Request, user: UserMe = Depends(get_current_user), db: Session = Depends(get_db)
) -> ProfileResponse:
    """Fetch current user's resident profile."""
    row = db.execute(
        text(
            """
            SELECT rp.*, u.email
            FROM resident_profiles rp
            JOIN users u ON u.id = rp.user_id
            WHERE rp.user_id = :uid
            """
        ),
        {"uid": str(user.id)},
    ).fetchone()

    if not row:
        # Create a default profile for new users.
        db.execute(
            text(
                """
                INSERT INTO resident_profiles(
                    user_id, first_name, last_name, phone, bio,
                    building_id, unit_id,
                    is_directory_visible, show_email, show_phone, show_unit,
                    consent_directory, consent_messaging, consent_marketing,
                    consent_updated_at
                )
                VALUES (
                    :uid, NULL, NULL, NULL, NULL,
                    NULL, NULL,
                    true, false, false, false,
                    true, true, false,
                    now()
                )
                """
            ),
            {"uid": str(user.id)},
        )
        _audit(
            db,
            actor_user_id=user.id,
            action="profiles.auto_create",
            entity_type="resident_profiles",
            entity_id=user.id,
            ip=request.client.host if request.client else None,
            ua=request.headers.get("user-agent"),
        )
        db.commit()
        row = db.execute(
            text(
                """
                SELECT rp.*, u.email
                FROM resident_profiles rp
                JOIN users u ON u.id = rp.user_id
                WHERE rp.user_id = :uid
                """
            ),
            {"uid": str(user.id)},
        ).fetchone()
        assert row is not None

    return _redact_profile(row, user, is_self=True)


# PUBLIC_INTERFACE
@router.put(
    "/me",
    response_model=ProfileResponse,
    summary="Update my profile",
    description="Updates authenticated user's profile fields and privacy/consent controls.",
)
def update_my_profile(
    req: ProfileUpdateRequest,
    request: Request,
    user: UserMe = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ProfileResponse:
    """Update profile with privacy controls."""
    db.execute(
        text(
            """
            INSERT INTO resident_profiles(user_id)
            VALUES (:uid)
            ON CONFLICT (user_id) DO NOTHING
            """
        ),
        {"uid": str(user.id)},
    )

    db.execute(
        text(
            """
            UPDATE resident_profiles
            SET
              first_name=:first_name,
              last_name=:last_name,
              phone=:phone,
              bio=:bio,
              building_id=:building_id,
              unit_id=:unit_id,
              is_directory_visible=:is_directory_visible,
              show_email=:show_email,
              show_phone=:show_phone,
              show_unit=:show_unit,
              consent_directory=:consent_directory,
              consent_messaging=:consent_messaging,
              consent_marketing=:consent_marketing,
              consent_updated_at=now(),
              updated_at=now()
            WHERE user_id=:uid
            """
        ),
        {
            "uid": str(user.id),
            "first_name": req.first_name,
            "last_name": req.last_name,
            "phone": req.phone,
            "bio": req.bio,
            "building_id": str(req.building_id) if req.building_id else None,
            "unit_id": str(req.unit_id) if req.unit_id else None,
            "is_directory_visible": req.privacy.is_directory_visible,
            "show_email": req.privacy.show_email,
            "show_phone": req.privacy.show_phone,
            "show_unit": req.privacy.show_unit,
            "consent_directory": req.consent_directory,
            "consent_messaging": req.consent_messaging,
            "consent_marketing": req.consent_marketing,
        },
    )

    _audit(
        db,
        actor_user_id=user.id,
        action="profiles.update_me",
        entity_type="resident_profiles",
        entity_id=user.id,
        ip=request.client.host if request.client else None,
        ua=request.headers.get("user-agent"),
    )
    db.commit()

    row = db.execute(
        text(
            """
            SELECT rp.*, u.email
            FROM resident_profiles rp
            JOIN users u ON u.id = rp.user_id
            WHERE rp.user_id = :uid
            """
        ),
        {"uid": str(user.id)},
    ).fetchone()
    assert row is not None
    return _redact_profile(row, user, is_self=True)


# PUBLIC_INTERFACE
@router.get(
    "/directory/search",
    response_model=DirectorySearchResponse,
    summary="Search resident directory",
    description="Search by name/email/unit label. Results are redacted by each resident's privacy settings.",
)
def directory_search(
    q: str = Query(..., min_length=1, description="Search query (name/email/unit)."),
    building_id: Optional[UUID] = Query(None, description="Optional building filter."),
    limit: int = Query(20, ge=1, le=50, description="Max results."),
    user: UserMe = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DirectorySearchResponse:
    """Directory search (privacy-aware)."""
    # Only show profiles that are visible AND have consent_directory.
    params = {"q": q, "limit": limit}
    building_filter = ""
    if building_id:
        building_filter = "AND rp.building_id = :building_id"
        params["building_id"] = str(building_id)

    rows = db.execute(
        text(
            f"""
            SELECT
              rp.*,
              u.email,
              un.unit_label
            FROM resident_profiles rp
            JOIN users u ON u.id = rp.user_id
            LEFT JOIN units un ON un.id = rp.unit_id
            WHERE
              rp.is_directory_visible = true
              AND rp.consent_directory = true
              {building_filter}
              AND (
                (rp.first_name || ' ' || rp.last_name) ILIKE '%' || :q || '%'
                OR u.email::text ILIKE '%' || :q || '%'
                OR COALESCE(un.unit_label, '') ILIKE '%' || :q || '%'
              )
            ORDER BY rp.updated_at DESC NULLS LAST
            LIMIT :limit
            """
        ),
        params,
    ).fetchall()

    results = []
    for r in rows:
        is_self = str(r.user_id) == str(user.id)
        results.append(_redact_profile(r, user, is_self=is_self))

    return DirectorySearchResponse(results=results)
