from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from src.api.db import get_db
from src.api.routers.auth import get_current_user
from src.api.schemas import UserMe

router = APIRouter(prefix="/messaging", tags=["Messaging"])


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
@router.post(
    "/conversations",
    summary="Create conversation",
    description="Create a 1:1 conversation between current user and another user (participant).",
)
def create_conversation(
    request: Request,
    participant_user_id: UUID = Query(..., description="Other participant user UUID."),
    user: UserMe = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create a conversation and participant rows."""
    # Check messaging consent of other user (best-effort)
    other_profile = db.execute(
        text("SELECT consent_messaging FROM resident_profiles WHERE user_id=:uid"),
        {"uid": str(participant_user_id)},
    ).fetchone()
    if other_profile and not other_profile.consent_messaging:
        raise HTTPException(status_code=403, detail="User does not consent to messaging")

    conv = db.execute(
        text("INSERT INTO conversations(created_at) VALUES (now()) RETURNING id, created_at")
    ).fetchone()
    assert conv is not None
    cid = str(conv.id)

    db.execute(
        text(
            """
            INSERT INTO conversation_participants(conversation_id, user_id, joined_at)
            VALUES (:cid, :uid, now())
            """
        ),
        {"cid": cid, "uid": str(user.id)},
    )
    db.execute(
        text(
            """
            INSERT INTO conversation_participants(conversation_id, user_id, joined_at)
            VALUES (:cid, :uid, now())
            """
        ),
        {"cid": cid, "uid": str(participant_user_id)},
    )

    _audit(
        db,
        actor_user_id=user.id,
        action="messaging.conversation.create",
        entity_type="conversations",
        entity_id=UUID(cid),
        ip=request.client.host if request.client else None,
        ua=request.headers.get("user-agent"),
        metadata={"participant_user_id": str(participant_user_id)},
    )
    db.commit()
    return {"conversation": {"id": cid, "created_at": conv.created_at.isoformat()}}


# PUBLIC_INTERFACE
@router.get(
    "/conversations",
    summary="List my conversations",
    description="List conversations for current user.",
)
def list_conversations(
    user: UserMe = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List conversations for current user."""
    rows = db.execute(
        text(
            """
            SELECT c.id, c.created_at
            FROM conversations c
            JOIN conversation_participants cp ON cp.conversation_id = c.id
            WHERE cp.user_id = :uid
            ORDER BY c.created_at DESC
            """
        ),
        {"uid": str(user.id)},
    ).fetchall()
    return {"results": [dict(r._mapping) for r in rows]}


# PUBLIC_INTERFACE
@router.get(
    "/conversations/{conversation_id}/messages",
    summary="List messages in a conversation",
    description="User must be a participant. Returns latest messages first.",
)
def list_messages(
    conversation_id: UUID,
    limit: int = Query(50, ge=1, le=200),
    user: UserMe = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List messages for a conversation."""
    is_participant = db.execute(
        text(
            "SELECT 1 FROM conversation_participants WHERE conversation_id=:cid AND user_id=:uid"
        ),
        {"cid": str(conversation_id), "uid": str(user.id)},
    ).fetchone()
    if not is_participant:
        raise HTTPException(status_code=403, detail="Not a participant")

    rows = db.execute(
        text(
            """
            SELECT id, conversation_id, sender_user_id, body, sent_at
            FROM messages
            WHERE conversation_id=:cid
            ORDER BY sent_at DESC
            LIMIT :limit
            """
        ),
        {"cid": str(conversation_id), "limit": limit},
    ).fetchall()
    return {"results": [dict(r._mapping) for r in rows]}
