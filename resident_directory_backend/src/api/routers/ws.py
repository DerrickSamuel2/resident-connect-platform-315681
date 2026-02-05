from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import DefaultDict, Set

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect
from sqlalchemy import text
from sqlalchemy.orm import Session

from src.api.db import get_db
from src.api.security import decode_token

router = APIRouter(tags=["WebSocket"])

# conversation_id -> set of websockets
_connections: DefaultDict[str, Set[WebSocket]] = defaultdict(set)
_lock = asyncio.Lock()


async def _broadcast(conversation_id: str, payload: dict) -> None:
    async with _lock:
        sockets = list(_connections.get(conversation_id, set()))
    for ws in sockets:
        try:
            await ws.send_json(payload)
        except Exception:
            # ignore broken sockets; cleanup happens on disconnect
            pass


def _get_user_from_ws_token(token: str) -> tuple[str, str]:
    payload = decode_token(token)
    if payload.get("typ") != "access":
        raise ValueError("Not an access token")
    sub = payload.get("sub")
    role = payload.get("role")
    if not sub or not role:
        raise ValueError("Invalid token payload")
    return str(sub), str(role)


def _ensure_participant(db: Session, conversation_id: str, user_id: str) -> None:
    exists = db.execute(
        text(
            """
            SELECT 1
            FROM conversation_participants
            WHERE conversation_id=:cid AND user_id=:uid
            """
        ),
        {"cid": conversation_id, "uid": user_id},
    ).fetchone()
    if not exists:
        raise ValueError("User is not a participant in this conversation")


# PUBLIC_INTERFACE
@router.websocket(
    "/ws/messages",
)
async def ws_messages(
    websocket: WebSocket,
    token: str = Query(..., description="JWT access token (pass as query parameter)."),
    conversation_id: str = Query(..., description="Conversation UUID to join."),
    db: Session = Depends(get_db),
):
    """
    WebSocket messaging channel.

    Usage:
    - Connect: ws://<host>/ws/messages?token=<ACCESS_JWT>&conversation_id=<UUID>
    - Client sends JSON:
        { "type": "message", "body": "hello" }
      Server broadcasts:
        { "type": "message", "conversation_id": "...", "message": {...} }

    Notes:
    - Token is validated as an ACCESS token.
    - User must be a participant of the conversation.
    """
    await websocket.accept()
    try:
        user_id, _role = _get_user_from_ws_token(token)
        _ensure_participant(db, conversation_id, user_id)

        async with _lock:
            _connections[conversation_id].add(websocket)

        await websocket.send_json(
            {"type": "joined", "conversation_id": conversation_id, "user_id": user_id}
        )

        while True:
            data = await websocket.receive_json()
            if not isinstance(data, dict):
                continue
            msg_type = data.get("type")
            if msg_type == "ping":
                await websocket.send_json({"type": "pong"})
                continue
            if msg_type != "message":
                await websocket.send_json({"type": "error", "detail": "Unknown message type"})
                continue
            body = (data.get("body") or "").strip()
            if not body:
                await websocket.send_json({"type": "error", "detail": "Message body required"})
                continue

            row = db.execute(
                text(
                    """
                    INSERT INTO messages(conversation_id, sender_user_id, body, sent_at)
                    VALUES (:cid, :sid, :body, now())
                    RETURNING id, conversation_id, sender_user_id, body, sent_at
                    """
                ),
                {"cid": conversation_id, "sid": user_id, "body": body},
            ).fetchone()
            db.commit()

            await _broadcast(
                conversation_id,
                {
                    "type": "message",
                    "conversation_id": conversation_id,
                    "message": {
                        "id": str(row.id),
                        "sender_user_id": str(row.sender_user_id),
                        "body": row.body,
                        "sent_at": row.sent_at.isoformat(),
                    },
                },
            )

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"type": "error", "detail": str(e)})
        except Exception:
            pass
    finally:
        async with _lock:
            _connections[conversation_id].discard(websocket)
            if not _connections[conversation_id]:
                _connections.pop(conversation_id, None)
        try:
            await websocket.close()
        except Exception:
            pass
