from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import text
from sqlalchemy.orm import Session

from src.api.db import get_db
from src.api.schemas import LoginRequest, RefreshRequest, RegisterRequest, TokenPair, UserMe
from src.api.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["Auth"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


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
    "/register",
    response_model=TokenPair,
    status_code=201,
    summary="Register a new resident account",
    description="Creates a new user with role=resident (self-registration cannot create admin) and returns access+refresh tokens.",
)
def register(req: RegisterRequest, request: Request, db: Session = Depends(get_db)) -> TokenPair:
    """Register a new user and issue tokens."""
    if req.role != "resident":
        raise HTTPException(status_code=400, detail="Self-registration only supports role=resident")

    existing = db.execute(text("SELECT id FROM users WHERE email = :email"), {"email": str(req.email)}).fetchone()
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    user_row = db.execute(
        text(
            """
            INSERT INTO users(email, password_hash, role, is_active, is_email_verified)
            VALUES (:email, :password_hash, 'resident', true, false)
            RETURNING id, email, role
            """
        ),
        {"email": str(req.email), "password_hash": hash_password(req.password)},
    ).fetchone()
    assert user_row is not None
    user_id = user_row.id

    # Create refresh session
    session_row = db.execute(
        text(
            """
            INSERT INTO user_sessions(user_id, refresh_token_hash, user_agent, ip_address, expires_at)
            VALUES (:user_id, :refresh_token_hash, :ua, :ip, (now() + interval '30 days'))
            RETURNING id
            """
        ),
        {
            "user_id": user_id,
            # store a hash-like value to avoid raw token storage; reuse password hashing context
            "refresh_token_hash": hash_password("placeholder"),
            "ua": request.headers.get("user-agent"),
            "ip": request.client.host if request.client else None,
        },
    ).fetchone()
    assert session_row is not None
    session_id = str(session_row.id)

    access = create_access_token(sub=str(user_id), role="resident")
    refresh = create_refresh_token(sub=str(user_id), session_id=session_id)

    # update refresh_token_hash to actual token hash
    db.execute(
        text("UPDATE user_sessions SET refresh_token_hash=:h WHERE id=:sid"),
        {"h": hash_password(refresh), "sid": session_id},
    )
    _audit(
        db,
        actor_user_id=user_id,
        action="auth.register",
        entity_type="users",
        entity_id=user_id,
        ip=request.client.host if request.client else None,
        ua=request.headers.get("user-agent"),
        metadata={"email": str(req.email)},
    )
    db.commit()
    return TokenPair(access_token=access, refresh_token=refresh)


# PUBLIC_INTERFACE
@router.post(
    "/login",
    response_model=TokenPair,
    summary="Login and obtain tokens",
    description="Verifies credentials and returns access+refresh tokens. Creates a server-side refresh session.",
)
def login(req: LoginRequest, request: Request, db: Session = Depends(get_db)) -> TokenPair:
    """Authenticate a user by email/password and issue JWT tokens."""
    row = db.execute(
        text(
            """
            SELECT id, email, password_hash, role, is_active
            FROM users
            WHERE email = :email
            """
        ),
        {"email": str(req.email)},
    ).fetchone()
    if not row or not row.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not verify_password(req.password, row.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    session_row = db.execute(
        text(
            """
            INSERT INTO user_sessions(user_id, refresh_token_hash, user_agent, ip_address, expires_at)
            VALUES (:user_id, :refresh_token_hash, :ua, :ip, (now() + interval '30 days'))
            RETURNING id
            """
        ),
        {
            "user_id": row.id,
            "refresh_token_hash": hash_password("placeholder"),
            "ua": request.headers.get("user-agent"),
            "ip": request.client.host if request.client else None,
        },
    ).fetchone()
    assert session_row is not None
    session_id = str(session_row.id)

    access = create_access_token(sub=str(row.id), role=row.role)
    refresh = create_refresh_token(sub=str(row.id), session_id=session_id)

    db.execute(
        text("UPDATE user_sessions SET refresh_token_hash=:h WHERE id=:sid"),
        {"h": hash_password(refresh), "sid": session_id},
    )
    _audit(
        db,
        actor_user_id=row.id,
        action="auth.login",
        entity_type="users",
        entity_id=row.id,
        ip=request.client.host if request.client else None,
        ua=request.headers.get("user-agent"),
    )
    db.commit()
    return TokenPair(access_token=access, refresh_token=refresh)


# PUBLIC_INTERFACE
@router.post(
    "/refresh",
    response_model=TokenPair,
    summary="Refresh access token",
    description="Validates refresh token and session, then issues a new access token and refresh token (rotated).",
)
def refresh(req: RefreshRequest, request: Request, db: Session = Depends(get_db)) -> TokenPair:
    """Rotate refresh token and issue a new access token."""
    payload = decode_token(req.refresh_token)
    if payload.get("typ") != "refresh":
        raise HTTPException(status_code=401, detail="Not a refresh token")

    user_id = payload.get("sub")
    sid = payload.get("sid")
    if not user_id or not sid:
        raise HTTPException(status_code=401, detail="Invalid refresh token payload")

    session = db.execute(
        text(
            """
            SELECT id, user_id, refresh_token_hash, revoked_at, expires_at
            FROM user_sessions
            WHERE id = :sid AND user_id = :uid
            """
        ),
        {"sid": sid, "uid": user_id},
    ).fetchone()
    if not session or session.revoked_at is not None:
        raise HTTPException(status_code=401, detail="Session invalid or revoked")
    if session.expires_at and session.expires_at.replace(tzinfo=timezone.utc) < _utcnow():
        raise HTTPException(status_code=401, detail="Session expired")

    if not verify_password(req.refresh_token, session.refresh_token_hash):
        raise HTTPException(status_code=401, detail="Refresh token does not match session")

    user = db.execute(
        text("SELECT id, role, is_active FROM users WHERE id=:uid"),
        {"uid": user_id},
    ).fetchone()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User inactive")

    # rotate: revoke old session and create new session row
    db.execute(text("UPDATE user_sessions SET revoked_at=now() WHERE id=:sid"), {"sid": sid})

    new_sess = db.execute(
        text(
            """
            INSERT INTO user_sessions(user_id, refresh_token_hash, user_agent, ip_address, expires_at)
            VALUES (:user_id, :refresh_token_hash, :ua, :ip, (now() + interval '30 days'))
            RETURNING id
            """
        ),
        {
            "user_id": user_id,
            "refresh_token_hash": hash_password("placeholder"),
            "ua": request.headers.get("user-agent"),
            "ip": request.client.host if request.client else None,
        },
    ).fetchone()
    assert new_sess is not None
    new_sid = str(new_sess.id)

    access = create_access_token(sub=str(user.id), role=user.role)
    refresh_token = create_refresh_token(sub=str(user.id), session_id=new_sid)
    db.execute(
        text("UPDATE user_sessions SET refresh_token_hash=:h WHERE id=:sid"),
        {"h": hash_password(refresh_token), "sid": new_sid},
    )

    _audit(
        db,
        actor_user_id=UUID(str(user.id)),
        action="auth.refresh",
        entity_type="user_sessions",
        entity_id=UUID(new_sid),
        ip=request.client.host if request.client else None,
        ua=request.headers.get("user-agent"),
    )
    db.commit()
    return TokenPair(access_token=access, refresh_token=refresh_token)


# PUBLIC_INTERFACE
def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)) -> UserMe:
    """FastAPI dependency: return current authenticated user."""
    payload = decode_token(token)
    if payload.get("typ") != "access":
        raise HTTPException(status_code=401, detail="Not an access token")

    uid = payload.get("sub")
    if not uid:
        raise HTTPException(status_code=401, detail="Missing subject")
    row = db.execute(
        text(
            """
            SELECT id, email, role, is_active, is_email_verified, created_at
            FROM users
            WHERE id = :uid
            """
        ),
        {"uid": uid},
    ).fetchone()
    if not row or not row.is_active:
        raise HTTPException(status_code=401, detail="User inactive or not found")
    return UserMe(
        id=row.id,
        email=row.email,
        role=row.role,
        is_active=row.is_active,
        is_email_verified=row.is_email_verified,
        created_at=row.created_at,
    )


# PUBLIC_INTERFACE
def require_admin(user: UserMe = Depends(get_current_user)) -> UserMe:
    """FastAPI dependency: require admin role."""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user


# PUBLIC_INTERFACE
@router.get(
    "/me",
    response_model=UserMe,
    summary="Get current user",
    description="Returns the authenticated user's identity from the access token.",
)
def me(user: UserMe = Depends(get_current_user)) -> UserMe:
    """Return current user."""
    return user
