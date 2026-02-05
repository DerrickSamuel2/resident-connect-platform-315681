"""Security helpers: password hashing + JWT creation/verification."""

from __future__ import annotations

import os
import time
from typing import Any, Dict, Optional

import jwt
from fastapi import HTTPException, status
from passlib.context import CryptContext

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _get_env(name: str, default: Optional[str] = None) -> str:
    val = os.getenv(name, default)
    if val is None or val == "":
        raise RuntimeError(f"Missing required environment variable: {name}")
    return val


def get_jwt_settings() -> Dict[str, Any]:
    """Load JWT settings from environment (do not hardcode secrets)."""
    return {
        "secret": _get_env("JWT_SECRET"),
        "issuer": os.getenv("JWT_ISSUER", "resident-directory-backend"),
        "audience": os.getenv("JWT_AUDIENCE", "resident-directory-frontend"),
        "access_expires_minutes": int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15")),
        "refresh_expires_days": int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "30")),
    }


# PUBLIC_INTERFACE
def hash_password(password: str) -> str:
    """Hash a password using passlib."""
    return _pwd_context.hash(password)


# PUBLIC_INTERFACE
def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against stored hash."""
    return _pwd_context.verify(password, password_hash)


def _now_ts() -> int:
    return int(time.time())


# PUBLIC_INTERFACE
def create_access_token(*, sub: str, role: str) -> str:
    """Create a short-lived access token."""
    s = get_jwt_settings()
    iat = _now_ts()
    exp = iat + s["access_expires_minutes"] * 60
    payload = {
        "typ": "access",
        "sub": sub,
        "role": role,
        "iss": s["issuer"],
        "aud": s["audience"],
        "iat": iat,
        "exp": exp,
    }
    return jwt.encode(payload, s["secret"], algorithm="HS256")


# PUBLIC_INTERFACE
def create_refresh_token(*, sub: str, session_id: str) -> str:
    """Create a longer-lived refresh token bound to a server-side session row."""
    s = get_jwt_settings()
    iat = _now_ts()
    exp = iat + s["refresh_expires_days"] * 24 * 60 * 60
    payload = {
        "typ": "refresh",
        "sub": sub,
        "sid": session_id,
        "iss": s["issuer"],
        "aud": s["audience"],
        "iat": iat,
        "exp": exp,
    }
    return jwt.encode(payload, s["secret"], algorithm="HS256")


# PUBLIC_INTERFACE
def decode_token(token: str) -> Dict[str, Any]:
    """Decode and validate token; raise 401 on failure."""
    s = get_jwt_settings()
    try:
        return jwt.decode(
            token,
            s["secret"],
            algorithms=["HS256"],
            audience=s["audience"],
            issuer=s["issuer"],
        )
    except jwt.PyJWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}",
        ) from e
