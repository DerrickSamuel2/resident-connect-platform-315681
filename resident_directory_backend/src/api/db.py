"""
Database utilities.

Project rule: ALWAYS read DB connection from database/db_connection.txt.
That file lives in the sibling workspace folder:
  resident-connect-platform-315682/database/db_connection.txt

We parse the 'psql postgresql://...' line to get a SQLAlchemy DATABASE_URL.
Optionally, DATABASE_URL env var can override for deployments.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Generator, Optional

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker


def _find_repo_root(start: Optional[Path] = None) -> Path:
    """Walk up the directory tree until we find the monorepo root."""
    cur = start or Path(__file__).resolve()
    # Expect path like .../resident-connect-platform-315681/resident_directory_backend/src/api/db.py
    for _ in range(12):
        if (cur / "resident-connect-platform-315681").exists() and (
            cur / "resident-connect-platform-315682"
        ).exists():
            return cur
        cur = cur.parent
    # Fallback: assume current file's 5th parent is repo root
    return Path(__file__).resolve().parents[6]


def _read_db_url_from_db_connection_txt() -> str:
    """Parse database/db_connection.txt content and return a SQLAlchemy-compatible URL."""
    repo_root = _find_repo_root()
    conn_path = (
        repo_root
        / "resident-connect-platform-315682"
        / "database"
        / "db_connection.txt"
    )
    if not conn_path.exists():
        raise RuntimeError(
            f"db_connection.txt not found at expected path: {conn_path}. "
            "Ensure the database workspace exists and schema has been applied."
        )
    raw = conn_path.read_text(encoding="utf-8").strip()
    # Expected: "psql postgresql://user:pass@host:port/db"
    if raw.startswith("psql "):
        raw = raw[len("psql ") :].strip()
    if not raw.startswith("postgresql://"):
        raise RuntimeError(
            "db_connection.txt must contain a line like: "
            "'psql postgresql://user:pass@host:port/dbname'"
        )
    return raw


def get_database_url() -> str:
    """Return effective database URL. Env override is supported but not required."""
    return os.getenv("DATABASE_URL") or _read_db_url_from_db_connection_txt()


_ENGINE: Optional[Engine] = None
_SessionLocal: Optional[sessionmaker] = None


# PUBLIC_INTERFACE
def get_engine() -> Engine:
    """Get (or create) the SQLAlchemy engine for the app."""
    global _ENGINE, _SessionLocal
    if _ENGINE is None:
        # Use psycopg3 driver. SQLAlchemy will auto-select psycopg if installed.
        _ENGINE = create_engine(get_database_url(), pool_pre_ping=True)
        _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_ENGINE)
    return _ENGINE


# PUBLIC_INTERFACE
def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that provides a DB session and ensures cleanup."""
    if _SessionLocal is None:
        get_engine()
    assert _SessionLocal is not None
    db = _SessionLocal()
    try:
        yield db
    finally:
        db.close()
