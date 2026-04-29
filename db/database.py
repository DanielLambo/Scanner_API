"""
SQLAlchemy async database setup.
Reads DATABASE_URL from env; defaults to local SQLite.
Supports Postgres via postgresql+asyncpg:// URLs.
"""
import os

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.orm import declarative_base

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite+aiosqlite:///./scanner_feedback.db")

# Normalize common Postgres URL shapes to the async driver
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+asyncpg://", 1)
elif DATABASE_URL.startswith("postgresql://") and "+asyncpg" not in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)

# asyncpg does not understand ?sslmode=require; strip it (TLS is on by default for managed PG)
if "+asyncpg" in DATABASE_URL and "sslmode=" in DATABASE_URL:
    from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
    parsed = urlparse(DATABASE_URL)
    query = [(k, v) for k, v in parse_qsl(parsed.query) if k != "sslmode"]
    DATABASE_URL = urlunparse(parsed._replace(query=urlencode(query)))

engine = create_async_engine(DATABASE_URL, echo=False, pool_pre_ping=True)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)
Base = declarative_base()
