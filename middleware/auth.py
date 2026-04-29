"""
API key authentication middleware — DB-backed multi-key validation
"""
from fastapi import HTTPException, Request, Security
from fastapi.security import APIKeyHeader
from db.database import SessionLocal
from db.crud import validate_api_key


api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(api_key: str = Security(api_key_header)) -> str:
    """
    Verify API key against the database.
    Returns the key string on success.
    Raises 401 if missing, 403 if invalid/inactive.
    """
    # Strip whitespace — common copy-paste issue with leading/trailing spaces or newlines
    if api_key:
        api_key = api_key.strip()

    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="Missing API key. Provide X-API-Key header."
        )

    async with SessionLocal() as db:
        valid = await validate_api_key(db, api_key)

    if not valid:
        raise HTTPException(
            status_code=403,
            detail="Invalid or inactive API key"
        )

    return api_key
