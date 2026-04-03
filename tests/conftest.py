"""
Test fixtures and configuration for the Scanner API test suite.
"""
import pytest
import pytest_asyncio
import httpx
import respx
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.orm import declarative_base
from unittest.mock import AsyncMock, patch

from app import app
from db.database import Base
from app import get_db

# -------------------------------------------------------------------------
# In-memory test database
# -------------------------------------------------------------------------

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

test_engine = create_async_engine(TEST_DATABASE_URL, echo=False)
TestSessionLocal = async_sessionmaker(test_engine, expire_on_commit=False)


async def override_get_db():
    """Override the real DB with an in-memory SQLite session."""
    async with TestSessionLocal() as session:
        yield session


# Patch Redis in canonicalizer at module level so every test skips Redis
import services.canonicalizer as _canonicalizer_mod

_canonicalizer_mod._redis_checked = True
_canonicalizer_mod._redis_client = None


@pytest.fixture(autouse=True, scope="session")
def _no_redis_url_cache():
    """
    Force URLCache to behave as if Redis is unavailable for all tests.
    The URLCache lazy-initialises; we pre-mark it as checked & unavailable.
    """
    from services.url_scanner import _url_cache
    _url_cache._checked = True
    _url_cache._redis = None
    yield


@pytest_asyncio.fixture(scope="session", autouse=True)
async def _create_test_tables():
    """Create all tables once per session."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def client():
    """Async test client with DB override."""
    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


@pytest.fixture
def phishing_payload():
    return {
        "email_address": "test@paypa1.com",
        "email_text": "Click here to verify your PayPal account immediately",
    }


@pytest.fixture
def safe_payload():
    return {
        "email_address": "user@gmail.com",
        "email_text": "Hi, see you at the meeting tomorrow",
    }


# -------------------------------------------------------------------------
# respx HTTP mock fixtures
# -------------------------------------------------------------------------

@pytest.fixture
def mock_gsb():
    with respx.mock:
        respx.post("https://safebrowsing.googleapis.com/v4/threatMatches:find").mock(
            return_value=httpx.Response(200, json={"matches": [{"threat": {"url": "http://evil.com"}}]})
        )
        yield


@pytest.fixture
def mock_gsb_clean():
    with respx.mock:
        respx.post("https://safebrowsing.googleapis.com/v4/threatMatches:find").mock(
            return_value=httpx.Response(200, json={})
        )
        yield


@pytest.fixture
def mock_redirect():
    with respx.mock:
        respx.get("https://bit.ly/test123").mock(
            return_value=httpx.Response(301,
                headers={"location": "http://phishing-destination.com"})
        )
        respx.get("http://phishing-destination.com").mock(
            return_value=httpx.Response(200)
        )
        yield


# -------------------------------------------------------------------------
# Async DB session fixture for CRUD tests (isolated per test)
# -------------------------------------------------------------------------

_crud_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
_CrudSessionLocal = async_sessionmaker(_crud_engine, expire_on_commit=False)


@pytest_asyncio.fixture
async def async_db_session():
    """Fresh in-memory SQLite session with all tables, dropped after each test."""
    async with _crud_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with _CrudSessionLocal() as session:
        yield session
    async with _crud_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
def mock_openphish_feed():
    with respx.mock:
        respx.get(url__startswith="https://raw.githubusercontent.com/openphish").mock(
            return_value=httpx.Response(200,
                text="http://evil1.com\nhttp://evil2.com\nhttp://phishing3.com\n")
        )
        yield


@pytest.fixture
def mock_multi_hop_redirect():
    with respx.mock:
        respx.get("https://bit.ly/abc").mock(
            return_value=httpx.Response(301,
                headers={"location": "https://tinyurl.com/xyz"}))
        respx.get("https://tinyurl.com/xyz").mock(
            return_value=httpx.Response(301,
                headers={"location": "http://final-phishing-destination.com"}))
        respx.get("http://final-phishing-destination.com").mock(
            return_value=httpx.Response(200))
        yield


@pytest.fixture
def mock_redirect_timeout():
    with respx.mock:
        respx.get("https://slow-redirect.com").mock(
            side_effect=httpx.TimeoutException("timeout"))
        yield


@pytest.fixture
def mock_gsb_full():
    with respx.mock:
        respx.post(url__startswith="https://safebrowsing.googleapis.com").mock(
            return_value=httpx.Response(200, json={
                "matches": [
                    {"threat": {"url": "http://evil.com"},
                     "threatType": "SOCIAL_ENGINEERING"},
                    {"threat": {"url": "http://malware.com"},
                     "threatType": "MALWARE"}
                ]
            })
        )
        yield


@pytest.fixture
def mock_gsb_network_error():
    with respx.mock:
        respx.post(url__startswith="https://safebrowsing.googleapis.com").mock(
            side_effect=httpx.NetworkError("connection failed"))
        yield


@pytest.fixture
def mock_openphish_error():
    with respx.mock:
        respx.get(url__startswith="https://raw.githubusercontent.com/openphish").mock(
            return_value=httpx.Response(500))
        yield
