import asyncio
import os
import pytest
from httpx import ASGITransport, AsyncClient
from core.bootstrap import bootstrap_system
from core.config import get_settings
from core.database import Base, close_database, get_engine
from core.redis_client import close_redis_client, get_redis_client
from gateways.pdp_api.main import app


@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    # Force test configuration
    os.environ["AEGIS_ENV"] = "test"
    os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
    os.environ["USE_IN_MEMORY_REDIS"] = "true"
    get_settings.cache_clear()
    bootstrap_system()


@pytest.fixture
async def async_db():
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
async def api_client(async_db):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client
