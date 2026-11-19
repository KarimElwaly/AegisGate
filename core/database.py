from contextlib import asynccontextmanager
from typing import AsyncGenerator
from sqlalchemy.pool import NullPool, StaticPool
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase
from core.config import get_settings
from core.logger import get_logger

logger = get_logger("core.database")


class Base(DeclarativeBase):
    pass


_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        settings = get_settings()
        connect_args = {}
        engine_kwargs = {
            "echo": False,
            "future": True,
        }
        if "sqlite" in settings.DATABASE_URL:
            connect_args["check_same_thread"] = False
            if settings.AEGIS_ENV == "test":
                engine_kwargs["poolclass"] = NullPool
            elif ":memory:" in settings.DATABASE_URL:
                engine_kwargs["poolclass"] = StaticPool

        engine_kwargs["connect_args"] = connect_args
        _engine = create_async_engine(
            settings.DATABASE_URL,
            **engine_kwargs,
        )
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    global _sessionmaker
    if _sessionmaker is None:
        engine = get_engine()
        _sessionmaker = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _sessionmaker


@asynccontextmanager
async def db_context() -> AsyncGenerator[AsyncSession, None]:
    """Safe context manager for background services & non-request DB operations."""
    maker = get_sessionmaker()
    async with maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI Depends generator for request-scoped database sessions."""
    maker = get_sessionmaker()
    async with maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def close_database() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _sessionmaker = None
