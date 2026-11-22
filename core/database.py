import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import NullPool, StaticPool

from core.config import get_settings
from core.logger import get_logger

logger = get_logger("core.database")


class Base(DeclarativeBase):
    pass


_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None
_engine_loop: asyncio.AbstractEventLoop | None = None


def get_engine() -> AsyncEngine:
    global _engine, _engine_loop
    current_loop = None
    try:
        current_loop = asyncio.get_running_loop()
    except RuntimeError:
        pass

    if _engine is not None and current_loop is not None and _engine_loop is not None and _engine_loop is not current_loop:
        _engine = None
        _sessionmaker = None

    if _engine is None:
        _engine_loop = current_loop
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
        if "sqlite" in settings.DATABASE_URL:
            from sqlalchemy import event

            @event.listens_for(_engine.sync_engine, "connect")
            def set_sqlite_pragma(dbapi_connection, connection_record):
                try:
                    cursor = dbapi_connection.cursor()
                    cursor.execute("PRAGMA journal_mode=WAL")
                    cursor.execute("PRAGMA synchronous=NORMAL")
                    cursor.close()
                except Exception:
                    pass
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    global _sessionmaker
    current_loop = None
    try:
        current_loop = asyncio.get_running_loop()
    except RuntimeError:
        pass

    if _sessionmaker is not None and current_loop is not None and _engine_loop is not None and _engine_loop is not current_loop:
        _sessionmaker = None

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
        except BaseException:
            await session.rollback()
            raise


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI Depends generator for request-scoped database sessions."""
    maker = get_sessionmaker()
    async with maker() as session:
        try:
            yield session
            await session.commit()
        except BaseException:
            await session.rollback()
            raise
        finally:
            await session.close()


async def close_database() -> None:
    global _engine, _sessionmaker, _engine_loop
    if _engine is not None:
        try:
            await _engine.dispose()
        except Exception:
            pass
        _engine = None
        _sessionmaker = None
        _engine_loop = None
