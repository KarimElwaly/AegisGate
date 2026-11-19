
import redis.asyncio as aioredis

from core.config import get_settings
from core.logger import get_logger

logger = get_logger("core.redis")

_redis_client: aioredis.Redis | None = None


async def get_redis_client() -> aioredis.Redis:
    global _redis_client
    if _redis_client is not None:
        return _redis_client

    settings = get_settings()

    if settings.USE_IN_MEMORY_REDIS:
        import fakeredis.aioredis as fake_aioredis
        logger.info("Initializing in-memory FakeRedis client")
        _redis_client = fake_aioredis.FakeRedis(decode_responses=True)
        return _redis_client

    try:
        client = aioredis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            socket_timeout=1.0,
            socket_connect_timeout=1.0,
        )
        await client.ping()
        _redis_client = client
        logger.info("Connected to live Redis", url=settings.REDIS_URL)
        return _redis_client
    except Exception as exc:
        logger.warning(
            "Live Redis unreachable or auth failed, falling back to in-memory FakeRedis",
            error=str(exc),
        )
        import fakeredis.aioredis as fake_aioredis
        _redis_client = fake_aioredis.FakeRedis(decode_responses=True)
        return _redis_client


async def close_redis_client() -> None:
    global _redis_client
    if _redis_client is not None:
        try:
            await _redis_client.close()
        except Exception:
            pass
        _redis_client = None

