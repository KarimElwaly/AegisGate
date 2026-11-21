from core.logger import get_logger
from core.redis_client import get_redis_client

logger = get_logger("core.governance.taint_tracker")


class TaintTracker:
    """Stateful Session Taint Tracker.
    Stores and tracks security labels/taints attached to active multi-agent sessions in Redis.
    Enables detection and blocking of toxic multi-step tool execution chains.
    """

    DEFAULT_TTL_SECONDS = 3600

    def _get_key(self, tenant_id: str, session_id: str) -> str:
        return f"aegis:taint:{tenant_id}:{session_id}"

    async def add_taints(
        self,
        tenant_id: str,
        session_id: str,
        taints: list[str] | set[str],
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> set[str]:
        if not taints:
            return await self.get_taints(tenant_id, session_id)

        redis = await get_redis_client()
        key = self._get_key(tenant_id, session_id)
        clean_taints = [str(t).strip().lower() for t in taints if str(t).strip()]
        if clean_taints:
            await redis.sadd(key, *clean_taints)
            await redis.expire(key, ttl_seconds)

        return await self.get_taints(tenant_id, session_id)

    async def get_taints(self, tenant_id: str, session_id: str) -> set[str]:
        if not session_id:
            return set()
        redis = await get_redis_client()
        key = self._get_key(tenant_id, session_id)
        members = await redis.smembers(key)
        return {m.decode("utf-8") if isinstance(m, bytes) else str(m) for m in members}

    async def has_any_taints(
        self, tenant_id: str, session_id: str, target_taints: list[str]
    ) -> bool:
        current = await self.get_taints(tenant_id, session_id)
        targets = {t.strip().lower() for t in target_taints}
        return bool(current.intersection(targets))

    async def has_all_taints(
        self, tenant_id: str, session_id: str, target_taints: list[str]
    ) -> bool:
        current = await self.get_taints(tenant_id, session_id)
        targets = {t.strip().lower() for t in target_taints}
        return targets.issubset(current)

    async def clear_taints(self, tenant_id: str, session_id: str) -> bool:
        redis = await get_redis_client()
        key = self._get_key(tenant_id, session_id)
        deleted = await redis.delete(key)
        return bool(deleted)


default_taint_tracker = TaintTracker()


def get_taint_tracker() -> TaintTracker:
    return default_taint_tracker
