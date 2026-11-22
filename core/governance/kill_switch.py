from typing import Any

from core.config import get_settings
from core.logger import get_logger
from core.redis_client import get_redis_client

logger = get_logger("core.governance.kill_switch")


class KillSwitchService:
    """Sub-millisecond emergency circuit breaker.
    Checked first on every request. Supports instant pause/block at:
    - GLOBAL
    - TENANT
    - WORKSPACE
    - AGENT
    - TOOL
    """

    def __init__(self) -> None:
        self._local_kill_switches: dict[str, str] = {}

    def _get_key(self, scope: str, target: str, tenant_id: str = "default") -> str:
        prefix = get_settings().REDIS_KEY_PREFIX
        scope = scope.lower()
        if scope == "global":
            return f"{prefix}kill:global"
        elif scope == "tenant":
            return f"{prefix}kill:tenant:{target or tenant_id}"
        elif scope == "workspace":
            return f"{prefix}kill:workspace:{tenant_id}:{target}"
        elif scope == "agent":
            return f"{prefix}kill:agent:{tenant_id}:{target}"
        elif scope == "tool":
            return f"{prefix}kill:tool:{tenant_id}:{target}"
        elif scope == "session":
            return f"{prefix}kill:session:{tenant_id}:{target}"
        return f"{prefix}kill:{scope}:{target}"

    async def set_kill_switch(
        self,
        scope: str,
        target: str,
        reason: str = "Emergency kill switch activated",
        tenant_id: str = "default",
        ttl_seconds: int | None = None,
    ) -> str:
        key = self._get_key(scope, target, tenant_id)
        try:
            redis = await get_redis_client()
            if ttl_seconds:
                await redis.setex(key, ttl_seconds, reason)
            else:
                await redis.set(key, reason)
            # Track in active index set
            prefix = get_settings().REDIS_KEY_PREFIX
            await redis.sadd(f"{prefix}kill:active_keys", key)
        except Exception as e:
            logger.warning("Redis kill switch write failed, using local memory", error=str(e))
            self._local_kill_switches[key] = reason

        logger.critical(
            "KILL SWITCH ACTIVATED",
            scope=scope,
            target=target,
            tenant_id=tenant_id,
            reason=reason,
        )
        return key

    async def engage(
        self,
        scope: str,
        target: str = "",
        reason: str = "Emergency kill switch activated",
        tenant_id: str = "default",
        operator: str = "admin",
        ttl_seconds: int | None = None,
    ) -> str:
        """Convenience method to trip a kill switch, supporting 'scope:target' notation."""
        if ":" in scope and not target:
            scope_part, target_part = scope.split(":", 1)
            scope = scope_part
            target = target_part
        return await self.set_kill_switch(
            scope=scope,
            target=target,
            reason=reason,
            tenant_id=tenant_id,
            ttl_seconds=ttl_seconds,
        )

    async def is_tripped(
        self,
        tenant_id: str = "default",
        workspace_id: str = "default",
        agent_id: str = "default",
        session_id: str | None = None,
        tool_name: str | None = None,
    ) -> tuple[bool, str | None]:
        """Checks if a kill switch is active across global, tenant, workspace, agent, session, or tool."""
        is_killed, scope, reason = await self.check_kill_switches(
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            agent_id=agent_id,
            tool_name=tool_name,
        )
        if is_killed:
            return True, reason
        if session_id:
            prefix = get_settings().REDIS_KEY_PREFIX
            session_key = f"{prefix}kill:session:{tenant_id}:{session_id}"
            try:
                redis = await get_redis_client()
                val = await redis.get(session_key)
                if val is not None:
                    return True, str(val)
            except Exception:
                if session_key in self._local_kill_switches:
                    return True, self._local_kill_switches[session_key]
        return False, None

    async def remove_kill_switch(
        self,
        scope: str,
        target: str,
        tenant_id: str = "default",
    ) -> bool:
        key = self._get_key(scope, target, tenant_id)
        try:
            redis = await get_redis_client()
            await redis.delete(key)
            prefix = get_settings().REDIS_KEY_PREFIX
            await redis.srem(f"{prefix}kill:active_keys", key)
        except Exception:
            self._local_kill_switches.pop(key, None)

        logger.info("Kill switch deactivated", scope=scope, target=target)
        return True

    async def check_kill_switches(
        self,
        tenant_id: str,
        workspace_id: str,
        agent_id: str,
        tool_name: str | None = None,
    ) -> tuple[bool, str | None, str | None]:
        """Atomic check across all 5 scopes in a single Redis MGET roundtrip.
        Returns: (is_killed, scope, reason)
        """
        prefix = get_settings().REDIS_KEY_PREFIX
        global_key = f"{prefix}kill:global"
        tenant_key = f"{prefix}kill:tenant:{tenant_id}"
        workspace_key = f"{prefix}kill:workspace:{tenant_id}:{workspace_id}"
        agent_key = f"{prefix}kill:agent:{tenant_id}:{agent_id}"
        tool_key = f"{prefix}kill:tool:{tenant_id}:{tool_name}" if tool_name else None

        keys_to_check = [global_key, tenant_key, workspace_key, agent_key]
        if tool_key:
            keys_to_check.append(tool_key)

        try:
            redis = await get_redis_client()
            values = await redis.mget(keys_to_check)
            for k, val in zip(keys_to_check, values):
                if val is not None:
                    scope = k.split(":")[2]
                    return True, scope, str(val)
        except Exception:
            # Check local memory fallback
            for k in keys_to_check:
                if k in self._local_kill_switches:
                    scope = k.split(":")[2]
                    return True, scope, self._local_kill_switches[k]

        return False, None, None

    async def list_active_kill_switches(self) -> list[dict[str, Any]]:
        prefix = get_settings().REDIS_KEY_PREFIX
        active: list[dict[str, Any]] = []
        try:
            redis = await get_redis_client()
            keys = await redis.smembers(f"{prefix}kill:active_keys")
            for k in keys:
                val = await redis.get(k)
                if val:
                    parts = k.split(":")
                    scope = parts[2] if len(parts) > 2 else "unknown"
                    active.append({"key": k, "scope": scope, "reason": str(val)})
        except Exception:
            for k, val in self._local_kill_switches.items():
                parts = k.split(":")
                scope = parts[2] if len(parts) > 2 else "unknown"
                active.append({"key": k, "scope": scope, "reason": val})

        return active


default_kill_switch_service = KillSwitchService()


def get_kill_switch_service() -> KillSwitchService:
    return default_kill_switch_service

