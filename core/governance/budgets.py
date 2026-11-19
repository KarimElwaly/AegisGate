from typing import Any, Dict, Optional, Tuple
from core.config import get_settings
from core.logger import get_logger
from core.redis_client import get_redis_client
from core.schemas.verdicts import BudgetSnapshot

logger = get_logger("core.governance.budgets")

BUDGET_LUA_SCRIPT = """
local delta_tokens = tonumber(ARGV[1]) or 0
local delta_cost = tonumber(ARGV[2]) or 0
local delta_tool_calls = tonumber(ARGV[3]) or 0
local is_failure = tonumber(ARGV[4]) or 0

local max_tokens = tonumber(ARGV[5]) or 0
local max_cost = tonumber(ARGV[6]) or 0
local max_tool_calls = tonumber(ARGV[7]) or 0
local max_failures = tonumber(ARGV[8]) or 0
local ttl = tonumber(ARGV[9]) or 0

local current_tokens = tonumber(redis.call('HGET', KEYS[1], 'tokens_used')) or 0
local current_cost = tonumber(redis.call('HGET', KEYS[1], 'cost_used_usd')) or 0
local current_tool_calls = tonumber(redis.call('HGET', KEYS[1], 'tool_calls_used')) or 0
local current_failures = tonumber(redis.call('HGET', KEYS[1], 'consecutive_failures')) or 0

if max_tokens > 0 and (current_tokens + delta_tokens) > max_tokens then
    return {0, 'max_tokens_exceeded', tostring(current_tokens + delta_tokens), tostring(max_tokens)}
end
if max_cost > 0 and (current_cost + delta_cost) > max_cost then
    return {0, 'max_cost_exceeded', tostring(current_cost + delta_cost), tostring(max_cost)}
end
if max_tool_calls > 0 and (current_tool_calls + delta_tool_calls) > max_tool_calls then
    return {0, 'max_tool_calls_exceeded', tostring(current_tool_calls + delta_tool_calls), tostring(max_tool_calls)}
end

local new_failures = 0
if is_failure == 1 then
    new_failures = current_failures + 1
    if max_failures > 0 and new_failures > max_failures then
        return {0, 'max_consecutive_failures_exceeded', tostring(new_failures), tostring(max_failures)}
    end
else
    new_failures = 0
end

local new_tokens = current_tokens + delta_tokens
local new_cost = current_cost + delta_cost
local new_tool_calls = current_tool_calls + delta_tool_calls

redis.call('HSET', KEYS[1], 'tokens_used', tostring(new_tokens), 'cost_used_usd', tostring(new_cost), 'tool_calls_used', tostring(new_tool_calls), 'consecutive_failures', tostring(new_failures))

if ttl > 0 then
    redis.call('EXPIRE', KEYS[1], ttl)
end

return {1, 'ok', tostring(new_tokens), tostring(new_cost), tostring(new_tool_calls), tostring(new_failures)}
"""


class BudgetManager:
    """Atomic Redis Lua Budget & Quota enforcement per Tenant, Workspace, Session, or Agent."""

    def __init__(self) -> None:
        self._local_storage: Dict[str, Dict[str, Any]] = {}

    def _get_budget_key(self, tenant_id: str, scope_type: str, scope_id: str) -> str:
        prefix = get_settings().REDIS_KEY_PREFIX
        return f"{prefix}budget:{tenant_id}:{scope_type}:{scope_id}"

    async def check_and_consume(
        self,
        tenant_id: str,
        scope_type: str,
        scope_id: str,
        delta_tokens: int = 0,
        delta_cost_usd: float = 0.0,
        delta_tool_calls: int = 0,
        is_failure: bool = False,
        max_tokens: int = 0,
        max_cost_usd: float = 0.0,
        max_tool_calls: int = 0,
        max_consecutive_failures: int = 0,
        ttl_seconds: int = 86400,
    ) -> Tuple[bool, str, BudgetSnapshot]:
        key = self._get_budget_key(tenant_id, scope_type, scope_id)

        try:
            redis = await get_redis_client()
            res = await redis.eval(
                BUDGET_LUA_SCRIPT,
                1,
                key,
                delta_tokens,
                delta_cost_usd,
                delta_tool_calls,
                1 if is_failure else 0,
                max_tokens,
                max_cost_usd,
                max_tool_calls,
                max_consecutive_failures,
                ttl_seconds,
            )

            is_allowed = bool(res[0] == 1)
            status_or_reason = str(res[1])

            if is_allowed:
                snapshot = BudgetSnapshot(
                    tokens_used=int(res[2]),
                    tokens_limit=max_tokens,
                    cost_used_usd=float(res[3]),
                    cost_limit_usd=max_cost_usd,
                    tool_calls_used=int(res[4]),
                    tool_calls_limit=max_tool_calls,
                )
            else:
                current_val = float(res[2]) if "." in str(res[2]) else int(res[2])
                snapshot = BudgetSnapshot(
                    tokens_used=int(current_val) if "tokens" in status_or_reason else 0,
                    tokens_limit=max_tokens,
                    cost_used_usd=float(current_val) if "cost" in status_or_reason else 0.0,
                    cost_limit_usd=max_cost_usd,
                    tool_calls_used=int(current_val) if "tool_calls" in status_or_reason else 0,
                    tool_calls_limit=max_tool_calls,
                )

            return is_allowed, status_or_reason, snapshot
        except Exception as exc:
            # Memory fallback when Redis/Lua is not available in mock/testing
            if key not in self._local_storage:
                self._local_storage[key] = {
                    "tokens_used": 0,
                    "cost_used_usd": 0.0,
                    "tool_calls_used": 0,
                    "consecutive_failures": 0,
                }
            curr = self._local_storage[key]
            if max_tokens > 0 and (curr["tokens_used"] + delta_tokens) > max_tokens:
                return False, "max_tokens_exceeded", BudgetSnapshot(tokens_used=curr["tokens_used"] + delta_tokens, tokens_limit=max_tokens)
            if max_cost_usd > 0 and (curr["cost_used_usd"] + delta_cost_usd) > max_cost_usd:
                return False, "max_cost_exceeded", BudgetSnapshot(cost_used_usd=curr["cost_used_usd"] + delta_cost_usd, cost_limit_usd=max_cost_usd)
            if max_tool_calls > 0 and (curr["tool_calls_used"] + delta_tool_calls) > max_tool_calls:
                return False, "max_tool_calls_exceeded", BudgetSnapshot(tool_calls_used=curr["tool_calls_used"] + delta_tool_calls, tool_calls_limit=max_tool_calls)

            curr["tokens_used"] += delta_tokens
            curr["cost_used_usd"] += delta_cost_usd
            curr["tool_calls_used"] += delta_tool_calls
            if is_failure:
                curr["consecutive_failures"] += 1
                if max_consecutive_failures > 0 and curr["consecutive_failures"] > max_consecutive_failures:
                    return False, "max_consecutive_failures_exceeded", BudgetSnapshot()
            else:
                curr["consecutive_failures"] = 0

            return True, "ok", BudgetSnapshot(
                tokens_used=curr["tokens_used"],
                tokens_limit=max_tokens,
                cost_used_usd=curr["cost_used_usd"],
                cost_limit_usd=max_cost_usd,
                tool_calls_used=curr["tool_calls_used"],
                tool_calls_limit=max_tool_calls,
            )

    async def get_budget_snapshot(self, tenant_id: str, scope_type: str, scope_id: str) -> BudgetSnapshot:
        key = self._get_budget_key(tenant_id, scope_type, scope_id)
        if key in self._local_storage:
            curr = self._local_storage[key]
            return BudgetSnapshot(
                tokens_used=curr["tokens_used"],
                cost_used_usd=curr["cost_used_usd"],
                tool_calls_used=curr["tool_calls_used"],
            )
        try:
            redis = await get_redis_client()
            data = await redis.hgetall(key)
            if data:
                return BudgetSnapshot(
                    tokens_used=int(data.get("tokens_used", 0)),
                    cost_used_usd=float(data.get("cost_used_usd", 0.0)),
                    tool_calls_used=int(data.get("tool_calls_used", 0)),
                )
        except Exception:
            pass
        return BudgetSnapshot()

    async def reset_budget(self, tenant_id: str, scope_type: str, scope_id: str) -> None:
        key = self._get_budget_key(tenant_id, scope_type, scope_id)
        self._local_storage.pop(key, None)
        try:
            redis = await get_redis_client()
            await redis.delete(key)
        except Exception:
            pass


default_budget_manager = BudgetManager()


def get_budget_manager() -> BudgetManager:
    return default_budget_manager
