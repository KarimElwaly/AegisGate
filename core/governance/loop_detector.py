import hashlib
import json
import time
from typing import Any, Dict, Optional, Tuple
from core.config import get_settings
from core.logger import get_logger
from core.redis_client import get_redis_client

logger = get_logger("core.governance.loop_detector")

LOOP_DETECTOR_LUA = """
local key = KEYS[1]
local now_sec = tonumber(ARGV[1])
local window_sec = tonumber(ARGV[2])
local call_hash = tostring(ARGV[3])
local threshold = tonumber(ARGV[4])
local member_id = tostring(ARGV[5])

-- 1. Expire entries outside the sliding window
local min_score = now_sec - window_sec
redis.call('ZREMRANGEBYSCORE', key, '-inf', min_score)

-- 2. Add current call
redis.call('ZADD', key, now_sec, member_id)
redis.call('EXPIRE', key, window_sec * 2)

-- 3. Count occurrences of this call_hash in the active window
local members = redis.call('ZRANGEBYSCORE', key, min_score, '+inf')
local match_count = 0
for i = 1, #members do
    local m = members[i]
    -- member format: "<random_uuid>:<call_hash>"
    if string.sub(m, -#call_hash) == call_hash then
        match_count = match_count + 1
    end
end

if match_count >= threshold then
    return {1, match_count}
else
    return {0, match_count}
end
"""


class LoopDetector:
    """Sliding-window Runaway Loop Detector.
    Detects when an agent or session repeatedly invokes the exact same action/parameters
    within a short time window and trips circuit breaker before cost or recursion cascades.
    """

    def __init__(self) -> None:
        self._local_history: Dict[str, list] = {}

    @staticmethod
    def compute_call_hash(actor_id: str, action_name: str, parameters: Dict[str, Any]) -> str:
        canonical_params = json.dumps(parameters or {}, sort_keys=True, default=str)
        raw = f"{actor_id}:{action_name}:{canonical_params}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    async def record_and_check(
        self,
        tenant_id: str,
        session_id: str,
        actor_id: str,
        action_name: str,
        parameters: Dict[str, Any],
        threshold: int = 3,
        window_seconds: int = 60,
    ) -> Tuple[bool, int, str]:
        """Returns: (is_tripped, count, call_hash)"""
        call_hash = self.compute_call_hash(actor_id, action_name, parameters)
        prefix = get_settings().REDIS_KEY_PREFIX
        key = f"{prefix}loop:{tenant_id}:{session_id or 'global'}"
        now = time.time()
        member_id = f"{now:.6f}_{time.monotonic()}:{call_hash}"

        try:
            redis = await get_redis_client()
            res = await redis.eval(
                LOOP_DETECTOR_LUA,
                1,
                key,
                int(now),
                window_seconds,
                call_hash,
                threshold,
                member_id,
            )
            is_tripped = bool(res[0] == 1)
            count = int(res[1])
            if is_tripped:
                logger.warning(
                    "RUNAWAY LOOP DETECTED",
                    tenant_id=tenant_id,
                    session_id=session_id,
                    action=action_name,
                    count=count,
                    threshold=threshold,
                )
            return is_tripped, count, call_hash
        except Exception as exc:
            logger.warning("Redis loop detector Lua failed, using memory fallback", error=str(exc))
            # In-memory fallback
            if key not in self._local_history:
                self._local_history[key] = []

            # Purge expired
            min_time = now - window_seconds
            self._local_history[key] = [
                item for item in self._local_history[key] if item["timestamp"] >= min_time
            ]
            self._local_history[key].append({"timestamp": now, "hash": call_hash})

            count = sum(1 for item in self._local_history[key] if item["hash"] == call_hash)
            is_tripped = count >= threshold
            if is_tripped:
                logger.warning("RUNAWAY LOOP DETECTED (memory fallback)", action=action_name, count=count)
            return is_tripped, count, call_hash

    async def reset(self, tenant_id: str, session_id: str) -> None:
        prefix = get_settings().REDIS_KEY_PREFIX
        key = f"{prefix}loop:{tenant_id}:{session_id or 'global'}"
        try:
            redis = await get_redis_client()
            await redis.delete(key)
        except Exception:
            pass
        self._local_history.pop(key, None)


default_loop_detector = LoopDetector()


def get_loop_detector() -> LoopDetector:
    return default_loop_detector
