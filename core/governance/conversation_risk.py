import json
import time
from typing import Any
from pydantic import BaseModel, Field

from core.logger import get_logger
from core.redis_client import get_redis_client

logger = get_logger("core.governance.conversation_risk")


class ConversationRiskSummary(BaseModel):
    cumulative_risk_score: float = 0.0
    high_risk_turns: int = 0
    total_turns: int = 0
    decay_factor: float = 0.85


class ConversationRiskTracker:
    """Multi-Turn Conversational Risk Accumulator (Crescendo Defense).
    Maintains a sliding window of risk scores across turns in an interactive session
    backed by Redis (aegis:conv_risk:{tenant}:{session_id}) with exponential decay.
    """

    DEFAULT_TTL_SECONDS = 7200
    DEFAULT_DECAY = 0.85
    HIGH_RISK_THRESHOLD = 0.25
    MAX_WINDOW_TURNS = 20

    def __init__(self) -> None:
        self._memory_cache: dict[str, list[dict[str, Any]]] = {}

    def _get_key(self, tenant_id: str, session_id: str) -> str:
        return f"aegis:conv_risk:{tenant_id}:{session_id}"

    async def get_session_risk(
        self,
        tenant_id: str,
        session_id: str,
        decay: float = DEFAULT_DECAY,
    ) -> ConversationRiskSummary:
        """Calculates decaying cumulative risk score and counts high-risk turns for a session."""
        if not session_id:
            return ConversationRiskSummary()

        turns = await self._load_turns(tenant_id, session_id)
        if not turns:
            return ConversationRiskSummary(decay_factor=decay)

        # Calculate decaying cumulative risk across turns (oldest to newest)
        n = len(turns)
        cumulative = 0.0
        high_risk_count = 0

        for i, turn in enumerate(turns):
            score = float(turn.get("score", 0.0))
            if score >= self.HIGH_RISK_THRESHOLD:
                high_risk_count += 1
            # Weight older turns less using exponential decay
            weight = decay ** (n - 1 - i)
            cumulative += score * weight

        return ConversationRiskSummary(
            cumulative_risk_score=min(1.0, round(cumulative, 3)),
            high_risk_turns=high_risk_count,
            total_turns=n,
            decay_factor=decay,
        )

    async def record_turn_risk(
        self,
        tenant_id: str,
        session_id: str,
        turn_risk: float,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> ConversationRiskSummary:
        """Appends a new turn's risk score to the session's sliding window and returns updated summary."""
        if not session_id:
            return ConversationRiskSummary()

        turn_entry = {
            "score": round(max(0.0, min(1.0, float(turn_risk))), 3),
            "timestamp": time.time(),
        }

        turns = await self._load_turns(tenant_id, session_id)
        turns.append(turn_entry)
        if len(turns) > self.MAX_WINDOW_TURNS:
            turns = turns[-self.MAX_WINDOW_TURNS:]

        await self._save_turns(tenant_id, session_id, turns, ttl_seconds)
        return await self.get_session_risk(tenant_id, session_id)

    async def reset_session_risk(self, tenant_id: str, session_id: str) -> None:
        """Clears accumulated conversation risk for a session."""
        if not session_id:
            return
        key = self._get_key(tenant_id, session_id)
        self._memory_cache.pop(key, None)
        try:
            redis = await get_redis_client()
            await redis.delete(key)
        except Exception:
            pass

    async def _load_turns(self, tenant_id: str, session_id: str) -> list[dict[str, Any]]:
        key = self._get_key(tenant_id, session_id)
        try:
            redis = await get_redis_client()
            raw = await redis.get(key)
            if raw:
                data = json.loads(raw)
                if isinstance(data, list):
                    return data
        except Exception:
            pass
        return list(self._memory_cache.get(key, []))

    async def _save_turns(
        self,
        tenant_id: str,
        session_id: str,
        turns: list[dict[str, Any]],
        ttl_seconds: int,
    ) -> None:
        key = self._get_key(tenant_id, session_id)
        self._memory_cache[key] = turns
        try:
            redis = await get_redis_client()
            await redis.set(key, json.dumps(turns), ex=ttl_seconds)
        except Exception as e:
            logger.debug("redis_conversation_risk_save_fallback", error=str(e))


default_conversation_risk_tracker = ConversationRiskTracker()


def get_conversation_risk_tracker() -> ConversationRiskTracker:
    return default_conversation_risk_tracker

