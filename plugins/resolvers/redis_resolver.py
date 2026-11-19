import json
import re
from typing import Any, Dict
from pydantic import BaseModel, ConfigDict, Field
from core.logger import get_logger
from core.redis_client import get_redis_client
from core.registry.interfaces import BaseContextResolver
from core.schemas.events import EvaluationRequest

logger = get_logger("plugins.resolvers.redis")


class RedisStateResolverConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    enabled: bool = True
    key_template: str = "aegisgate:state:{actor_id}"
    data_type: str = "json"  # "string" | "hash" | "json"
    output_key: str = "redis_state"
    fallback_response: Dict[str, Any] = Field(default_factory=dict)


class RedisStateResolver(BaseContextResolver):
    name = "redis_state_resolver"
    version = "1.0.0"
    config_schema = RedisStateResolverConfig

    def _format_key(self, template: str, request: EvaluationRequest) -> str:
        params = request.action.parameters or {}
        context_vars = {
            "tenant_id": request.tenant_id,
            "session_id": request.session_id or "global",
            "actor_id": request.actor.id,
            "actor_role": request.actor.role,
            "action_name": request.action.name,
            **params,
        }

        def repl(match):
            key = match.group(1)
            return str(context_vars.get(key, ""))

        return re.sub(r"\{([a-zA-Z0-9_]+)\}", repl, template)

    async def resolve(
        self,
        request: EvaluationRequest,
        config: BaseModel,
    ) -> Dict[str, Any]:
        cfg = config if isinstance(config, RedisStateResolverConfig) else RedisStateResolverConfig(**config.model_dump())
        if not cfg.enabled:
            return {}

        key = self._format_key(cfg.key_template, request)
        try:
            redis = await get_redis_client()
            if cfg.data_type == "hash":
                data = await redis.hgetall(key)
                if data:
                    return {cfg.output_key: data}
            else:
                val = await redis.get(key)
                if val is not None:
                    if cfg.data_type == "json":
                        try:
                            parsed = json.loads(str(val))
                            return parsed if isinstance(parsed, dict) else {cfg.output_key: parsed}
                        except Exception:
                            return {cfg.output_key: str(val)}
                    return {cfg.output_key: str(val)}
        except Exception as e:
            logger.warning("RedisStateResolver error", key=key, error=str(e))

        return dict(cfg.fallback_response)
