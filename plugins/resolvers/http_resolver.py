import hashlib
import json
import re
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field, model_validator

from core.logger import get_logger
from core.redis_client import get_redis_client
from core.registry.interfaces import BaseContextResolver
from core.schemas.events import EvaluationRequest
from core.security.ssrf import SSRFProtectionError, validate_outbound_url

logger = get_logger("plugins.resolvers.http")


class HTTPContextResolverConfig(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    enabled: bool = True
    url_template: str = Field(default="http://localhost:8080/api/assets/{target_ip}", alias="url")
    method: str = "GET"
    headers: dict[str, str] = Field(default_factory=dict)
    timeout_ms: int = 300
    cache_ttl_seconds: int = 300
    fallback_response: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def resolve_url_field(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "url" in data and "url_template" not in data:
                data["url_template"] = data["url"]
        return data


class HTTPContextResolver(BaseContextResolver):
    name = "http_context_resolver"
    version = "1.0.0"
    config_schema = HTTPContextResolverConfig

    def _format_template(self, template: str, request: EvaluationRequest) -> str:
        # Build comprehensive variable context including nested and flat variables
        params = request.action.parameters or {}
        full_context: dict[str, Any] = {
            "tenant_id": request.tenant_id,
            "session_id": request.session_id or "global",
            "actor": request.actor.model_dump(),
            "actor_id": request.actor.id,
            "actor_role": request.actor.role,
            "action": request.action.model_dump(),
            "action_name": request.action.name,
            "content": request.content.model_dump(),
            "metadata": request.metadata or {},
            **params,
        }

        def _get_nested(root: Any, path: str) -> Any:
            parts = path.split(".")
            curr = root
            for p in parts:
                if isinstance(curr, dict):
                    curr = curr.get(p)
                elif hasattr(curr, p):
                    curr = getattr(curr, p)
                else:
                    return None
            return curr

        def repl(match):
            key = match.group(1)
            val = _get_nested(full_context, key)
            if val is not None:
                return str(val)
            if key in full_context:
                return str(full_context[key])
            return ""

        return re.sub(r"\{([a-zA-Z0-9_\.]+)\}", repl, template)

    async def resolve(
        self,
        request: EvaluationRequest,
        config: BaseModel,
    ) -> dict[str, Any]:
        cfg = config if isinstance(config, HTTPContextResolverConfig) else HTTPContextResolverConfig(**config.model_dump())
        if not cfg.enabled:
            return {}

        url = self._format_template(cfg.url_template, request)

        # SSRF validation
        try:
            await validate_outbound_url(url, target_type="http_resolver")
        except SSRFProtectionError as e:
            logger.warning("http_resolver_ssrf_blocked", url=url, error=str(e))
            return cfg.fallback_response

        cache_key = f"aegisgate:ctx:http:{hashlib.sha256(url.encode()).hexdigest()[:16]}"

        # 1. Check Redis cache
        try:
            redis = await get_redis_client()
            cached = await redis.get(cache_key)
            if cached:
                return json.loads(str(cached))
        except Exception:
            pass

        # 2. HTTP Request with timeout
        timeout_sec = max(0.02, cfg.timeout_ms / 1000.0)
        try:
            async with httpx.AsyncClient(timeout=timeout_sec) as client:
                if cfg.method.upper() == "GET":
                    resp = await client.get(url, headers=cfg.headers)
                else:
                    resp = await client.post(url, headers=cfg.headers, json={"request_id": request.request_id})

                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, dict):
                        # Cache in Redis
                        try:
                            redis = await get_redis_client()
                            await redis.setex(cache_key, cfg.cache_ttl_seconds, json.dumps(data))
                        except Exception:
                            pass
                        return data
        except Exception as exc:
            logger.warning(
                "HTTPContextResolver call failed or timed out, returning fallback",
                url=url,
                error=str(exc),
            )

        return dict(cfg.fallback_response)

