from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from core.registry.interfaces import BaseContextResolver
from core.schemas.events import EvaluationRequest


class StaticLookupResolverConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    enabled: bool = True
    lookup_field: str = "action.parameters.target_ip"
    lookup_table: dict[str, Any] = Field(default_factory=dict)
    output_key: str = "resolved_asset"
    fallback_response: dict[str, Any] = Field(default_factory=dict)


class StaticLookupResolver(BaseContextResolver):
    name = "static_lookup_resolver"
    version = "1.0.0"
    config_schema = StaticLookupResolverConfig

    def _extract_field_value(self, path: str, request: EvaluationRequest) -> Any:
        parts = path.split(".")
        current: Any = request
        for p in parts:
            if isinstance(current, dict):
                current = current.get(p)
            elif hasattr(current, p):
                current = getattr(current, p)
            else:
                return None
            if current is None:
                return None
        return current

    async def resolve(
        self,
        request: EvaluationRequest,
        config: BaseModel,
    ) -> dict[str, Any]:
        cfg = config if isinstance(config, StaticLookupResolverConfig) else StaticLookupResolverConfig(**config.model_dump())
        if not cfg.enabled or not cfg.lookup_table:
            return dict(cfg.fallback_response)

        val = self._extract_field_value(cfg.lookup_field, request)
        if val is None:
            return dict(cfg.fallback_response)

        lookup_key = str(val)
        matched = cfg.lookup_table.get(lookup_key)

        if matched is not None:
            if isinstance(matched, dict):
                return matched
            return {cfg.output_key: matched}

        return dict(cfg.fallback_response)

