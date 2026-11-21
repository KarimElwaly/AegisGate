import asyncio
from typing import Any

from pydantic import BaseModel

from core.logger import get_logger
from core.pipeline.stages.stage_context import PipelineStageContext
from core.registry.interfaces import DefaultPluginConfig
from core.registry.registry import PluginRegistry

logger = get_logger("core.pipeline.stages.context_resolution")


class ContextResolutionStage:
    """Stage 4: Dynamic context enrichment from external systems and cache."""

    def __init__(self, registry: PluginRegistry) -> None:
        self.registry = registry

    async def execute(self, ctx: PipelineStageContext) -> None:
        req = ctx.request
        pack = ctx.policy_pack
        resolved: dict[str, Any] = {}

        for resolver_binding in pack.resolvers:
            if not resolver_binding.enabled:
                continue
            resolver = self.registry.get_resolver(resolver_binding.name)
            if not resolver:
                continue

            try:
                cfg_cls = resolver.config_schema
                if cfg_cls is BaseModel:
                    cfg_cls = DefaultPluginConfig
                cfg = cfg_cls(**resolver_binding.config)
                timeout_sec = max(0.01, resolver_binding.timeout_ms / 1000.0)
                ctx_res = await asyncio.wait_for(
                    resolver.resolve(req, cfg),
                    timeout=timeout_sec,
                )
                if isinstance(ctx_res, dict):
                    resolved.update(ctx_res)
            except Exception as e:
                logger.warning("Context resolver failed", name=resolver.name, error=str(e))

        ctx.resolved_context = resolved

