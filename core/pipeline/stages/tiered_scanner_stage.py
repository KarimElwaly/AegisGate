import asyncio
from typing import Any

from pydantic import BaseModel

from core.config import get_settings
from core.logger import get_logger
from core.pipeline.stages.stage_context import PipelineStageContext
from core.registry.interfaces import BaseScanner, DefaultPluginConfig, ScannerResult
from core.registry.registry import PluginRegistry
from core.schemas.events import EvaluationRequest
from core.schemas.verdicts import ScannerFinding

logger = get_logger("core.pipeline.stages.tiered_scanner")


class TieredScannerStage:
    """Stage 5: Parallel tiered scanning across Tier 1 (deterministic), Tier 2 (ML), Tier 3 (Judge)."""

    def __init__(self, registry: PluginRegistry) -> None:
        self.registry = registry
        self._parsed_config_cache: dict[str, Any] = {}

    def get_typed_config(
        self, scanner: BaseScanner, raw_config: dict[str, Any], pack_id: str, pack_version: str
    ) -> Any:
        cache_key = f"{pack_id}:{pack_version}:{scanner.name}"
        cached = self._parsed_config_cache.get(cache_key)
        if cached is not None:
            return cached

        schema_cls = scanner.config_schema
        if schema_cls is BaseModel:
            schema_cls = DefaultPluginConfig

        try:
            typed = schema_cls(**raw_config)
        except Exception:
            typed = DefaultPluginConfig(**raw_config)

        self._parsed_config_cache[cache_key] = typed
        return typed

    async def execute_scanner(
        self,
        scanner: BaseScanner,
        request: EvaluationRequest,
        context: dict[str, Any],
        typed_config: Any,
        timeout_ms: int,
        on_timeout: str,
    ) -> ScannerResult:
        timeout_sec = max(0.01, timeout_ms / 1000.0)
        try:
            return await asyncio.wait_for(
                scanner.scan(request, context, typed_config),
                timeout=timeout_sec,
            )
        except TimeoutError:
            logger.warning("Scanner timed out", scanner=scanner.name, timeout_ms=timeout_ms)
            status = "block" if on_timeout == "deny" else "flag" if on_timeout == "flag" else "pass"
            return ScannerResult(
                scanner_name=scanner.name,
                tier=scanner.tier,
                status=status,
                score=0.5 if status != "pass" else 0.0,
                details={"error": "timeout", "timeout_ms": timeout_ms},
                message=f"Scanner {scanner.name} timed out after {timeout_ms}ms",
            )
        except Exception as exc:
            logger.error("Scanner execution exception", scanner=scanner.name, error=str(exc))
            status = "block" if on_timeout == "deny" else "error"
            return ScannerResult(
                scanner_name=scanner.name,
                tier=scanner.tier,
                status=status,
                score=0.5 if status == "error" else 1.0,
                details={"exception": str(exc)},
                message=f"Scanner {scanner.name} failed with error: {exc!s}",
            )

    async def execute(self, ctx: PipelineStageContext) -> None:
        req = ctx.request
        pack = ctx.policy_pack
        stage_str = req.stage.value if hasattr(req.stage, "value") else str(req.stage)
        available_scanners = self.registry.get_scanners_for_stage(stage_str)
        pack_scanner_map = {s.name: s for s in pack.scanners}

        tier_scanners: dict[int, list[BaseScanner]] = {1: [], 2: [], 3: []}
        for s in available_scanners:
            if pack.scanners:
                cfg = pack_scanner_map.get(s.name)
                if not cfg or not cfg.enabled:
                    continue
            else:
                if s.name == "webhook_scanner":
                    continue
            tier_scanners.setdefault(s.tier, []).append(s)

        ctx.scanner_findings = []
        ctx.mutated_content_map = {}
        ctx.mutated_parameters_map = {}
        ctx.redaction_map = {}
        short_circuit = False

        for tier in (1, 2, 3):
            scanners = tier_scanners.get(tier, [])
            if not scanners or short_circuit:
                continue

            tasks = []
            for s in scanners:
                cfg_item = pack_scanner_map.get(s.name)
                raw_cfg = cfg_item.config if cfg_item else {}
                timeout_ms = cfg_item.timeout_ms if cfg_item else get_settings().DEFAULT_SCANNER_TIMEOUT_MS
                on_timeout = cfg_item.on_timeout if cfg_item else "flag"
                typed_cfg = self.get_typed_config(s, raw_cfg, pack.id, pack.version)

                tasks.append(
                    self.execute_scanner(
                        scanner=s,
                        request=req,
                        context=ctx.resolved_context,
                        typed_config=typed_cfg,
                        timeout_ms=timeout_ms,
                        on_timeout=on_timeout,
                    )
                )

            tier_results: list[ScannerResult] = await asyncio.gather(*tasks)

            for res in tier_results:
                finding = ScannerFinding(
                    scanner_name=res.scanner_name,
                    tier=res.tier,
                    status=res.status,
                    score=res.score,
                    details=res.details,
                    message=res.message,
                )
                ctx.scanner_findings.append(finding)

                if res.mutated_content and isinstance(res.mutated_content, dict):
                    ctx.mutated_content_map.update(res.mutated_content)
                if res.mutated_parameters and isinstance(res.mutated_parameters, dict):
                    ctx.mutated_parameters_map.update(res.mutated_parameters)
                if res.redaction_map and isinstance(res.redaction_map, dict):
                    ctx.redaction_map.update(res.redaction_map)

                if tier == 1 and res.status == "block":
                    short_circuit = True
                    ctx.short_circuit = True
