import asyncio
import time
from typing import Any, Dict, List, Optional
from pydantic import BaseModel
from core.config import get_settings
from core.logger import get_logger
from core.policy_engine.yaml_engine import get_yaml_policy_engine
from core.registry.interfaces import BaseScanner, DefaultPluginConfig, ScannerResult
from core.registry.registry import PluginRegistry, get_plugin_registry
from core.schemas.common import DecisionEnum, EffectiveModeEnum
from core.schemas.events import EvaluationRequest
from core.schemas.policy import PolicyPackDefinition
from core.schemas.verdicts import (
    ApprovalTicketInfo,
    BudgetSnapshot,
    EvaluationVerdict,
    ScannerFinding,
    TriggeredRule,
)

logger = get_logger("core.pipeline")


class PipelineOrchestrator:
    """Tiered Pipeline Orchestrator.
    Executes parallel scanner tiers, enforces timeouts, short-circuits on critical blocks,
    and coordinates policy engine evaluation without hardcoding domain logic.
    """

    def __init__(
        self,
        plugin_registry: Optional[PluginRegistry] = None,
        policy_engine=None,
    ) -> None:
        self.registry = plugin_registry or get_plugin_registry()
        self.policy_engine = policy_engine or get_yaml_policy_engine()
        self._parsed_config_cache: Dict[str, Any] = {}

    def _get_typed_config(self, scanner: BaseScanner, raw_config: Dict[str, Any], pack_id: str, pack_version: str) -> Any:
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

    async def _execute_scanner(
        self,
        scanner: BaseScanner,
        request: EvaluationRequest,
        context: Dict[str, Any],
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
        except asyncio.TimeoutError:
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
                message=f"Scanner {scanner.name} failed with error: {str(exc)}",
            )

    async def evaluate(self, request: EvaluationRequest) -> EvaluationVerdict:
        start_time = time.perf_counter()

        # 1. Resolve Policy Pack
        policy_pack = self.policy_engine.get_policy_pack(request.policy_pack_id)
        if not policy_pack:
            # Fallback to minimal default pack
            policy_pack = PolicyPackDefinition(
                id=request.policy_pack_id or "default",
                name="Default Dynamic Pack",
                version="1.0.0",
                execution_mode="enforce",
            )

        # 2. Determine effective mode
        if request.execution_mode_override:
            effective_mode = EffectiveModeEnum(request.execution_mode_override)
        elif policy_pack.execution_mode == "shadow":
            effective_mode = EffectiveModeEnum.SHADOW
        else:
            effective_mode = EffectiveModeEnum.ENFORCE

        # 3. Resolve context
        resolved_context: Dict[str, Any] = {}
        for resolver_binding in policy_pack.resolvers:
            if not resolver_binding.enabled:
                continue
            resolver = self.registry.get_resolver(resolver_binding.name)
            if resolver:
                try:
                    cfg_cls = resolver.config_schema
                    if cfg_cls is BaseModel:
                        cfg_cls = DefaultPluginConfig
                    cfg = cfg_cls(**resolver_binding.config)
                    ctx_res = await asyncio.wait_for(
                        resolver.resolve(request, cfg),
                        timeout=max(0.01, resolver_binding.timeout_ms / 1000.0),
                    )
                    if isinstance(ctx_res, dict):
                        resolved_context.update(ctx_res)
                except Exception as e:
                    logger.warning("Context resolver failed", name=resolver.name, error=str(e))

        # 4. Filter and prepare scanners by tier
        stage_str = request.stage.value if hasattr(request.stage, "value") else str(request.stage)
        available_scanners = self.registry.get_scanners_for_stage(stage_str)

        pack_scanner_map = {s.name: s for s in policy_pack.scanners}

        tier_scanners: Dict[int, List[BaseScanner]] = {1: [], 2: [], 3: []}
        for s in available_scanners:
            if policy_pack.scanners:
                cfg = pack_scanner_map.get(s.name)
                if not cfg or not cfg.enabled:
                    continue
            else:
                if s.name == "webhook_scanner":
                    continue
            tier_scanners.setdefault(s.tier, []).append(s)

        all_findings: List[ScannerFinding] = []
        mutated_content_map: Dict[str, Any] = {}
        mutated_parameters_map: Dict[str, Any] = {}
        redaction_map: Dict[str, str] = {}
        short_circuit = False

        # Execute tiers sequentially (Tier 1 -> Tier 2 -> Tier 3)
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
                typed_cfg = self._get_typed_config(s, raw_cfg, policy_pack.id, policy_pack.version)

                tasks.append(
                    self._execute_scanner(
                        scanner=s,
                        request=request,
                        context=resolved_context,
                        typed_config=typed_cfg,
                        timeout_ms=timeout_ms,
                        on_timeout=on_timeout,
                    )
                )

            tier_results: List[ScannerResult] = await asyncio.gather(*tasks)

            for res in tier_results:
                finding = ScannerFinding(
                    scanner_name=res.scanner_name,
                    tier=res.tier,
                    status=res.status,
                    score=res.score,
                    details=res.details,
                    message=res.message,
                )
                all_findings.append(finding)

                if res.mutated_content and isinstance(res.mutated_content, dict):
                    mutated_content_map.update(res.mutated_content)
                if res.mutated_parameters and isinstance(res.mutated_parameters, dict):
                    mutated_parameters_map.update(res.mutated_parameters)
                if res.redaction_map and isinstance(res.redaction_map, dict):
                    redaction_map.update(res.redaction_map)

                # Check Tier-1 Critical Short Circuit
                if tier == 1 and res.status == "block":
                    short_circuit = True

        # 5. Evaluate YAML Policy Rules
        rule_decision, risk_score, triggered_rules, rule_mutations = await self.policy_engine.evaluate(
            request=request,
            scanner_findings=all_findings,
            resolved_context=resolved_context,
            policy_pack=policy_pack,
        )

        if "mutated_content" in rule_mutations:
            mutated_content_map.update(rule_mutations["mutated_content"])
        if "mutated_parameters" in rule_mutations:
            mutated_parameters_map.update(rule_mutations["mutated_parameters"])

        # 6. Determine final decision
        has_scanner_block = any(f.status == "block" for f in all_findings)
        if has_scanner_block and rule_decision == DecisionEnum.ALLOW:
            nominal_decision = DecisionEnum.DENY
            if risk_score < 0.8:
                risk_score = 0.9
        else:
            nominal_decision = rule_decision

        # Apply mutations if MODIFY was selected
        if (mutated_content_map or mutated_parameters_map) and nominal_decision == DecisionEnum.ALLOW:
            nominal_decision = DecisionEnum.MODIFY

        # 7. Apply Shadow Mode semantics
        if effective_mode == EffectiveModeEnum.SHADOW:
            effective_decision = DecisionEnum.ALLOW
            would_have_decided = nominal_decision
        else:
            effective_decision = nominal_decision
            would_have_decided = nominal_decision

        # 8. Check for HITL ticket config if SUSPEND_FOR_APPROVAL
        approval_ticket: Optional[ApprovalTicketInfo] = None
        if nominal_decision == DecisionEnum.SUSPEND_FOR_APPROVAL:
            approval_cfg = rule_mutations.get("approval_config", {})
            approval_ticket = ApprovalTicketInfo(
                ticket_id=None,
                status="pending",
                required_approvals=approval_cfg.get("required_approvals", 1),
            )

        latency_ms = (time.perf_counter() - start_time) * 1000.0

        return EvaluationVerdict(
            decision=effective_decision,
            effective_mode=effective_mode,
            would_have_decided=would_have_decided,
            risk_score=risk_score,
            mutated_content=mutated_content_map if mutated_content_map else None,
            mutated_parameters=mutated_parameters_map if mutated_parameters_map else None,
            redaction_map_ref=request.session_id if redaction_map else None,
            triggered_rules=triggered_rules,
            scanner_findings=all_findings,
            resolved_context=resolved_context,
            budget_snapshot=BudgetSnapshot(),
            approval_ticket=approval_ticket,
            latency_ms=round(latency_ms, 2),
        )


default_orchestrator = PipelineOrchestrator()


def get_pipeline_orchestrator() -> PipelineOrchestrator:
    return default_orchestrator
