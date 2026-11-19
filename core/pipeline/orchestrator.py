import asyncio
import time
from typing import Any, Dict, List, Optional
from pydantic import BaseModel
from core.config import get_settings
from core.governance.budgets import get_budget_manager
from core.governance.delegation import DelegationPolicyConfig, get_delegation_validator
from core.governance.kill_switch import get_kill_switch_service
from core.governance.loop_detector import get_loop_detector
from core.logger import get_logger
from core.policy_engine.yaml_engine import get_yaml_policy_engine
from core.registry.interfaces import BaseScanner, DefaultPluginConfig, ScannerResult
from core.registry.registry import PluginRegistry, get_plugin_registry
from core.schemas.common import DecisionEnum, EffectiveModeEnum, SeverityEnum
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
    Integrates sub-millisecond kill switches, delegation chain validation,
    atomic Redis Lua budgets, sliding-window loop detection, parallel scanner tiers,
    and policy evaluation without hardcoding domain logic.
    """

    def __init__(
        self,
        plugin_registry: Optional[PluginRegistry] = None,
        policy_engine=None,
    ) -> None:
        self.registry = plugin_registry or get_plugin_registry()
        self.policy_engine = policy_engine or get_yaml_policy_engine()
        self.kill_switch = get_kill_switch_service()
        self.budget_manager = get_budget_manager()
        self.loop_detector = get_loop_detector()
        self.delegation_validator = get_delegation_validator()
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

        # -------------------------------------------------------------
        # 1. SUB-MILLISECOND KILL SWITCH CHECK (CHECKED FIRST)
        # -------------------------------------------------------------
        is_killed, kill_scope, kill_reason = await self.kill_switch.check_kill_switches(
            tenant_id=request.tenant_id,
            workspace_id=request.workspace_id,
            agent_id=request.actor.id,
            tool_name=request.action.name if request.action else None,
        )
        if is_killed:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            return EvaluationVerdict(
                decision=DecisionEnum.DENY,
                effective_mode=EffectiveModeEnum.ENFORCE,
                would_have_decided=DecisionEnum.DENY,
                risk_score=1.0,
                triggered_rules=[
                    TriggeredRule(
                        rule_id="kill-switch-engaged",
                        policy_pack="governance-kill-switch",
                        policy_version="1.0.0",
                        severity=SeverityEnum.CRITICAL,
                        reason=f"Emergency Kill Switch active on scope '{kill_scope}': {kill_reason}",
                        compliance_tags=["CIRCUIT-BREAKER", "EMERGENCY-HALT"],
                    )
                ],
                latency_ms=round(latency_ms, 2),
            )

        # -------------------------------------------------------------
        # 2. RESOLVE POLICY PACK & EFFECTIVE MODE
        # -------------------------------------------------------------
        policy_pack = self.policy_engine.get_policy_pack(request.policy_pack_id)
        if not policy_pack:
            policy_pack = PolicyPackDefinition(
                id=request.policy_pack_id or "default",
                name="Default Dynamic Pack",
                version="1.0.0",
                execution_mode="enforce",
            )

        if request.execution_mode_override:
            effective_mode = EffectiveModeEnum(request.execution_mode_override)
        elif policy_pack.execution_mode == "shadow":
            effective_mode = EffectiveModeEnum.SHADOW
        else:
            effective_mode = EffectiveModeEnum.ENFORCE

        # -------------------------------------------------------------
        # 3. DELEGATION CHAIN & PRIVILEGE ESCALATION CHECK
        # -------------------------------------------------------------
        delegation_cfg_dict = policy_pack.budgets.get("delegation", {}) if policy_pack.budgets else {}
        delegation_cfg = DelegationPolicyConfig(**delegation_cfg_dict)
        is_delegation_valid, delegation_reason = self.delegation_validator.validate_delegation(
            actor=request.actor,
            action_name=request.action.name if request.action else "default_action",
            config=delegation_cfg,
        )
        if not is_delegation_valid:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            return EvaluationVerdict(
                decision=DecisionEnum.DENY if effective_mode == EffectiveModeEnum.ENFORCE else DecisionEnum.ALLOW,
                effective_mode=effective_mode,
                would_have_decided=DecisionEnum.DENY,
                risk_score=0.9,
                triggered_rules=[
                    TriggeredRule(
                        rule_id="delegation-privilege-escalation",
                        policy_pack=policy_pack.id,
                        policy_version=policy_pack.version,
                        severity=SeverityEnum.HIGH,
                        reason=delegation_reason or "Delegation validation failed",
                        compliance_tags=["RBAC", "PRIVILEGE-ESCALATION"],
                    )
                ],
                latency_ms=round(latency_ms, 2),
            )

        # -------------------------------------------------------------
        # 4. SLIDING-WINDOW RUNAWAY LOOP DETECTOR
        # -------------------------------------------------------------
        if request.stage in ("tool_pre_call", "agent_handoff"):
            loop_cfg = policy_pack.budgets.get("loop_detector", {}) if policy_pack.budgets else {}
            loop_threshold = loop_cfg.get("threshold", 3)
            loop_window = loop_cfg.get("window_seconds", 60)
            is_loop, loop_count, call_hash = await self.loop_detector.record_and_check(
                tenant_id=request.tenant_id,
                session_id=request.session_id or "global",
                actor_id=request.actor.id,
                action_name=request.action.name if request.action else "default_action",
                parameters=request.action.parameters or {},
                threshold=loop_threshold,
                window_seconds=loop_window,
            )
            if is_loop:
                latency_ms = (time.perf_counter() - start_time) * 1000.0
                return EvaluationVerdict(
                    decision=DecisionEnum.DENY if effective_mode == EffectiveModeEnum.ENFORCE else DecisionEnum.ALLOW,
                    effective_mode=effective_mode,
                    would_have_decided=DecisionEnum.DENY,
                    risk_score=0.9,
                    triggered_rules=[
                        TriggeredRule(
                            rule_id="runaway-loop-circuit-breaker",
                            policy_pack=policy_pack.id,
                            policy_version=policy_pack.version,
                            severity=SeverityEnum.HIGH,
                            reason=f"Runaway loop detected: action '{request.action.name}' called {loop_count} times in {loop_window}s",
                            compliance_tags=["LOOP-PREVENTION", "RESOURCE-EXHAUSTION"],
                        )
                    ],
                    latency_ms=round(latency_ms, 2),
                )

        # -------------------------------------------------------------
        # 5. ATOMIC BUDGET & QUOTA CHECK
        # -------------------------------------------------------------
        budget_snapshot = BudgetSnapshot()
        if policy_pack.budgets:
            budget_limits = policy_pack.budgets
            scope_type = "session" if request.session_id else "tenant"
            scope_id = request.session_id or request.tenant_id
            delta_tokens = request.action.estimated_tokens if request.action else 0
            delta_cost = request.action.estimated_cost_usd if request.action else 0.0
            delta_tool_calls = 1 if request.stage == "tool_pre_call" else 0

            is_budget_ok, budget_status, budget_snapshot = await self.budget_manager.check_and_consume(
                tenant_id=request.tenant_id,
                scope_type=scope_type,
                scope_id=scope_id,
                delta_tokens=delta_tokens,
                delta_cost_usd=delta_cost,
                delta_tool_calls=delta_tool_calls,
                max_tokens=budget_limits.get("max_tokens", 0),
                max_cost_usd=budget_limits.get("max_cost_usd", 0.0),
                max_tool_calls=budget_limits.get("max_tool_calls", 0),
                max_consecutive_failures=budget_limits.get("max_consecutive_failures", 0),
            )
            if not is_budget_ok:
                latency_ms = (time.perf_counter() - start_time) * 1000.0
                return EvaluationVerdict(
                    decision=DecisionEnum.DENY if effective_mode == EffectiveModeEnum.ENFORCE else DecisionEnum.ALLOW,
                    effective_mode=effective_mode,
                    would_have_decided=DecisionEnum.DENY,
                    risk_score=0.8,
                    budget_snapshot=budget_snapshot,
                    triggered_rules=[
                        TriggeredRule(
                            rule_id="budget-quota-exceeded",
                            policy_pack=policy_pack.id,
                            policy_version=policy_pack.version,
                            severity=SeverityEnum.HIGH,
                            reason=f"Budget quota limit reached: {budget_status}",
                            compliance_tags=["BUDGET-ENFORCEMENT", "COST-CONTROL"],
                        )
                    ],
                    latency_ms=round(latency_ms, 2),
                )

        # -------------------------------------------------------------
        # 6. CONTEXT RESOLVERS ENRICHMENT
        # -------------------------------------------------------------
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

        # -------------------------------------------------------------
        # 7. TIERED SCANNERS EXECUTION
        # -------------------------------------------------------------
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

                if tier == 1 and res.status == "block":
                    short_circuit = True

        # -------------------------------------------------------------
        # 8. POLICY RULES EVALUATION
        # -------------------------------------------------------------
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

        has_scanner_block = any(f.status == "block" for f in all_findings)
        if has_scanner_block and rule_decision == DecisionEnum.ALLOW:
            nominal_decision = DecisionEnum.DENY
            if risk_score < 0.8:
                risk_score = 0.9
        else:
            nominal_decision = rule_decision

        if (mutated_content_map or mutated_parameters_map) and nominal_decision == DecisionEnum.ALLOW:
            nominal_decision = DecisionEnum.MODIFY

        if effective_mode == EffectiveModeEnum.SHADOW:
            effective_decision = DecisionEnum.ALLOW
            would_have_decided = nominal_decision
        else:
            effective_decision = nominal_decision
            would_have_decided = nominal_decision

        approval_ticket: Optional[ApprovalTicketInfo] = None
        if nominal_decision == DecisionEnum.SUSPEND_FOR_APPROVAL:
            approval_cfg = rule_mutations.get("approval_config", {})
            try:
                from core.hitl.engine import get_hitl_engine
                hitl_eng = get_hitl_engine()
                pack_name = getattr(policy_pack, "id", getattr(policy_pack, "name", "default")) if policy_pack else "default"
                created_ticket = await hitl_eng.create_ticket(
                    request=request,
                    verdict=EvaluationVerdict(
                        decision=effective_decision,
                        effective_mode=effective_mode,
                        would_have_decided=would_have_decided,
                        risk_score=risk_score,
                        triggered_rules=triggered_rules,
                        scanner_findings=all_findings,
                        resolved_context=resolved_context,
                        latency_ms=0.0,
                    ),
                    policy_pack_id=pack_name,
                    required_approvals=approval_cfg.get("required_approvals", 1),
                    required_approver_roles=approval_cfg.get("required_approver_roles"),
                    ttl_seconds=approval_cfg.get("ttl_seconds", 300),
                    callback_url=approval_cfg.get("callback_url"),
                    callback_secret=approval_cfg.get("callback_secret"),
                )
                approval_ticket = ApprovalTicketInfo(
                    ticket_id=created_ticket.ticket_id,
                    status=created_ticket.status,
                    required_approvals=created_ticket.required_approvals,
                    expires_at=created_ticket.expires_at,
                )
            except Exception as e:
                logger.warning("hitl_ticket_creation_failed", error=str(e))
                approval_ticket = ApprovalTicketInfo(
                    ticket_id=None,
                    status="pending",
                    required_approvals=approval_cfg.get("required_approvals", 1),
                )

        latency_ms = (time.perf_counter() - start_time) * 1000.0

        verdict = EvaluationVerdict(
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
            budget_snapshot=budget_snapshot,
            approval_ticket=approval_ticket,
            latency_ms=round(latency_ms, 2),
        )

        # Audit Ledger Recording
        if getattr(request, "record_audit", True):
            try:
                from core.audit.ledger import AuditLedger
                ledger = AuditLedger()
                pack_name = getattr(policy_pack, "id", getattr(policy_pack, "name", "default")) if policy_pack else "default"
                pack_ver = getattr(policy_pack, "version", "1.0.0") if policy_pack else "1.0.0"
                eff_mode_str = effective_mode.value if hasattr(effective_mode, "value") else str(effective_mode)
                would_dec_str = would_have_decided.value if hasattr(would_have_decided, "value") else str(would_have_decided)

                if getattr(request, "record_audit_sync", False):
                    await ledger.record_event(
                        request=request,
                        verdict=verdict,
                        policy_pack_id=pack_name,
                        policy_pack_version=pack_ver,
                        effective_mode=eff_mode_str,
                        would_have_decided=would_dec_str,
                    )
                else:
                    asyncio.create_task(
                        ledger.record_event(
                            request=request,
                            verdict=verdict,
                            policy_pack_id=pack_name,
                            policy_pack_version=pack_ver,
                            effective_mode=eff_mode_str,
                            would_have_decided=would_dec_str,
                        )
                    )
            except Exception as e:
                logger.warning("audit_recording_failed", error=str(e))

        # Live Shadow Mode Evaluation
        shadow_pack_id = getattr(request, "shadow_policy_pack_id", None)
        if shadow_pack_id:
            asyncio.create_task(
                self._evaluate_shadow(request, verdict, shadow_pack_id)
            )

        return verdict

    async def _evaluate_shadow(
        self,
        request: EvaluationRequest,
        active_verdict: EvaluationVerdict,
        shadow_pack_id: str,
    ) -> None:
        """Asynchronously evaluates candidate shadow policy pack and records deltas."""
        try:
            shadow_pack = self.policy_engine.get_registered_pack(shadow_pack_id)
            if not shadow_pack:
                return

            shadow_decision, risk, triggered, _ = await self.policy_engine.evaluate(
                request=request,
                scanner_findings=active_verdict.scanner_findings,
                resolved_context=active_verdict.resolved_context or {},
                policy_pack=shadow_pack,
            )
            shadow_verdict = EvaluationVerdict(
                decision=shadow_decision,
                effective_mode=EffectiveModeEnum.SHADOW,
                risk_score=risk,
                triggered_rules=triggered,
                scanner_findings=active_verdict.scanner_findings,
                resolved_context=active_verdict.resolved_context,
                latency_ms=0.0,
            )

            active_dec = active_verdict.decision.value if hasattr(active_verdict.decision, "value") else str(active_verdict.decision)
            shadow_dec = shadow_decision.value if hasattr(shadow_decision, "value") else str(shadow_decision)

            if active_dec != shadow_dec:
                from core.simulator.shadow import get_shadow_delta_manager
                mgr = get_shadow_delta_manager()
                await mgr.record_delta(
                    tenant_id=request.tenant_id,
                    workspace_id=request.workspace_id,
                    trace_id=request.trace_id,
                    active_pack_id=request.policy_pack_id,
                    active_version="active",
                    shadow_pack_id=shadow_pack_id,
                    shadow_version=getattr(shadow_pack, "version", "1.0.0"),
                    active_verdict=active_verdict,
                    shadow_verdict=shadow_verdict,
                    request_summary={
                        "stage": request.stage.value if hasattr(request.stage, "value") else str(request.stage),
                        "action": request.action.name if hasattr(request.action, "name") else str(request.action),
                    },
                )
        except Exception as e:
            logger.warning("shadow_evaluation_failed", error=str(e))


default_orchestrator = PipelineOrchestrator()


def get_pipeline_orchestrator() -> PipelineOrchestrator:
    return default_orchestrator
