import re
from typing import Any, Dict, List, Optional, Tuple
import yaml
from core.logger import get_logger
from core.policy_engine.interface import PolicyEngineInterface
from core.schemas.common import DecisionEnum, SeverityEnum
from core.schemas.events import EvaluationRequest
from core.schemas.policy import ConditionExpression, PolicyPackDefinition, PolicyRule
from core.schemas.verdicts import ScannerFinding, TriggeredRule

logger = get_logger("core.policy_engine.yaml")


class YamlPolicyEngine(PolicyEngineInterface):
    """Native YAML DSL Policy Engine with boolean logic, inheritance, and hot-reload."""

    def __init__(self) -> None:
        self._policy_packs: Dict[str, PolicyPackDefinition] = {}

    def register_policy_pack(self, pack: PolicyPackDefinition) -> None:
        self._policy_packs[pack.id] = pack
        logger.info("Registered policy pack", pack_id=pack.id, version=pack.version)

    def load_from_yaml_string(self, yaml_content: str) -> PolicyPackDefinition:
        data = yaml.safe_load(yaml_content)
        pack = PolicyPackDefinition(**data)
        self.register_policy_pack(pack)
        return pack

    def get_policy_pack(self, pack_id: str) -> Optional[PolicyPackDefinition]:
        return self._policy_packs.get(pack_id)

    get_registered_pack = get_policy_pack

    def resolve_inheritance(self, pack: PolicyPackDefinition) -> PolicyPackDefinition:
        """Resolves pack inheritance if 'extends' is specified."""
        if not pack.extends:
            return pack

        parent = self._policy_packs.get(pack.extends)
        if not parent:
            logger.warning("Parent policy pack not found for extension", extends=pack.extends)
            return pack

        # Recursively resolve parent's parent if needed
        resolved_parent = self.resolve_inheritance(parent)

        # Merge scanners: child overrides parent scanner by name
        scanner_map = {s.name: s for s in resolved_parent.scanners}
        for s in pack.scanners:
            scanner_map[s.name] = s

        # Merge resolvers
        resolver_map = {r.name: r for r in resolved_parent.resolvers}
        for r in pack.resolvers:
            resolver_map[r.name] = r

        # Merge budgets
        merged_budgets = {**resolved_parent.budgets, **pack.budgets}

        # Merge rules: child rules + parent rules (deduplicated by rule.id)
        rule_map = {r.id: r for r in resolved_parent.rules}
        for r in pack.rules:
            rule_map[r.id] = r

        merged_rules = list(rule_map.values())
        # Sort rules by priority (ascending: lower number = higher precedence)
        merged_rules.sort(key=lambda x: x.priority)

        return PolicyPackDefinition(
            id=pack.id,
            name=pack.name,
            version=pack.version,
            extends=pack.extends,
            execution_mode=pack.execution_mode or resolved_parent.execution_mode,
            description=pack.description or resolved_parent.description,
            scanners=list(scanner_map.values()),
            resolvers=list(resolver_map.values()),
            budgets=merged_budgets,
            rules=merged_rules,
        )

    def _extract_field(self, field_path: str, context_bundle: Dict[str, Any]) -> Any:
        parts = field_path.split(".")
        current = context_bundle
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            elif hasattr(current, part):
                current = getattr(current, part)
            else:
                return None
            if current is None:
                return None
        return current

    def _evaluate_clause(self, clause: ConditionExpression, context_bundle: Dict[str, Any]) -> bool:
        if clause.all is not None:
            return all(self._evaluate_clause(sub, context_bundle) for sub in clause.all)

        if clause.any is not None:
            return any(self._evaluate_clause(sub, context_bundle) for sub in clause.any)

        if clause.not_ is not None:
            return not self._evaluate_clause(clause.not_, context_bundle)

        if not clause.field or not clause.operator:
            return True

        actual_val = self._extract_field(clause.field, context_bundle)
        expected_val = clause.value
        op = clause.operator.lower()

        if op in ("eq", "=="):
            return actual_val == expected_val
        elif op in ("neq", "!="):
            return actual_val != expected_val
        elif op == "in":
            if isinstance(expected_val, (list, tuple, set)):
                return actual_val in expected_val
            if isinstance(actual_val, str) and isinstance(expected_val, str):
                return actual_val in expected_val
            return False
        elif op == "not_in":
            if isinstance(expected_val, (list, tuple, set)):
                return actual_val not in expected_val
            return True
        elif op == "contains":
            if isinstance(actual_val, (list, tuple, set)):
                return expected_val in actual_val
            if isinstance(actual_val, str) and isinstance(expected_val, str):
                return expected_val.lower() in actual_val.lower()
            return False
        elif op == "regex":
            if actual_val is None:
                return False
            return bool(re.search(str(expected_val), str(actual_val)))
        elif op in ("gt", ">"):
            try:
                return float(actual_val) > float(expected_val)
            except (ValueError, TypeError):
                return False
        elif op in ("gte", ">="):
            try:
                return float(actual_val) >= float(expected_val)
            except (ValueError, TypeError):
                return False
        elif op in ("lt", "<"):
            try:
                return float(actual_val) < float(expected_val)
            except (ValueError, TypeError):
                return False
        elif op in ("lte", "<="):
            try:
                return float(actual_val) <= float(expected_val)
            except (ValueError, TypeError):
                return False
        elif op == "exists":
            return actual_val is not None
        elif op == "is_null":
            return actual_val is None

        return False

    async def evaluate(
        self,
        request: EvaluationRequest,
        scanner_findings: List[ScannerFinding],
        resolved_context: Dict[str, Any],
        policy_pack: PolicyPackDefinition,
    ) -> Tuple[DecisionEnum, float, List[TriggeredRule], Dict[str, Any]]:
        resolved_pack = self.resolve_inheritance(policy_pack)

        # Build context bundle for expression evaluation
        findings_map: Dict[str, Any] = {}
        findings_status_map: Dict[str, str] = {}
        for f in scanner_findings:
            dumped = f.model_dump()
            findings_map[f.scanner_name] = dumped
            findings_status_map[f.scanner_name] = f.status
            for pfx in ("tier1_", "tier2_", "tier3_"):
                if f.scanner_name.startswith(pfx):
                    short_name = f.scanner_name[len(pfx):]
                    findings_map[short_name] = dumped
                    findings_status_map[short_name] = f.status

        current_stage = request.stage.value if hasattr(request.stage, "value") else str(request.stage)

        context_bundle = {
            "stage": current_stage,
            "tenant_id": request.tenant_id,
            "workspace_id": request.workspace_id,
            "environment": request.environment,
            "actor": request.actor.model_dump(),
            "action": request.action.model_dump(),
            "content": request.content.model_dump(),
            "metadata": request.metadata,
            "resolved_context": resolved_context,
            "scanner_findings": findings_map,
            "scanner_status": findings_status_map,
        }

        triggered_rules: List[TriggeredRule] = []
        rule_mutations: Dict[str, Any] = {}
        highest_decision: DecisionEnum = DecisionEnum.ALLOW
        max_risk: float = 0.0

        decision_priority = {
            DecisionEnum.ALLOW: 0,
            DecisionEnum.MODIFY: 1,
            DecisionEnum.SUSPEND_FOR_APPROVAL: 2,
            DecisionEnum.ESCALATE: 3,
            DecisionEnum.DENY: 4,
        }

        severity_risk = {
            SeverityEnum.LOW: 0.2,
            SeverityEnum.MEDIUM: 0.5,
            SeverityEnum.HIGH: 0.8,
            SeverityEnum.CRITICAL: 1.0,
        }

        for rule in resolved_pack.rules:
            # Check stage filter
            if rule.stages and current_stage not in rule.stages:
                continue

            # Evaluate condition
            matched = True
            if rule.condition:
                matched = self._evaluate_clause(rule.condition, context_bundle)

            if matched:
                act = rule.action
                rule_decision = DecisionEnum(act.decision) if isinstance(act.decision, str) else act.decision
                rule_severity = SeverityEnum(act.severity) if isinstance(act.severity, str) else act.severity
                risk = severity_risk.get(rule_severity, 0.5)

                if risk > max_risk:
                    max_risk = risk

                triggered_rules.append(
                    TriggeredRule(
                        rule_id=rule.id,
                        policy_pack=resolved_pack.id,
                        policy_version=resolved_pack.version,
                        severity=rule_severity,
                        reason=act.reason,
                        compliance_tags=act.compliance_tags,
                    )
                )

                if act.mutated_content:
                    rule_mutations["mutated_content"] = act.mutated_content
                if act.mutated_parameters:
                    rule_mutations["mutated_parameters"] = act.mutated_parameters
                if act.approval_config:
                    rule_mutations["approval_config"] = act.approval_config

                # Update highest decision
                if decision_priority.get(rule_decision, 0) > decision_priority.get(highest_decision, 0):
                    highest_decision = rule_decision

                # If Critical DENY, short-circuit immediately
                if rule_decision == DecisionEnum.DENY and rule_severity == SeverityEnum.CRITICAL:
                    break

        return highest_decision, max_risk, triggered_rules, rule_mutations


default_yaml_engine = YamlPolicyEngine()


def get_yaml_policy_engine() -> YamlPolicyEngine:
    return default_yaml_engine
