from abc import ABC, abstractmethod
from typing import Any, Dict, List, Tuple
from core.schemas.common import DecisionEnum
from core.schemas.events import EvaluationRequest
from core.schemas.policy import PolicyPackDefinition
from core.schemas.verdicts import ScannerFinding, TriggeredRule


class PolicyEngineInterface(ABC):
    """Interface for Policy Evaluation engines (YAML DSL, OPA/Rego, etc.)."""

    @abstractmethod
    async def evaluate(
        self,
        request: EvaluationRequest,
        scanner_findings: List[ScannerFinding],
        resolved_context: Dict[str, Any],
        policy_pack: PolicyPackDefinition,
    ) -> Tuple[DecisionEnum, float, List[TriggeredRule], Dict[str, Any]]:
        """Evaluates rules against request, findings, and context.
        Returns:
            - decision: ALLOW | DENY | MODIFY | SUSPEND_FOR_APPROVAL | ESCALATE
            - risk_score: float (0.0 to 1.0)
            - triggered_rules: list of TriggeredRule
            - rule_mutations: dict containing optional mutated_content / mutated_parameters
        """
        pass
