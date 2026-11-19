from typing import Any, Dict, List, Optional, Tuple
import httpx
from pydantic import BaseModel, ConfigDict
from core.logger import get_logger
from core.policy_engine.interface import PolicyEngineInterface
from core.schemas.common import DecisionEnum, SeverityEnum
from core.schemas.events import EvaluationRequest
from core.schemas.policy import PolicyPackDefinition
from core.schemas.verdicts import ScannerFinding, TriggeredRule

logger = get_logger("core.policy_engine.opa")


class OPAEngineConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    opa_url: str = "http://localhost:8181"
    policy_path: str = "v1/data/aegisgate/authz"
    timeout_ms: int = 500
    fail_open: bool = False


class OPAPolicyEngine(PolicyEngineInterface):
    """Enterprise OPA/Rego HTTP Policy Evaluation Adapter."""

    def __init__(self, config: Optional[OPAEngineConfig] = None) -> None:
        self.config = config or OPAEngineConfig()

    async def evaluate(
        self,
        request: EvaluationRequest,
        scanner_findings: List[ScannerFinding],
        resolved_context: Dict[str, Any],
        policy_pack: PolicyPackDefinition,
    ) -> Tuple[DecisionEnum, float, List[TriggeredRule], Dict[str, Any]]:
        url = f"{self.config.opa_url.rstrip('/')}/{self.config.policy_path.lstrip('/')}"
        timeout_sec = max(0.02, self.config.timeout_ms / 1000.0)

        input_payload = {
            "input": {
                "request": request.model_dump(),
                "scanner_findings": [f.model_dump() for f in scanner_findings],
                "resolved_context": resolved_context,
                "policy_pack_id": policy_pack.id,
                "policy_pack_version": policy_pack.version,
            }
        }

        try:
            async with httpx.AsyncClient(timeout=timeout_sec) as client:
                resp = await client.post(url, json=input_payload)
                if resp.status_code == 200:
                    data = resp.json().get("result", {})
                    # OPA result format
                    decision_str = data.get("decision", "ALLOW" if data.get("allow", True) else "DENY")
                    decision = DecisionEnum(decision_str)
                    risk_score = float(data.get("risk_score", 0.0))
                    raw_rules = data.get("triggered_rules", [])

                    triggered: List[TriggeredRule] = []
                    for r in raw_rules:
                        triggered.append(
                            TriggeredRule(
                                rule_id=r.get("rule_id", "opa-rule"),
                                policy_pack="opa-rego",
                                policy_version="1.0.0",
                                severity=r.get("severity", "high"),
                                reason=r.get("reason", "OPA rule violation"),
                                compliance_tags=r.get("compliance_tags", ["OPA-REGO"]),
                            )
                        )

                    mutations = data.get("mutations", {})
                    return decision, risk_score, triggered, mutations
                else:
                    logger.error("OPA returned non-200", status_code=resp.status_code)
        except Exception as exc:
            logger.warning("OPA request failed or timed out", url=url, error=str(exc))

        # Fallback behavior when OPA unreachable
        if self.config.fail_open:
            logger.warning("OPA unreachable, failing open per configuration")
            return DecisionEnum.ALLOW, 0.0, [], {}
        else:
            logger.error("OPA unreachable, failing closed per configuration")
            triggered = [
                TriggeredRule(
                    rule_id="opa-fail-closed",
                    policy_pack="opa-rego",
                    policy_version="1.0.0",
                    severity=SeverityEnum.CRITICAL,
                    reason="OPA policy service unavailable, fail-closed policy enforced",
                    compliance_tags=["AVAILABILITY-FAIL-CLOSED"],
                )
            ]
            return DecisionEnum.DENY, 1.0, triggered, {}
