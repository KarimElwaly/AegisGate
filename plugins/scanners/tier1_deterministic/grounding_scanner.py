import json
from typing import Any, List
from pydantic import BaseModel, ConfigDict, Field
from core.registry.interfaces import BaseScanner, ScannerResult
from core.schemas.events import EvaluationRequest


class EvidenceGroundingConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    enabled: bool = True
    action_on_ungrounded: str = "block"  # "block" | "flag"
    require_citations_for_reports: bool = False


class EvidenceGroundingScanner(BaseScanner):
    name = "grounding_scanner"
    version = "1.0.0"
    tier = 1
    supported_stages = ["llm_output", "tool_post_call", "agent_handoff"]
    config_schema = EvidenceGroundingConfig

    async def scan(
        self,
        request: EvaluationRequest,
        context: dict[str, Any],
        config: BaseModel,
    ) -> ScannerResult:
        cfg = config if isinstance(config, EvidenceGroundingConfig) else EvidenceGroundingConfig(**config.model_dump())
        if not cfg.enabled:
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        citations = request.content.citations or []
        if not citations and cfg.require_citations_for_reports:
            return ScannerResult(
                scanner_name=self.name,
                tier=self.tier,
                status=cfg.action_on_ungrounded,
                score=0.8,
                details={"error": "No citations provided in output"},
                message="Report is missing required evidence citations",
            )

        if not citations:
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        # Gather untrusted data & known session evidence
        untrusted_text = ""
        if request.content.untrusted_data:
            if isinstance(request.content.untrusted_data, (dict, list)):
                untrusted_text = json.dumps(request.content.untrusted_data)
            else:
                untrusted_text = str(request.content.untrusted_data)

        known_ids = set()
        if "session_evidence_ids" in context:
            known_ids.update(context["session_evidence_ids"])
        if "evidence_ids" in request.metadata:
            known_ids.update(request.metadata["evidence_ids"])

        missing_citations: list[str] = []
        for cite in citations:
            cite_str = str(cite).strip()
            # Must appear in untrusted data text or in known session IDs
            if cite_str not in untrusted_text and cite_str not in known_ids:
                missing_citations.append(cite_str)

        if missing_citations:
            status = cfg.action_on_ungrounded
            return ScannerResult(
                scanner_name=self.name,
                tier=self.tier,
                status=status,
                score=1.0 if status == "block" else 0.5,
                details={
                    "total_citations": len(citations),
                    "missing_citations": missing_citations,
                },
                message=f"Detected ungrounded citations: {', '.join(missing_citations)}",
            )

        return ScannerResult(
            scanner_name=self.name,
            tier=self.tier,
            status="pass",
            details={"verified_citations": citations},
        )
