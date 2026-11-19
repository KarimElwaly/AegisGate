import json
import time
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import db_context
from core.logger import get_logger
from core.models.audit import AuditRecord
from core.policy_engine.yaml_engine import get_yaml_policy_engine
from core.schemas.events import ActionModel, ActorModel, EvaluationRequest
from core.schemas.policy import PolicyPackDefinition
from core.schemas.verdicts import ScannerFinding

logger = get_logger("core.simulator.replay")


class ReplaySimulationRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    tenant_id: str = "default"
    candidate_pack_yaml: str | None = None
    candidate_pack_id: str | None = None
    max_events: int = Field(default=100, ge=1, le=1000)


class ReplayDiffReport(BaseModel):
    model_config = ConfigDict(extra="ignore")

    total_events: int = 0
    concordant_count: int = 0
    discordant_count: int = 0
    concordance_rate: float = 1.0
    new_blocks_count: int = 0
    new_allows_count: int = 0
    new_blocks: list[dict[str, Any]] = Field(default_factory=list)
    new_allows: list[dict[str, Any]] = Field(default_factory=list)
    avg_replayed_latency_ms: float = 0.0


class PolicyReplaySimulator:
    """
    Historical Policy Simulation Lab.
    Replays recorded audit events against a candidate draft policy pack
    and outputs a comprehensive diff report before production rollout.
    """

    def __init__(self):
        self.yaml_engine = get_yaml_policy_engine()

    async def run_replay(
        self,
        request: ReplaySimulationRequest,
        db_session: AsyncSession | None = None,
    ) -> ReplayDiffReport:
        # 1. Parse or fetch candidate policy pack
        candidate_pack: PolicyPackDefinition | None = None
        if request.candidate_pack_yaml:
            candidate_pack = self.yaml_engine.load_pack_from_yaml(request.candidate_pack_yaml)
        elif request.candidate_pack_id:
            # Look up registered pack from engine
            candidate_pack = self.yaml_engine.get_registered_pack(request.candidate_pack_id)

        if not candidate_pack:
            raise ValueError("Candidate policy pack could not be resolved from YAML or pack_id.")

        # 2. Fetch historical audit logs
        records: list[AuditRecord] = []
        async def _fetch(s: AsyncSession):
            stmt = (
                select(AuditRecord)
                .where(AuditRecord.tenant_id == request.tenant_id)
                .order_by(AuditRecord.created_at.desc())
                .limit(request.max_events)
            )
            res = await s.execute(stmt)
            return list(res.scalars().all())

        if db_session:
            records = await _fetch(db_session)
        else:
            async with db_context() as session:
                records = await _fetch(session)

        if not records:
            return ReplayDiffReport(
                total_events=0,
                concordant_count=0,
                discordant_count=0,
                concordance_rate=1.0,
                new_blocks_count=0,
                new_allows_count=0,
                new_blocks=[],
                new_allows=[],
                avg_replayed_latency_ms=0.0,
            )

        # 3. Replay each record against candidate policy pack
        total = len(records)
        concordant = 0
        new_blocks: list[dict[str, Any]] = []
        new_allows: list[dict[str, Any]] = []
        latencies: list[float] = []

        for rec in records:
            actor_dict = json.loads(rec.actor_json or "{}")
            action_dict = json.loads(rec.action_json or "{}")
            resolved_ctx = json.loads(rec.resolved_context_json or "{}")
            raw_findings = json.loads(rec.scanner_findings_json or "[]")
            scanner_findings = [
                ScannerFinding(**sf) if isinstance(sf, dict) else sf
                for sf in raw_findings
            ]

            eval_req = EvaluationRequest(
                trace_id=rec.trace_id,
                tenant_id=rec.tenant_id,
                workspace_id=rec.workspace_id,
                session_id=rec.session_id,
                policy_pack_id=candidate_pack.id,
                stage=rec.stage,
                actor=ActorModel(**actor_dict) if actor_dict else ActorModel(id="unknown", role="unknown"),
                action=ActionModel(**action_dict) if action_dict else ActionModel(name="unknown"),
            )

            t0 = time.perf_counter()
            cand_decision, risk_score, triggered_rules, _ = await self.yaml_engine.evaluate(
                request=eval_req,
                scanner_findings=scanner_findings,
                resolved_context=resolved_ctx,
                policy_pack=candidate_pack,
            )
            t1 = time.perf_counter()
            latencies.append((t1 - t0) * 1000.0)

            cand_dec_str = cand_decision.value if hasattr(cand_decision, "value") else str(cand_decision)
            hist_dec_str = rec.decision

            if cand_dec_str == hist_dec_str:
                concordant += 1
            else:
                diff_item = {
                    "trace_id": rec.trace_id,
                    "action_name": action_dict.get("name"),
                    "historical_decision": hist_dec_str,
                    "candidate_decision": cand_dec_str,
                    "candidate_triggered_rules": [r.rule_id for r in triggered_rules],
                    "candidate_reasons": [r.reason for r in triggered_rules],
                }
                if hist_dec_str == "ALLOW" and cand_dec_str in ("DENY", "SUSPEND_FOR_APPROVAL"):
                    new_blocks.append(diff_item)
                elif hist_dec_str in ("DENY", "SUSPEND_FOR_APPROVAL") and cand_dec_str == "ALLOW":
                    new_allows.append(diff_item)

        discordant = total - concordant
        concordance_rate = round(concordant / total, 4) if total > 0 else 1.0
        avg_lat = round(sum(latencies) / len(latencies), 3) if latencies else 0.0

        return ReplayDiffReport(
            total_events=total,
            concordant_count=concordant,
            discordant_count=discordant,
            concordance_rate=concordance_rate,
            new_blocks_count=len(new_blocks),
            new_allows_count=len(new_allows),
            new_blocks=new_blocks,
            new_allows=new_allows,
            avg_replayed_latency_ms=avg_lat,
        )


_global_replay_simulator: PolicyReplaySimulator | None = None


def get_replay_simulator() -> PolicyReplaySimulator:
    global _global_replay_simulator
    if _global_replay_simulator is None:
        _global_replay_simulator = PolicyReplaySimulator()
    return _global_replay_simulator
