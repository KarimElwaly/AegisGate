import datetime
import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from core.database import db_context
from core.logger import get_logger
from core.models.shadow import ShadowDeltaRecord
from core.schemas.verdicts import EvaluationVerdict

logger = get_logger("core.simulator.shadow")


class ShadowDeltaItem(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: int | None = None
    tenant_id: str
    workspace_id: str
    trace_id: str
    active_pack_id: str
    active_version: str
    shadow_pack_id: str
    shadow_version: str
    active_decision: str
    shadow_decision: str
    active_reasons: list[str] = Field(default_factory=list)
    shadow_reasons: list[str] = Field(default_factory=list)
    request_summary: dict[str, Any] = Field(default_factory=dict)
    created_at: str


class ShadowDeltaManager:
    """Records and queries decision deltas between active and shadow policy packs."""

    def __init__(self):
        self._mem_deltas: list[dict[str, Any]] = []

    async def record_delta(
        self,
        tenant_id: str,
        workspace_id: str,
        trace_id: str,
        active_pack_id: str,
        active_version: str,
        shadow_pack_id: str,
        shadow_version: str,
        active_verdict: EvaluationVerdict,
        shadow_verdict: EvaluationVerdict,
        request_summary: dict[str, Any] | None = None,
    ) -> ShadowDeltaItem:
        active_decision = active_verdict.decision.value if hasattr(active_verdict.decision, "value") else str(active_verdict.decision)
        shadow_decision = shadow_verdict.decision.value if hasattr(shadow_verdict.decision, "value") else str(shadow_verdict.decision)

        active_reasons = [r.reason for r in active_verdict.triggered_rules]
        shadow_reasons = [r.reason for r in shadow_verdict.triggered_rules]
        req_sum = request_summary or {}
        now = datetime.datetime.utcnow()

        item_data = {
            "tenant_id": tenant_id,
            "workspace_id": workspace_id,
            "trace_id": trace_id,
            "active_pack_id": active_pack_id,
            "active_version": active_version,
            "shadow_pack_id": shadow_pack_id,
            "shadow_version": shadow_version,
            "active_decision": active_decision,
            "shadow_decision": shadow_decision,
            "active_reasons": active_reasons,
            "shadow_reasons": shadow_reasons,
            "request_summary": req_sum,
            "created_at": now.isoformat(),
        }
        self._mem_deltas.append(item_data)

        try:
            record = ShadowDeltaRecord(
                tenant_id=tenant_id,
                workspace_id=workspace_id,
                trace_id=trace_id,
                active_pack_id=active_pack_id,
                active_version=active_version,
                shadow_pack_id=shadow_pack_id,
                shadow_version=shadow_version,
                active_decision=active_decision,
                shadow_decision=shadow_decision,
                active_reasons_json=json.dumps(active_reasons),
                shadow_reasons_json=json.dumps(shadow_reasons),
                request_summary_json=json.dumps(req_sum),
                created_at=now,
            )
            async with db_context() as session:
                session.add(record)
                await session.commit()
        except Exception as e:
            logger.warning("db_shadow_delta_persist_skipped", error=str(e))

        logger.info(
            "shadow_delta_recorded",
            trace_id=trace_id,
            active_decision=active_decision,
            shadow_decision=shadow_decision,
        )

        return ShadowDeltaItem(**item_data)

    async def list_deltas(
        self,
        tenant_id: str,
        limit: int = 50,
    ) -> list[ShadowDeltaItem]:
        # Return from memory or DB
        matching = [
            ShadowDeltaItem(**d) for d in self._mem_deltas if d["tenant_id"] == tenant_id
        ]
        if matching:
            return matching[-limit:]

        try:
            async with db_context() as session:
                stmt = (
                    select(ShadowDeltaRecord)
                    .where(ShadowDeltaRecord.tenant_id == tenant_id)
                    .order_by(ShadowDeltaRecord.created_at.desc())
                    .limit(limit)
                )
                res = await session.execute(stmt)
                records = list(res.scalars().all())
                return [
                    ShadowDeltaItem(
                        id=r.id,
                        tenant_id=r.tenant_id,
                        workspace_id=r.workspace_id,
                        trace_id=r.trace_id,
                        active_pack_id=r.active_pack_id,
                        active_version=r.active_version,
                        shadow_pack_id=r.shadow_pack_id,
                        shadow_version=r.shadow_version,
                        active_decision=r.active_decision,
                        shadow_decision=r.shadow_decision,
                        active_reasons=json.loads(r.active_reasons_json or "[]"),
                        shadow_reasons=json.loads(r.shadow_reasons_json or "[]"),
                        request_summary=json.loads(r.request_summary_json or "{}"),
                        created_at=r.created_at.isoformat() if r.created_at else "",
                    )
                    for r in records
                ]
        except Exception:
            return []


_global_shadow_delta_mgr: ShadowDeltaManager | None = None


def get_shadow_delta_manager() -> ShadowDeltaManager:
    global _global_shadow_delta_mgr
    if _global_shadow_delta_mgr is None:
        _global_shadow_delta_mgr = ShadowDeltaManager()
    return _global_shadow_delta_mgr
