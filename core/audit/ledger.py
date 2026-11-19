import asyncio
import datetime
import hashlib
import json
import time
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import db_context
from core.logger import get_logger
from core.models.audit import AuditRecord
from core.schemas.events import EvaluationRequest
from core.schemas.verdicts import EvaluationVerdict

logger = get_logger("core.audit.ledger")

GENESIS_HASH = "0" * 64

_last_timestamp: float = 0.0


def get_monotonic_utc() -> datetime.datetime:
    global _last_timestamp
    t = time.time()
    if t <= _last_timestamp:
        t = _last_timestamp + 0.001
    _last_timestamp = t
    return datetime.datetime.fromtimestamp(t, tz=datetime.UTC)


def format_iso_utc(dt: datetime.datetime) -> str:
    """Produces normalized naive UTC ISO format for deterministic canonical hashing."""
    if dt.tzinfo is not None:
        dt = dt.astimezone(datetime.UTC).replace(tzinfo=None)
    return dt.isoformat()


def canonical_json(obj: Any) -> str:
    """Produces deterministic canonical JSON (sorted keys, compact delimiters)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def compute_sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


class AuditLedger:
    """
    Append-only cryptographically verifiable hash-chained audit ledger.
    Every record per tenant computes:
      record_hash = SHA256(prev_hash || canonical_json(record_payload))
    """

    def __init__(self, session: AsyncSession | None = None):
        self._session = session

    async def get_latest_hash(self, tenant_id: str, session: AsyncSession) -> str:
        """Fetches the record_hash of the most recent record for a tenant."""
        stmt = (
            select(AuditRecord.record_hash)
            .where(AuditRecord.tenant_id == tenant_id)
            .order_by(AuditRecord.created_at.desc(), AuditRecord.id.desc())
            .limit(1)
        )
        res = await session.execute(stmt)
        latest = res.scalar_one_or_none()
        return latest or GENESIS_HASH

    async def record_event(
        self,
        request: EvaluationRequest,
        verdict: EvaluationVerdict,
        policy_pack_id: str,
        policy_pack_version: str = "1.0.0",
        effective_mode: str = "enforce",
        would_have_decided: str | None = None,
        compliance_tags: list[str] | None = None,
        db_session: AsyncSession | None = None,
    ) -> AuditRecord:
        """Records an evaluation event into the append-only hash-chained ledger."""
        record_id = str(uuid.uuid4())
        created_at = get_monotonic_utc()

        # Compute payload hash of raw request data
        req_summary = {
            "stage": request.stage.value if hasattr(request.stage, "value") else str(request.stage),
            "actor": request.actor.model_dump() if hasattr(request.actor, "model_dump") else request.actor,
            "action": request.action.model_dump() if hasattr(request.action, "model_dump") else request.action,
            "content": request.content.model_dump() if request.content and hasattr(request.content, "model_dump") else request.content,
            "untrusted_data": request.content.untrusted_data if request.content and hasattr(request.content, "untrusted_data") else None,
        }
        payload_hash = compute_sha256(canonical_json(req_summary))

        tags = list(set((compliance_tags or []) + [
            t for r in verdict.triggered_rules for t in (r.compliance_tags or [])
        ]))

        findings_data = [
            f.model_dump() if hasattr(f, "model_dump") else f for f in verdict.scanner_findings
        ]
        actor_data = request.actor.model_dump() if hasattr(request.actor, "model_dump") else request.actor
        action_data = request.action.model_dump() if hasattr(request.action, "model_dump") else request.action

        async def _persist(s: AsyncSession) -> AuditRecord:
            prev_hash = await self.get_latest_hash(request.tenant_id, s)

            record_payload = {
                "id": record_id,
                "tenant_id": request.tenant_id,
                "workspace_id": request.workspace_id,
                "trace_id": request.trace_id,
                "session_id": request.session_id,
                "policy_pack_id": policy_pack_id,
                "policy_pack_version": policy_pack_version,
                "effective_mode": effective_mode,
                "stage": request.stage.value if hasattr(request.stage, "value") else str(request.stage),
                "decision": verdict.decision.value if hasattr(verdict.decision, "value") else str(verdict.decision),
                "would_have_decided": would_have_decided,
                "payload_hash": payload_hash,
                "actor": actor_data,
                "action": action_data,
                "resolved_context": verdict.resolved_context,
                "scanner_findings": findings_data,
                "compliance_tags": tags,
                "latency_ms": verdict.latency_ms,
                "created_at": format_iso_utc(created_at),
            }

            canonical_payload_str = canonical_json(record_payload)
            record_hash = compute_sha256(prev_hash + canonical_payload_str)

            record = AuditRecord(
                id=record_id,
                tenant_id=request.tenant_id,
                workspace_id=request.workspace_id,
                trace_id=request.trace_id,
                session_id=request.session_id,
                policy_pack_id=policy_pack_id,
                policy_pack_version=policy_pack_version,
                effective_mode=effective_mode,
                stage=request.stage.value if hasattr(request.stage, "value") else str(request.stage),
                decision=verdict.decision.value if hasattr(verdict.decision, "value") else str(verdict.decision),
                would_have_decided=would_have_decided,
                actor_json=canonical_json(actor_data),
                action_json=canonical_json(action_data),
                resolved_context_json=canonical_json(verdict.resolved_context),
                scanner_findings_json=canonical_json(findings_data),
                compliance_tags_json=canonical_json(tags),
                latency_ms=verdict.latency_ms,
                payload_hash=payload_hash,
                prev_hash=prev_hash,
                record_hash=record_hash,
                created_at=created_at,
            )
            s.add(record)
            await s.flush()
            logger.debug(
                "audit_recorded",
                tenant_id=request.tenant_id,
                trace_id=request.trace_id,
                decision=record.decision,
                record_hash=record_hash[:16],
            )
            return record

        if db_session:
            return await _persist(db_session)
        else:
            try:
                async with db_context() as session:
                    return await _persist(session)
            except (GeneratorExit, asyncio.CancelledError, Exception) as exc:
                if isinstance(exc, (GeneratorExit, asyncio.CancelledError)):
                    logger.debug("audit_record_cancelled_on_shutdown")
                    return None
                logger.error("audit_record_persist_error", error=str(exc))
                return None
