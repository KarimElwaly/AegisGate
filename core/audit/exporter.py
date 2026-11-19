import csv
import io
import json
from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from core.database import db_context
from core.models.audit import AuditRecord


class ComplianceAuditExporter:
    """Exports audit logs in standard compliance formats (JSONL and CSV) with regulatory tag filtering."""

    @staticmethod
    def _matches_tag(tags_json: str, target_tag: Optional[str]) -> bool:
        if not target_tag:
            return True
        try:
            tags = json.loads(tags_json or "[]")
            target_lower = target_tag.lower()
            return any(target_lower in t.lower() for t in tags)
        except Exception:
            return False

    async def export(
        self,
        tenant_id: str,
        export_format: str = "jsonl",
        compliance_tag: Optional[str] = None,
        db_session: Optional[AsyncSession] = None,
    ) -> str:
        async def _query(session: AsyncSession) -> List[AuditRecord]:
            stmt = (
                select(AuditRecord)
                .where(AuditRecord.tenant_id == tenant_id)
                .order_by(AuditRecord.created_at.asc(), AuditRecord.id.asc())
            )
            res = await session.execute(stmt)
            all_records = list(res.scalars().all())
            return [r for r in all_records if self._matches_tag(r.compliance_tags_json, compliance_tag)]

        if db_session:
            records = await _query(db_session)
        else:
            async with db_context() as session:
                records = await _query(session)

        if export_format.lower() == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow([
                "id",
                "created_at",
                "tenant_id",
                "workspace_id",
                "trace_id",
                "session_id",
                "stage",
                "decision",
                "policy_pack_id",
                "policy_pack_version",
                "effective_mode",
                "compliance_tags",
                "latency_ms",
                "prev_hash",
                "record_hash",
            ])
            for r in records:
                writer.writerow([
                    r.id,
                    r.created_at.isoformat() if r.created_at else "",
                    r.tenant_id,
                    r.workspace_id,
                    r.trace_id,
                    r.session_id or "",
                    r.stage,
                    r.decision,
                    r.policy_pack_id,
                    r.policy_pack_version,
                    r.effective_mode,
                    r.compliance_tags_json,
                    r.latency_ms,
                    r.prev_hash,
                    r.record_hash,
                ])
            return output.getvalue()
        else:
            # Default to JSONL
            lines = []
            for r in records:
                row = {
                    "id": r.id,
                    "created_at": r.created_at.isoformat() if r.created_at else "",
                    "tenant_id": r.tenant_id,
                    "workspace_id": r.workspace_id,
                    "trace_id": r.trace_id,
                    "session_id": r.session_id,
                    "stage": r.stage,
                    "decision": r.decision,
                    "would_have_decided": r.would_have_decided,
                    "policy_pack_id": r.policy_pack_id,
                    "policy_pack_version": r.policy_pack_version,
                    "effective_mode": r.effective_mode,
                    "actor": json.loads(r.actor_json or "{}"),
                    "action": json.loads(r.action_json or "{}"),
                    "resolved_context": json.loads(r.resolved_context_json or "{}"),
                    "scanner_findings": json.loads(r.scanner_findings_json or "[]"),
                    "compliance_tags": json.loads(r.compliance_tags_json or "[]"),
                    "latency_ms": r.latency_ms,
                    "payload_hash": r.payload_hash,
                    "prev_hash": r.prev_hash,
                    "record_hash": r.record_hash,
                }
                lines.append(json.dumps(row, separators=(",", ":")))
            return "\n".join(lines)
