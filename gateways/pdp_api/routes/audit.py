import json
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Response
from sqlalchemy import select

from core.audit.exporter import ComplianceAuditExporter
from core.audit.verifier import AuditVerificationResult, AuditVerifier
from core.database import db_context
from core.models.audit import AuditRecord

router = APIRouter(prefix="/v1/audit", tags=["Audit Ledger & Compliance"])


@router.get("/verify", response_model=AuditVerificationResult)
async def verify_audit_chain(
    tenant_id: str = Query(default="default", description="Tenant ID to cryptographically verify"),
) -> AuditVerificationResult:
    """
    Cryptographically verifies hash-chain continuity and payload integrity for all audit records
    of a tenant: record_hash == SHA256(prev_hash || canonical_json(record_payload)).
    """
    verifier = AuditVerifier()
    return await verifier.verify_tenant_chain(tenant_id=tenant_id)


@router.get("/export")
async def export_audit_logs(
    tenant_id: str = Query(default="default", description="Tenant ID to export"),
    format: str = Query(default="jsonl", pattern="^(jsonl|csv)$", description="Export format: jsonl or csv"),
    compliance_tag: str | None = Query(default=None, description="Optional regulatory tag filter (e.g. OWASP-LLM, SOC2)"),
) -> Response:
    """Exports audit logs in JSONL or CSV with compliance tag filtering."""
    exporter = ComplianceAuditExporter()
    content = await exporter.export(tenant_id=tenant_id, export_format=format, compliance_tag=compliance_tag)
    media_type = "text/csv" if format == "csv" else "application/x-ndjson"
    filename = f"audit_{tenant_id}_{format}.{format}"
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("")
async def list_audit_records(
    tenant_id: str = Query(default="default", description="Tenant ID"),
    decision: str | None = Query(default=None, description="Filter by decision"),
    limit: int = Query(default=50, ge=1, le=500, description="Max records to return"),
) -> list[dict[str, Any]]:
    """Lists audit records for a tenant."""
    results: list[dict[str, Any]] = []
    try:
        async with db_context() as session:
            stmt = select(AuditRecord).where(AuditRecord.tenant_id == tenant_id)
            if decision:
                stmt = stmt.where(AuditRecord.decision == decision)
            stmt = stmt.order_by(AuditRecord.created_at.desc(), AuditRecord.id.desc()).limit(limit)
            res = await session.execute(stmt)
            records = res.scalars().all()
            for r in records:
                results.append({
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
                    "actor": json.loads(r.actor_json or "{}"),
                    "action": json.loads(r.action_json or "{}"),
                    "resolved_context": json.loads(r.resolved_context_json or "{}"),
                    "scanner_findings": json.loads(r.scanner_findings_json or "[]"),
                    "compliance_tags": json.loads(r.compliance_tags_json or "[]"),
                    "latency_ms": r.latency_ms,
                    "payload_hash": r.payload_hash,
                    "prev_hash": r.prev_hash,
                    "record_hash": r.record_hash,
                })
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Database query error: {exc!s}")
    return results
