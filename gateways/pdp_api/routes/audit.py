import datetime
import json
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import func, select

from core.auth.dependencies import AuthenticatedActor, get_pdp_actor
from core.audit.exporter import ComplianceAuditExporter
from core.audit.verifier import AuditVerificationResult, AuditVerifier
from core.database import db_context
from core.models.approval import ApprovalTicketRecord
from core.models.audit import AuditRecord
from core.models.discovery import DiscoveredAssetRecord

router = APIRouter(prefix="/v1/audit", tags=["Audit Ledger & Compliance"])


@router.get("/verify", response_model=AuditVerificationResult)
async def verify_audit_chain(
    tenant_id: str | None = Query(default=None, description="Tenant ID to cryptographically verify"),
    actor: AuthenticatedActor = Depends(get_pdp_actor),
) -> AuditVerificationResult:
    """
    Cryptographically verifies hash-chain continuity and payload integrity for all audit records
    of a tenant: record_hash == SHA256(prev_hash || canonical_json(record_payload)).
    """
    effective_tenant = actor.tenant_id
    if actor.role == "SuperAdmin" and tenant_id:
        effective_tenant = tenant_id
    elif tenant_id and tenant_id != actor.tenant_id and actor.role != "SuperAdmin":
        raise HTTPException(status_code=403, detail="Cross-tenant access forbidden")

    verifier = AuditVerifier()
    return await verifier.verify_tenant_chain(tenant_id=effective_tenant)


@router.get("/export")
async def export_audit_logs(
    tenant_id: str | None = Query(default=None, description="Tenant ID to export"),
    format: str = Query(default="jsonl", pattern="^(jsonl|csv)$", description="Export format: jsonl or csv"),
    compliance_tag: str | None = Query(default=None, description="Optional regulatory tag filter (e.g. OWASP-LLM, SOC2)"),
    actor: AuthenticatedActor = Depends(get_pdp_actor),
) -> Response:
    """Exports audit logs in JSONL or CSV with compliance tag filtering."""
    effective_tenant = actor.tenant_id
    if actor.role == "SuperAdmin" and tenant_id:
        effective_tenant = tenant_id
    elif tenant_id and tenant_id != actor.tenant_id and actor.role != "SuperAdmin":
        raise HTTPException(status_code=403, detail="Cross-tenant access forbidden")

    exporter = ComplianceAuditExporter()
    content = await exporter.export(tenant_id=effective_tenant, export_format=format, compliance_tag=compliance_tag)
    media_type = "text/csv" if format == "csv" else "application/x-ndjson"
    filename = f"audit_{effective_tenant}_{format}.{format}"
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("")
async def list_audit_records(
    tenant_id: str | None = Query(default=None, description="Tenant ID"),
    decision: str | None = Query(default=None, description="Filter by decision"),
    limit: int = Query(default=50, ge=1, le=500, description="Max records to return"),
    actor: AuthenticatedActor = Depends(get_pdp_actor),
) -> list[dict[str, Any]]:
    """Lists audit records for a tenant."""
    effective_tenant = actor.tenant_id
    if actor.role == "SuperAdmin" and tenant_id:
        effective_tenant = tenant_id
    elif tenant_id and tenant_id != actor.tenant_id and actor.role != "SuperAdmin":
        raise HTTPException(status_code=403, detail="Cross-tenant access forbidden")

    results: list[dict[str, Any]] = []
    try:
        async with db_context() as session:
            stmt = select(AuditRecord).where(AuditRecord.tenant_id == effective_tenant)
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


@router.get("/compliance-report")
async def generate_compliance_report(
    framework: str = Query(
        default="eu-ai-act",
        pattern="^(eu-ai-act|hipaa|pci-dss|nist-ai-rmf)$",
        description="Regulatory compliance framework",
    ),
    tenant_id: str | None = Query(default=None, description="Tenant ID to audit"),
    format: str = Query(default="json", pattern="^(json|markdown)$", description="Report format: json or markdown"),
    from_date: str | None = Query(default=None),
    to_date: str | None = Query(default=None),
    actor: AuthenticatedActor = Depends(get_pdp_actor),
) -> Response:
    """Generates structured auditor evidence package with cryptographic verification certificate."""
    effective_tenant = actor.tenant_id
    if actor.role == "SuperAdmin" and tenant_id:
        effective_tenant = tenant_id
    elif tenant_id and tenant_id != actor.tenant_id and actor.role != "SuperAdmin":
        raise HTTPException(status_code=403, detail="Cross-tenant access forbidden")

    verifier = AuditVerifier()
    verif = await verifier.verify_tenant_chain(tenant_id=effective_tenant)

    decision_counts: dict[str, int] = {"ALLOW": 0, "DENY": 0, "MODIFY": 0, "SUSPEND_FOR_APPROVAL": 0}
    control_breakdown: dict[str, int] = {}
    hitl_counts: dict[str, int] = {"pending": 0, "approved": 0, "rejected": 0}
    shadow_count = 0

    framework_prefixes = {
        "eu-ai-act": "EU-AI-ACT",
        "hipaa": "HIPAA",
        "pci-dss": "PCI-DSS",
        "nist-ai-rmf": "NIST-AI-RMF",
    }
    target_prefix = framework_prefixes.get(framework, "")

    try:
        async with db_context() as session:
            # 1. Audit decisions
            stmt = select(AuditRecord).where(AuditRecord.tenant_id == effective_tenant)
            res = await session.execute(stmt)
            records = res.scalars().all()

            for r in records:
                dec = r.decision
                if dec in decision_counts:
                    decision_counts[dec] += 1
                else:
                    decision_counts[dec] = 1

                try:
                    tags = json.loads(r.compliance_tags_json or "[]")
                    for t in tags:
                        if target_prefix in t:
                            control_breakdown[t] = control_breakdown.get(t, 0) + 1
                except Exception:
                    pass

            # 2. HITL Ticket stats
            ticket_stmt = select(ApprovalTicketRecord).where(ApprovalTicketRecord.tenant_id == effective_tenant)
            ticket_res = await session.execute(ticket_stmt)
            tickets = ticket_res.scalars().all()
            for t in tickets:
                st = (t.status or "pending").lower()
                if st in hitl_counts:
                    hitl_counts[st] += 1

            # 3. Discovered shadow assets
            shadow_stmt = select(func.count(DiscoveredAssetRecord.id)).where(DiscoveredAssetRecord.tenant_id == effective_tenant)
            shadow_res = await session.execute(shadow_stmt)
            shadow_count = shadow_res.scalar() or 0

    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Database aggregation error: {exc!s}")

    report_id = str(uuid.uuid4())
    generated_at = datetime.datetime.now(datetime.UTC).isoformat()

    report_data = {
        "report_id": report_id,
        "framework": framework,
        "tenant_id": effective_tenant,
        "generated_at": generated_at,
        "hash_chain_certificate": {
            "is_valid": verif.is_valid,
            "total_records": verif.total_records,
            "tampered_records": verif.tampered_records,
            "status": "VERIFIED_UNBROKEN" if verif.is_valid else "TAMPERED",
            "verification_message": verif.message,
        },
        "enforcement_summary": decision_counts,
        "control_breakdown": control_breakdown,
        "hitl_human_oversight": hitl_counts,
        "shadow_ai_exceptions": shadow_count,
    }

    if format == "markdown":
        md = f"""# AegisGate Regulatory Compliance Audit Report
**Framework:** {framework.upper()}  
**Report ID:** `{report_id}`  
**Tenant ID:** `{tenant_id}`  
**Generated At:** {generated_at}  

---

## 1. Cryptographic Hash-Chain Verification
- **Status:** **{'✓ ' + ('VERIFIED_UNBROKEN' if verif.is_valid else 'TAMPERED')}**
- **Total Audited Records:** {verif.total_records}
- **Tampered Records:** {len(verif.tampered_records)}
- **Certificate Detail:** {verif.message}

---

## 2. Policy Enforcement Summary
| Decision | Count |
| :--- | :--- |
| **ALLOW** | {decision_counts.get('ALLOW', 0)} |
| **DENY** (Enforced Block) | {decision_counts.get('DENY', 0)} |
| **MODIFY** (Sanitized / Sovereign) | {decision_counts.get('MODIFY', 0)} |
| **SUSPEND_FOR_APPROVAL** (HITL) | {decision_counts.get('SUSPEND_FOR_APPROVAL', 0)} |

---

## 3. Control Breakdown ({target_prefix})
| Control Tag | Enforcements |
| :--- | :--- |
"""
        if control_breakdown:
            for ctag, count in control_breakdown.items():
                md += f"| `{ctag}` | {count} |\n"
        else:
            md += "| *No specific control triggers recorded in period* | 0 |\n"

        md += f"""
---

## 4. Human Oversight (HITL) Governance
- **Pending Approvals:** {hitl_counts.get('pending', 0)}
- **Approved Actions:** {hitl_counts.get('approved', 0)}
- **Rejected Actions:** {hitl_counts.get('rejected', 0)}

---

## 5. Shadow AI Assets & Discovery
- **Unapproved / Monitored Shadow AI Assets:** {shadow_count}

*Certified by AegisGate Sub-15ms Governance PDP Engine.*
"""
        return Response(content=md, media_type="text/markdown", headers={"Content-Disposition": f'inline; filename="compliance_{framework}_{tenant_id}.md"'})

    return Response(content=json.dumps(report_data, indent=2), media_type="application/json")
