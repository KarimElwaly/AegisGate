import json

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.audit.ledger import GENESIS_HASH, canonical_json, compute_sha256, format_iso_utc
from core.crypto.kms import get_key_provider
from core.database import db_context
from core.logger import get_logger
from core.models.audit import AuditRecord

logger = get_logger("core.audit.verifier")


class AuditVerificationResult(BaseModel):
    is_valid: bool = Field(..., description="True if cryptographic hash chain is continuous and uncorrupted")
    total_records: int = Field(default=0, description="Total audit records verified")
    tampered_records: list[str] = Field(default_factory=list, description="IDs of records failing cryptographic proof")
    message: str = Field(default="", description="Detailed verification status message")


class AuditVerifier:
    """Verifies cryptographic hash chain integrity for an audit ledger."""

    @classmethod
    def recompute_record_hash(cls, record: AuditRecord) -> str:
        """Recomputes expected SHA256(prev_hash || canonical_json(record_payload))."""
        actor_data = json.loads(record.actor_json) if record.actor_json else {}
        action_data = json.loads(record.action_json) if record.action_json else {}
        resolved_context = json.loads(record.resolved_context_json) if record.resolved_context_json else {}
        scanner_findings = json.loads(record.scanner_findings_json) if record.scanner_findings_json else []
        compliance_tags = json.loads(record.compliance_tags_json) if record.compliance_tags_json else []

        record_payload = {
            "id": record.id,
            "tenant_id": record.tenant_id,
            "workspace_id": record.workspace_id,
            "trace_id": record.trace_id,
            "session_id": record.session_id,
            "policy_pack_id": record.policy_pack_id,
            "policy_pack_version": record.policy_pack_version,
            "effective_mode": record.effective_mode,
            "stage": record.stage,
            "decision": record.decision,
            "would_have_decided": record.would_have_decided,
            "payload_hash": record.payload_hash,
            "actor": actor_data,
            "action": action_data,
            "resolved_context": resolved_context,
            "scanner_findings": scanner_findings,
            "compliance_tags": compliance_tags,
            "latency_ms": record.latency_ms,
            "created_at": format_iso_utc(record.created_at),
        }
        canonical_payload_str = canonical_json(record_payload)
        return compute_sha256(record.prev_hash + canonical_payload_str)

    async def verify_tenant_chain(
        self,
        tenant_id: str,
        db_session: AsyncSession | None = None,
    ) -> AuditVerificationResult:
        """
        Sequentially validates all records for tenant_id:
        1. Confirms prev_hash == previous record's record_hash (or GENESIS_HASH for first record).
        2. Recomputes SHA256(prev_hash || canonical_json(payload)) and confirms equality to record_hash.
        """
        async def _run(session: AsyncSession) -> AuditVerificationResult:
            stmt = (
                select(AuditRecord)
                .where(AuditRecord.tenant_id == tenant_id)
                .order_by(AuditRecord.created_at.asc(), AuditRecord.id.asc())
            )
            res = await session.execute(stmt)
            records = list(res.scalars().all())

            if not records:
                return AuditVerificationResult(
                    is_valid=True,
                    total_records=0,
                    tampered_records=[],
                    message="No audit records found for tenant (empty ledger is valid).",
                )

            tampered_ids: list[str] = []
            by_prev: dict[str, AuditRecord] = {}
            for r in records:
                if r.prev_hash in by_prev:
                    tampered_ids.append(r.id)
                    logger.error("audit_chain_fork_detected", record_id=r.id, prev_hash=r.prev_hash)
                    break
                by_prev[r.prev_hash] = r

            if tampered_ids:
                return AuditVerificationResult(
                    is_valid=False,
                    total_records=len(records),
                    tampered_records=tampered_ids,
                    message=f"Audit chain verification FAILED: Fork detected at record ID {tampered_ids[0]}.",
                )

            # Reconstruct topological chain starting from GENESIS_HASH
            ordered_chain: list[AuditRecord] = []
            curr_hash = GENESIS_HASH
            while curr_hash in by_prev:
                curr_rec = by_prev[curr_hash]
                ordered_chain.append(curr_rec)
                curr_hash = curr_rec.record_hash

            if len(ordered_chain) != len(records):
                missing_records = [r.id for r in records if r not in ordered_chain]
                return AuditVerificationResult(
                    is_valid=False,
                    total_records=len(records),
                    tampered_records=missing_records,
                    message="Audit chain verification FAILED: Discontinuity or orphaned records detected.",
                )

            expected_prev_hash = GENESIS_HASH
            for idx, rec in enumerate(ordered_chain):
                # 1. Check prev_hash continuity
                if rec.prev_hash != expected_prev_hash:
                    tampered_ids.append(rec.id)
                    logger.error(
                        "audit_hash_chain_broken",
                        record_id=rec.id,
                        expected_prev=expected_prev_hash,
                        actual_prev=rec.prev_hash,
                        index=idx,
                    )
                    break

                # 2. Recompute record_hash
                expected_record_hash = self.recompute_record_hash(rec)
                if rec.record_hash != expected_record_hash:
                    tampered_ids.append(rec.id)
                    logger.error(
                        "audit_record_payload_tampered",
                        record_id=rec.id,
                        expected_hash=expected_record_hash,
                        actual_hash=rec.record_hash,
                        index=idx,
                    )
                    break

                expected_prev_hash = rec.record_hash

                # 3. Check KMS HMAC signature if present
                if rec.kms_signature:
                    key_provider = get_key_provider()
                    if not key_provider.verify_hmac(rec.record_hash, rec.kms_signature):
                        tampered_ids.append(rec.id)
                        logger.error(
                            "audit_kms_signature_invalid",
                            record_id=rec.id,
                            record_hash=rec.record_hash,
                            index=idx,
                        )
                        break

            if tampered_ids:
                return AuditVerificationResult(
                    is_valid=False,
                    total_records=len(records),
                    tampered_records=tampered_ids,
                    message=f"Audit chain verification FAILED: Tampering or discontinuity detected at record ID {tampered_ids[0]}.",
                )

            return AuditVerificationResult(
                is_valid=True,
                total_records=len(records),
                tampered_records=[],
                message=f"Audit chain verified successfully across {len(records)} records. Hash continuity unbroken.",
            )

        if db_session:
            return await _run(db_session)
        else:
            async with db_context() as session:
                return await _run(session)
