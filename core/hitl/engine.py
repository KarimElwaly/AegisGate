import asyncio
import datetime
import hashlib
import hmac
import json
import uuid
from typing import Any

import httpx
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import db_context
from core.hitl.schemas import ApprovalDecisionRequest, ApprovalTicketResponse
from core.logger import get_logger
from core.models.approval import ApprovalTicketRecord
from core.schemas.events import EvaluationRequest
from core.schemas.verdicts import EvaluationVerdict
from core.security.ssrf import SSRFProtectionError, validate_outbound_url

logger = get_logger("core.hitl.engine")


class HITLEngine:
    """
    Human-in-the-Loop (HITL) Governance Engine.
    Manages persistent approval tickets, single/dual-approval (4-eyes principle),
    parameter overrides, and HMAC-signed webhook callback dispatches.
    """

    def __init__(self, db_session: AsyncSession | None = None):
        self._db_session = db_session
        # In-memory store fallback for fast testing or when running without DB
        self._mem_tickets: dict[str, dict[str, Any]] = {}

    def _to_response(self, data: dict[str, Any]) -> ApprovalTicketResponse:
        return ApprovalTicketResponse(
            ticket_id=data["ticket_id"],
            tenant_id=data["tenant_id"],
            workspace_id=data["workspace_id"],
            trace_id=data["trace_id"],
            session_id=data.get("session_id"),
            policy_pack_id=data["policy_pack_id"],
            status=data["status"],
            risk_score=data.get("risk_score", 0.0),
            action_name=data["action_name"],
            original_parameters=data.get("original_parameters", {}),
            modified_parameters=data.get("modified_parameters"),
            triggered_rules=data.get("triggered_rules", []),
            resolved_context=data.get("resolved_context", {}),
            required_approvals=data.get("required_approvals", 1),
            required_approver_roles=data.get("required_approver_roles", []),
            approved_by=data.get("approved_by", []),
            rejected_by=data.get("rejected_by"),
            decision_notes=data.get("decision_notes"),
            callback_url=data.get("callback_url"),
            expires_at=data["expires_at"].isoformat() if isinstance(data["expires_at"], datetime.datetime) else str(data["expires_at"]),
            created_at=data["created_at"].isoformat() if isinstance(data["created_at"], datetime.datetime) else str(data["created_at"]),
            updated_at=data["updated_at"].isoformat() if isinstance(data["updated_at"], datetime.datetime) else str(data["updated_at"]),
        )

    async def create_ticket(
        self,
        request: EvaluationRequest,
        verdict: EvaluationVerdict,
        policy_pack_id: str,
        required_approvals: int = 1,
        required_approver_roles: list[str] | None = None,
        ttl_seconds: int = 300,
        callback_url: str | None = None,
        callback_secret: str | None = None,
    ) -> ApprovalTicketResponse:
        ticket_id = str(uuid.uuid4())
        now = datetime.datetime.utcnow()
        expires_at = now + datetime.timedelta(seconds=ttl_seconds)

        action_name = request.action.name if hasattr(request.action, "name") else str(request.action)
        orig_params = request.action.parameters if hasattr(request.action, "parameters") else {}
        triggered_rules_data = [
            r.model_dump() if hasattr(r, "model_dump") else r for r in verdict.triggered_rules
        ]

        ticket_data = {
            "ticket_id": ticket_id,
            "tenant_id": request.tenant_id,
            "workspace_id": request.workspace_id,
            "trace_id": request.trace_id,
            "session_id": request.session_id,
            "policy_pack_id": policy_pack_id,
            "status": "pending",
            "risk_score": verdict.risk_score,
            "action_name": action_name,
            "original_parameters": orig_params,
            "modified_parameters": None,
            "triggered_rules": triggered_rules_data,
            "resolved_context": verdict.resolved_context or {},
            "required_approvals": max(1, required_approvals),
            "required_approver_roles": required_approver_roles or [],
            "approved_by": [],
            "rejected_by": None,
            "decision_notes": None,
            "callback_url": callback_url,
            "callback_secret": callback_secret,
            "expires_at": expires_at,
            "created_at": now,
            "updated_at": now,
        }

        # Store in memory cache
        self._mem_tickets[ticket_id] = ticket_data

        # Store in DB if available
        try:
            record = ApprovalTicketRecord(
                ticket_id=ticket_id,
                tenant_id=request.tenant_id,
                workspace_id=request.workspace_id,
                trace_id=request.trace_id,
                session_id=request.session_id,
                policy_pack_id=policy_pack_id,
                status="pending",
                risk_score=verdict.risk_score,
                action_name=action_name,
                original_parameters_json=json.dumps(orig_params),
                modified_parameters_json=None,
                triggered_rules_json=json.dumps(triggered_rules_data),
                resolved_context_json=json.dumps(verdict.resolved_context or {}),
                required_approvals=max(1, required_approvals),
                required_approver_roles_json=json.dumps(required_approver_roles or []),
                approved_by_json=json.dumps([]),
                rejected_by=None,
                decision_notes=None,
                callback_url=callback_url,
                callback_secret=callback_secret,
                expires_at=expires_at,
                created_at=now,
                updated_at=now,
            )
            if self._db_session:
                self._db_session.add(record)
                await self._db_session.flush()
            else:
                async with db_context() as session:
                    session.add(record)
                    await session.commit()
        except Exception as e:
            logger.warning("db_ticket_persist_skipped", error=str(e))

        logger.info(
            "hitl_ticket_created",
            ticket_id=ticket_id,
            action=action_name,
            required_approvals=required_approvals,
            expires_at=expires_at.isoformat(),
        )

        return self._to_response(ticket_data)

    async def get_ticket(self, ticket_id: str) -> ApprovalTicketResponse | None:
        # Check memory first
        data = self._mem_tickets.get(ticket_id)
        if not data:
            # Check DB
            try:
                async with db_context() as session:
                    stmt = select(ApprovalTicketRecord).where(ApprovalTicketRecord.ticket_id == ticket_id)
                    res = await session.execute(stmt)
                    rec = res.scalar_one_or_none()
                    if rec:
                        data = {
                            "ticket_id": rec.ticket_id,
                            "tenant_id": rec.tenant_id,
                            "workspace_id": rec.workspace_id,
                            "trace_id": rec.trace_id,
                            "session_id": rec.session_id,
                            "policy_pack_id": rec.policy_pack_id,
                            "status": rec.status,
                            "risk_score": rec.risk_score,
                            "action_name": rec.action_name,
                            "original_parameters": json.loads(rec.original_parameters_json or "{}"),
                            "modified_parameters": json.loads(rec.modified_parameters_json) if rec.modified_parameters_json else None,
                            "triggered_rules": json.loads(rec.triggered_rules_json or "[]"),
                            "resolved_context": json.loads(rec.resolved_context_json or "{}"),
                            "required_approvals": rec.required_approvals,
                            "required_approver_roles": json.loads(rec.required_approver_roles_json or "[]"),
                            "approved_by": json.loads(rec.approved_by_json or "[]"),
                            "rejected_by": rec.rejected_by,
                            "decision_notes": rec.decision_notes,
                            "callback_url": rec.callback_url,
                            "callback_secret": rec.callback_secret,
                            "expires_at": rec.expires_at,
                            "created_at": rec.created_at,
                            "updated_at": rec.updated_at,
                        }
                        self._mem_tickets[ticket_id] = data
            except Exception as e:
                logger.warning("db_get_ticket_error", error=str(e))

        if not data:
            return None

        # Check expiration
        now = datetime.datetime.utcnow()
        exp = data["expires_at"] if isinstance(data["expires_at"], datetime.datetime) else datetime.datetime.fromisoformat(str(data["expires_at"]))
        if data["status"] == "pending" and now > exp:
            data["status"] = "expired"
            data["updated_at"] = now
            self._mem_tickets[ticket_id] = data

        return self._to_response(data)

    async def list_tickets(
        self,
        tenant_id: str,
        status: str | None = None,
    ) -> list[ApprovalTicketResponse]:
        results: list[ApprovalTicketResponse] = []
        try:
            async with db_context() as session:
                stmt = select(ApprovalTicketRecord).where(ApprovalTicketRecord.tenant_id == tenant_id)
                if status:
                    stmt = stmt.where(ApprovalTicketRecord.status == status)
                stmt = stmt.order_by(ApprovalTicketRecord.created_at.desc())
                res = await session.execute(stmt)
                records = res.scalars().all()
                if records:
                    for rec in records:
                        t_resp = await self.get_ticket(rec.ticket_id)
                        if t_resp and (status is None or t_resp.status == status):
                            results.append(t_resp)
                    return results
        except Exception as e:
            logger.warning("db_list_tickets_error", error=str(e))

        # Fallback to in-memory store matching tenant
        for t in self._mem_tickets.values():
            if t["tenant_id"] == tenant_id:
                resp = await self.get_ticket(t["ticket_id"])
                if resp and (status is None or resp.status == status):
                    results.append(resp)
        return results

    async def decide_ticket(
        self,
        ticket_id: str,
        decision_req: ApprovalDecisionRequest,
    ) -> ApprovalTicketResponse:
        ticket = await self.get_ticket(ticket_id)
        if not ticket:
            raise ValueError(f"Approval ticket '{ticket_id}' not found.")

        data = self._mem_tickets[ticket_id]

        if data["status"] != "pending":
            raise ValueError(f"Cannot decide ticket in '{data['status']}' state.")

        # Check approver role if roles are restricted (SuperAdmin has universal override authority)
        req_roles = data.get("required_approver_roles") or []
        if req_roles and decision_req.approver_role not in req_roles and decision_req.approver_role.lower() != "superadmin":
            raise PermissionError(
                f"Approver role '{decision_req.approver_role}' is not authorized. Required: {req_roles}"
            )

        now = datetime.datetime.utcnow()
        decision_action = decision_req.decision.lower().strip()

        if decision_action == "reject":
            data["status"] = "rejected"
            data["rejected_by"] = decision_req.approver_id
            data["decision_notes"] = decision_req.decision_notes
            data["updated_at"] = now
        elif decision_action == "approve":
            # Guard against same approver approving twice (Dual-Approval / 4-eyes rule)
            approved_by_list = data.get("approved_by", [])
            if decision_req.approver_id in approved_by_list:
                raise ValueError(
                    f"Approver '{decision_req.approver_id}' has already approved this ticket. Dual-approval requires a distinct second approver."
                )

            approved_by_list.append(decision_req.approver_id)
            data["approved_by"] = approved_by_list

            # Handle parameter overrides
            if decision_req.parameter_override is not None:
                data["modified_parameters"] = decision_req.parameter_override

            if decision_req.decision_notes:
                data["decision_notes"] = decision_req.decision_notes

            # Check if threshold reached
            if len(approved_by_list) >= data.get("required_approvals", 1):
                data["status"] = "approved"
            else:
                data["status"] = "pending"  # Waiting for additional approvals

            data["updated_at"] = now
        else:
            raise ValueError(f"Unsupported decision: '{decision_action}'. Must be 'approve' or 'reject'.")

        self._mem_tickets[ticket_id] = data

        # Dispatch async webhook callback if status finalized
        if data["status"] in ("approved", "rejected") and data.get("callback_url"):
            asyncio.create_task(self._send_callback(data))

        # Update in DB asynchronously
        try:
            async with db_context() as session:
                stmt = (
                    update(ApprovalTicketRecord)
                    .where(ApprovalTicketRecord.ticket_id == ticket_id)
                    .values(
                        status=data["status"],
                        approved_by_json=json.dumps(data["approved_by"]),
                        rejected_by=data.get("rejected_by"),
                        modified_parameters_json=json.dumps(data["modified_parameters"]) if data.get("modified_parameters") else None,
                        decision_notes=data.get("decision_notes"),
                        updated_at=now,
                    )
                )
                await session.execute(stmt)
                await session.commit()
        except Exception as e:
            logger.warning("db_update_ticket_error", error=str(e))

        logger.info(
            "hitl_ticket_decided",
            ticket_id=ticket_id,
            approver=decision_req.approver_id,
            decision=decision_action,
            new_status=data["status"],
        )

        return self._to_response(data)

    async def _send_callback(self, ticket_data: dict[str, Any]) -> None:
        """Sends signed HMAC POST callback to caller's webhook."""
        url = ticket_data.get("callback_url")
        secret = ticket_data.get("callback_secret") or "aegisgate-default-secret"
        if not url:
            return

        try:
            await validate_outbound_url(url, target_type="hitl_callback")
        except SSRFProtectionError as ssrf_err:
            logger.warning(
                "hitl_callback_ssrf_blocked",
                ticket_id=ticket_data["ticket_id"],
                url=url,
                error=str(ssrf_err),
            )
            return

        payload = {
            "ticket_id": ticket_data["ticket_id"],
            "status": ticket_data["status"],
            "action": ticket_data["action_name"],
            "effective_parameters": ticket_data.get("modified_parameters") or ticket_data.get("original_parameters"),
            "approved_by": ticket_data.get("approved_by"),
            "rejected_by": ticket_data.get("rejected_by"),
            "decision_notes": ticket_data.get("decision_notes"),
            "timestamp": datetime.datetime.utcnow().isoformat(),
        }

        body_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        sig = hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()

        headers = {
            "Content-Type": "application/json",
            "X-Aegis-Signature": f"sha256={sig}",
            "X-Aegis-Ticket-Id": ticket_data["ticket_id"],
        }

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(url, content=body_bytes, headers=headers)
                logger.info(
                    "hitl_callback_delivered",
                    ticket_id=ticket_data["ticket_id"],
                    url=url,
                    status_code=resp.status_code,
                )
        except Exception as e:
            logger.error(
                "hitl_callback_failed",
                ticket_id=ticket_data["ticket_id"],
                url=url,
                error=str(e),
            )


# Global singleton instance for easy access across gateways and PDP API
_global_hitl_engine: HITLEngine | None = None


def get_hitl_engine() -> HITLEngine:
    global _global_hitl_engine
    if _global_hitl_engine is None:
        _global_hitl_engine = HITLEngine()
    return _global_hitl_engine
