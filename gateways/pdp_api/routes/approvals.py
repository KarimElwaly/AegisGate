from fastapi import APIRouter, Depends, HTTPException, Query

from core.auth.dependencies import AuthenticatedActor, get_pdp_actor
from core.hitl.engine import get_hitl_engine
from core.hitl.schemas import ApprovalDecisionRequest, ApprovalTicketResponse

router = APIRouter(prefix="/v1/approvals", tags=["Human-in-the-Loop Approvals"])


@router.get("", response_model=list[ApprovalTicketResponse])
async def list_approvals(
    tenant_id: str | None = Query(default=None, description="Tenant ID"),
    status: str | None = Query(default=None, description="Filter by status (pending, approved, rejected, expired)"),
    actor: AuthenticatedActor = Depends(get_pdp_actor),
) -> list[ApprovalTicketResponse]:
    """Lists approval tickets for a tenant."""
    effective_tenant = actor.tenant_id
    if actor.role == "SuperAdmin" and tenant_id:
        effective_tenant = tenant_id
    elif tenant_id and tenant_id != actor.tenant_id and actor.role != "SuperAdmin":
        raise HTTPException(status_code=403, detail="Cross-tenant access forbidden")

    engine = get_hitl_engine()
    return await engine.list_tickets(tenant_id=effective_tenant, status=status)


@router.get("/{ticket_id}", response_model=ApprovalTicketResponse)
async def get_approval(
    ticket_id: str,
    actor: AuthenticatedActor = Depends(get_pdp_actor),
) -> ApprovalTicketResponse:
    """Fetches details of a specific approval ticket."""
    engine = get_hitl_engine()
    ticket = await engine.get_ticket(ticket_id)
    if not ticket:
        raise HTTPException(status_code=404, detail=f"Approval ticket '{ticket_id}' not found")
    if actor.role != "SuperAdmin" and ticket.tenant_id != actor.tenant_id:
        raise HTTPException(status_code=403, detail="Cross-tenant access forbidden")
    return ticket


@router.post("/{ticket_id}/decide", response_model=ApprovalTicketResponse)
async def decide_approval(
    ticket_id: str,
    decision_req: ApprovalDecisionRequest,
    actor: AuthenticatedActor = Depends(get_pdp_actor),
) -> ApprovalTicketResponse:
    """
    Submits a human decision (approve or reject) for an approval ticket.
    Supports dual-approval (4-eyes) and parameter overrides.
    """
    engine = get_hitl_engine()
    ticket = await engine.get_ticket(ticket_id)
    if not ticket:
        raise HTTPException(status_code=404, detail=f"Approval ticket '{ticket_id}' not found")
    if actor.role != "SuperAdmin" and ticket.tenant_id != actor.tenant_id:
        raise HTTPException(status_code=403, detail="Cross-tenant access forbidden")

    try:
        updated = await engine.decide_ticket(ticket_id=ticket_id, decision_req=decision_req)
        return updated
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except PermissionError as pe:
        raise HTTPException(status_code=403, detail=str(pe))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Internal decision error: {exc!s}")
