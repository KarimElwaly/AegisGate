
from fastapi import APIRouter, HTTPException, Query

from core.hitl.engine import get_hitl_engine
from core.hitl.schemas import ApprovalDecisionRequest, ApprovalTicketResponse

router = APIRouter(prefix="/v1/approvals", tags=["Human-in-the-Loop Approvals"])


@router.get("", response_model=list[ApprovalTicketResponse])
async def list_approvals(
    tenant_id: str = Query(default="default", description="Tenant ID"),
    status: str | None = Query(default=None, description="Filter by status (pending, approved, rejected, expired)"),
) -> list[ApprovalTicketResponse]:
    """Lists approval tickets for a tenant."""
    engine = get_hitl_engine()
    return await engine.list_tickets(tenant_id=tenant_id, status=status)


@router.get("/{ticket_id}", response_model=ApprovalTicketResponse)
async def get_approval(ticket_id: str) -> ApprovalTicketResponse:
    """Fetches details of a specific approval ticket."""
    engine = get_hitl_engine()
    ticket = await engine.get_ticket(ticket_id)
    if not ticket:
        raise HTTPException(status_code=404, detail=f"Approval ticket '{ticket_id}' not found")
    return ticket


@router.post("/{ticket_id}/decide", response_model=ApprovalTicketResponse)
async def decide_approval(
    ticket_id: str,
    decision_req: ApprovalDecisionRequest,
) -> ApprovalTicketResponse:
    """
    Submits a human decision (approve or reject) for an approval ticket.
    Supports dual-approval (4-eyes) and parameter overrides.
    """
    engine = get_hitl_engine()
    try:
        updated = await engine.decide_ticket(ticket_id=ticket_id, decision_req=decision_req)
        return updated
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except PermissionError as pe:
        raise HTTPException(status_code=403, detail=str(pe))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Internal decision error: {exc!s}")

