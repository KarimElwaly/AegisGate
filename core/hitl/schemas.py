import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ApprovalDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    approver_id: str = Field(..., description="Unique ID of the human approver")
    approver_role: str = Field(..., description="Role of the human approver (e.g. security_lead, admin)")
    decision: str = Field(..., description="'approve' or 'reject'")
    parameter_override: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional sanitized/modified parameters replacing original action parameters",
    )
    decision_notes: Optional[str] = Field(default="", description="Optional justification or notes")


class ApprovalTicketResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    ticket_id: str
    tenant_id: str
    workspace_id: str
    trace_id: str
    session_id: Optional[str] = None
    policy_pack_id: str
    status: str  # pending | approved | rejected | expired
    risk_score: float
    action_name: str
    original_parameters: Dict[str, Any]
    modified_parameters: Optional[Dict[str, Any]] = None
    triggered_rules: List[Dict[str, Any]]
    resolved_context: Dict[str, Any]
    required_approvals: int
    required_approver_roles: List[str]
    approved_by: List[str]
    rejected_by: Optional[str] = None
    decision_notes: Optional[str] = None
    callback_url: Optional[str] = None
    expires_at: str
    created_at: str
    updated_at: str
