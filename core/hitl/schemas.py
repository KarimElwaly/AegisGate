from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ApprovalDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    approver_id: str = Field(..., description="Unique ID of the human approver")
    approver_role: str = Field(..., description="Role of the human approver (e.g. security_lead, admin)")
    decision: str = Field(..., description="'approve' or 'reject'")
    parameter_override: dict[str, Any] | None = Field(
        default=None,
        description="Optional sanitized/modified parameters replacing original action parameters",
    )
    decision_notes: str | None = Field(default="", description="Optional justification or notes")


class ApprovalTicketResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    ticket_id: str
    tenant_id: str
    workspace_id: str
    trace_id: str
    session_id: str | None = None
    policy_pack_id: str
    status: str  # pending | approved | rejected | expired
    risk_score: float
    action_name: str
    original_parameters: dict[str, Any]
    modified_parameters: dict[str, Any] | None = None
    triggered_rules: list[dict[str, Any]]
    resolved_context: dict[str, Any]
    required_approvals: int
    required_approver_roles: list[str]
    approved_by: list[str]
    rejected_by: str | None = None
    decision_notes: str | None = None
    callback_url: str | None = None
    expires_at: str
    created_at: str
    updated_at: str

