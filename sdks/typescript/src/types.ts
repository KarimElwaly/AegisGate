export type Decision = "ALLOW" | "DENY" | "MODIFY" | "SUSPEND_FOR_APPROVAL" | "ESCALATE";
export type EffectiveMode = "enforce" | "shadow";
export type Stage =
  | "llm_input"
  | "llm_output"
  | "tool_pre_call"
  | "tool_post_call"
  | "agent_handoff"
  | "memory_write"
  | "rag_retrieval";

export interface Actor {
  id: string;
  type?: string;
  role?: string;
  delegation_chain?: string[];
}

export interface Action {
  name: string;
  target?: string | null;
  parameters?: Record<string, unknown>;
  estimated_tokens?: number;
  estimated_cost_usd?: number;
}

export interface Content {
  trusted_instructions?: string | null;
  untrusted_data?: unknown;
  output_payload?: unknown;
  citations?: string[];
}

export interface EvaluationRequest {
  request_id?: string;
  tenant_id: string;
  workspace_id?: string;
  environment?: string;
  policy_pack_id?: string;
  policy_pack_version?: string;
  trace_id?: string;
  span_id?: string | null;
  session_id?: string | null;
  stage: Stage;
  actor: Actor;
  action?: Action;
  content?: Content;
  execution_mode_override?: string | null;
  metadata?: Record<string, unknown>;
}

export interface TriggeredRule {
  rule_id: string;
  policy_pack: string;
  policy_version: string;
  severity: string;
  reason: string;
  compliance_tags: string[];
}

export interface ScannerFinding {
  scanner_name: string;
  tier: number;
  status: string;
  score: number;
  details?: Record<string, unknown>;
  message?: string | null;
}

export interface ApprovalTicket {
  ticket_id?: string | null;
  status?: string | null;
  required_approvals?: number;
  expires_at?: string | null;
}

export interface EvaluationVerdict {
  verdict_id: string;
  decision: Decision;
  effective_mode: EffectiveMode;
  would_have_decided: Decision;
  risk_score: number;
  mutated_content?: unknown;
  mutated_parameters?: Record<string, unknown> | null;
  triggered_rules: TriggeredRule[];
  scanner_findings: ScannerFinding[];
  resolved_context: Record<string, unknown>;
  approval_ticket?: ApprovalTicket | null;
  latency_ms: number;
}

