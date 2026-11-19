export interface TelemetryKPIs {
  totalRequests: number;
  blockRate: number;
  modifyRate: number;
  p95LatencyMs: number;
  activeHitlQueue: number;
  shadowDeltasCount: number;
}

export interface PolicyPackSummary {
  pack_id: string;
  version: string;
  name: string;
  status: 'draft' | 'shadow' | 'active' | 'archived';
  description?: string;
  yaml_dsl?: string;
}

export interface PluginItem {
  name: string;
  tier?: number;
  version: string;
  enabled: boolean;
  type: 'scanner' | 'resolver' | 'notifier';
  supported_stages?: string[];
  config_schema?: Record<string, unknown>;
}

export interface ApprovalTicket {
  ticket_id: string;
  tenant_id: string;
  workspace_id: string;
  trace_id: string;
  policy_pack_id: string;
  status: 'pending' | 'approved' | 'rejected' | 'expired';
  risk_score: number;
  action_name: string;
  original_parameters: Record<string, unknown>;
  modified_parameters?: Record<string, unknown>;
  triggered_rules: Array<{ rule_id: string; reason: string; severity?: string; compliance_tags?: string[] }>;
  resolved_context: Record<string, unknown>;
  required_approvals: number;
  required_approver_roles: string[];
  approved_by: string[];
  rejected_by?: string;
  decision_notes?: string;
  expires_at: string;
  created_at: string;
}

export interface AuditRecordItem {
  id: string;
  created_at: string;
  tenant_id: string;
  trace_id: string;
  stage: string;
  decision: string;
  policy_pack_id: string;
  latency_ms: number;
  record_hash: string;
  prev_hash: string;
  compliance_tags: string[];
  action: Record<string, unknown>;
  actor: Record<string, unknown>;
  resolved_context?: Record<string, unknown>;
}

export interface HashVerificationResponse {
  is_valid: boolean;
  total_records: number;
  tampered_records: string[];
  message: string;
}

export interface ReplayReport {
  total_events: number;
  concordant_count: number;
  discordant_count: number;
  concordance_rate: number;
  new_blocks_count: number;
  new_allows_count: number;
  avg_replayed_latency_ms: number;
}

export interface KillSwitchItem {
  scope: string;
  target?: string;
  tenant_id?: string;
  reason?: string;
  activated_at?: string;
  key?: string;
}

