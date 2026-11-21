import { EvaluationRequest, EvaluationVerdict, ApprovalTicket } from "./types.js";

export interface AegisClientOptions {
  baseUrl?: string;
  apiKey?: string;
  virtualApiKey?: string;
  tenantId?: string;
  workspaceId?: string;
  policyPackId?: string;
  failOpen?: boolean;
  timeoutMs?: number;
}

export interface WaitForApprovalOptions {
  intervalMs?: number;
  maxWaitMs?: number;
  onStatusChange?: (ticket: ApprovalTicket) => void;
}

export interface WrapToolOptions {
  actorId?: string;
  actorRole?: string;
  sessionId?: string;
  policyPackId?: string;
}

export class AegisClient {
  private baseUrl: string;
  private apiKey?: string;
  private virtualApiKey?: string;
  private tenantId: string;
  private workspaceId: string;
  private policyPackId: string;
  private failOpen: boolean;
  private timeoutMs: number;

  constructor(options: AegisClientOptions = {}) {
    this.baseUrl = (options.baseUrl || "http://localhost:8000").replace(/\/+$/, "");
    this.apiKey = options.apiKey;
    this.virtualApiKey = options.virtualApiKey;
    this.tenantId = options.tenantId || "default";
    this.workspaceId = options.workspaceId || "default";
    this.policyPackId = options.policyPackId || "base-enterprise";
    this.failOpen = options.failOpen || false;
    this.timeoutMs = options.timeoutMs || 5000;
  }

  public getHeaders(additionalHeaders?: Record<string, string>): Record<string, string> {
    const key = this.virtualApiKey || this.apiKey;
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "X-Aegis-Tenant-Id": this.tenantId,
      "X-Aegis-Workspace-Id": this.workspaceId,
      "X-Aegis-Policy-Pack": this.policyPackId,
      ...additionalHeaders,
    };
    if (key) {
      headers["Authorization"] = `Bearer ${key}`;
      if (key.startsWith("ag_live_") || key.startsWith("aegis_live_")) {
        headers["X-Aegis-Api-Key"] = key;
      }
    }
    return headers;
  }

  public async evaluate(request: Partial<EvaluationRequest>): Promise<EvaluationVerdict> {
    const payload: EvaluationRequest = {
      tenant_id: request.tenant_id || this.tenantId,
      workspace_id: request.workspace_id || this.workspaceId,
      policy_pack_id: request.policy_pack_id || this.policyPackId,
      stage: request.stage || "llm_input",
      actor: request.actor || { id: "ts-sdk-actor", role: "worker" },
      action: request.action || { name: "default_action" },
      content: request.content || {},
      session_taints: request.session_taints,
      declared_scope: request.declared_scope,
      metadata: request.metadata || {},
      ...request,
    };

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    const headers = this.getHeaders();
    if (payload.actor?.agent_token) {
      headers["X-Aegis-Agent-Token"] = payload.actor.agent_token;
    }

    try {
      const response = await fetch(`${this.baseUrl}/v1/evaluate`, {
        method: "POST",
        headers,
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`AegisGate PDP evaluate returned HTTP ${response.status}`);
      }

      const verdict = (await response.json()) as EvaluationVerdict;
      return verdict;
    } catch (error) {
      if (this.failOpen) {
        return {
          verdict_id: "fail-open-fallback",
          decision: "ALLOW",
          effective_mode: "enforce",
          would_have_decided: "ALLOW",
          risk_score: 0.0,
          triggered_rules: [],
          scanner_findings: [],
          resolved_context: {},
          latency_ms: 0,
        };
      }
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }

  public async waitForApproval(
    ticketId: string,
    options: WaitForApprovalOptions = {}
  ): Promise<ApprovalTicket> {
    const intervalMs = options.intervalMs || 1000;
    const maxWaitMs = options.maxWaitMs || 30000;
    const startTime = Date.now();

    while (Date.now() - startTime < maxWaitMs) {
      const resp = await fetch(`${this.baseUrl}/v1/approvals/${ticketId}`, {
        headers: this.getHeaders(),
      });
      if (resp.ok) {
        const ticket = (await resp.json()) as ApprovalTicket;
        if (options.onStatusChange) {
          options.onStatusChange(ticket);
        }
        if (ticket.status !== "pending") {
          return ticket;
        }
      }
      await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }
    throw new Error(`Approval ticket ${ticketId} timed out after ${maxWaitMs}ms`);
  }

  public async pollApproval(
    ticketId: string,
    intervalMs: number = 1000,
    maxWaitMs: number = 30000
  ): Promise<ApprovalTicket> {
    return this.waitForApproval(ticketId, { intervalMs, maxWaitMs });
  }

  public wrapTool<TArgs extends Record<string, unknown>, TResult>(
    toolName: string,
    fn: (args: TArgs) => Promise<TResult> | TResult,
    options: WrapToolOptions = {}
  ): (args: TArgs) => Promise<TResult> {
    return async (args: TArgs): Promise<TResult> => {
      // 1. Evaluate tool_pre_call
      const preVerdict = await this.evaluate({
        stage: "tool_pre_call",
        session_id: options.sessionId,
        policy_pack_id: options.policyPackId || this.policyPackId,
        actor: {
          id: options.actorId || "ts-agent-worker",
          role: options.actorRole || "tool_caller",
        },
        action: {
          name: toolName,
          parameters: args,
        },
      });

      if (preVerdict.decision === "DENY") {
        const reason = preVerdict.triggered_rules[0]?.reason || "Tool pre-call blocked by policy";
        throw new Error(`AegisGate Policy Denied tool '${toolName}': ${reason}`);
      }

      if (preVerdict.decision === "SUSPEND_FOR_APPROVAL" && preVerdict.approval_ticket?.ticket_id) {
        const resolvedTicket = await this.waitForApproval(preVerdict.approval_ticket.ticket_id);
        if (resolvedTicket.status !== "approved") {
          throw new Error(`Tool execution rejected by HITL: status=${resolvedTicket.status}`);
        }
      }

      const effectiveArgs = (preVerdict.mutated_parameters as TArgs) || args;
      const result = await fn(effectiveArgs);

      // 2. Evaluate tool_post_call
      const postVerdict = await this.evaluate({
        stage: "tool_post_call",
        session_id: options.sessionId,
        policy_pack_id: options.policyPackId || this.policyPackId,
        actor: {
          id: options.actorId || "ts-agent-worker",
          role: options.actorRole || "tool_caller",
        },
        action: {
          name: toolName,
        },
        content: {
          output_payload: result,
        },
      });

      if (postVerdict.decision === "DENY") {
        const reason = postVerdict.triggered_rules[0]?.reason || "Tool post-call blocked by policy";
        throw new Error(`AegisGate Policy Denied output of '${toolName}': ${reason}`);
      }

      return (postVerdict.mutated_content as TResult) || result;
    };
  }
}
