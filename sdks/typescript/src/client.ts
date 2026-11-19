import { EvaluationRequest, EvaluationVerdict, ApprovalTicket } from "./types.js";

export interface AegisClientOptions {
  baseUrl?: string;
  apiKey?: string;
  tenantId?: string;
  workspaceId?: string;
  policyPackId?: string;
  failOpen?: boolean;
  timeoutMs?: number;
}

export class AegisClient {
  private baseUrl: string;
  private apiKey?: string;
  private tenantId: string;
  private workspaceId: string;
  private policyPackId: string;
  private failOpen: boolean;
  private timeoutMs: number;

  constructor(options: AegisClientOptions = {}) {
    this.baseUrl = (options.baseUrl || "http://localhost:8000").replace(/\/+$/, "");
    this.apiKey = options.apiKey;
    this.tenantId = options.tenantId || "default";
    this.workspaceId = options.workspaceId || "default";
    this.policyPackId = options.policyPackId || "base-enterprise";
    this.failOpen = options.failOpen || false;
    this.timeoutMs = options.timeoutMs || 5000;
  }

  private getHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "X-Aegis-Tenant-Id": this.tenantId,
      "X-Aegis-Workspace-Id": this.workspaceId,
      "X-Aegis-Policy-Pack": this.policyPackId,
    };
    if (this.apiKey) {
      headers["Authorization"] = `Bearer ${this.apiKey}`;
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
      metadata: request.metadata || {},
      ...request,
    };

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(`${this.baseUrl}/v1/evaluate`, {
        method: "POST",
        headers: this.getHeaders(),
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

  public async pollApproval(
    ticketId: string,
    intervalMs: number = 1000,
    maxWaitMs: number = 30000
  ): Promise<ApprovalTicket> {
    const startTime = Date.now();
    while (Date.now() - startTime < maxWaitMs) {
      const resp = await fetch(`${this.baseUrl}/v1/approvals/${ticketId}`, {
        headers: this.getHeaders(),
      });
      if (resp.ok) {
        const ticket = (await resp.json()) as ApprovalTicket;
        if (ticket.status !== "pending") {
          return ticket;
        }
      }
      await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }
    throw new Error(`Approval ticket ${ticketId} timed out after ${maxWaitMs}ms`);
  }
}

