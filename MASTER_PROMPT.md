# ROLE & MISSION
You are a Principal Systems Architect and Staff Full-Stack/AI Security Engineer. Your mission is to design, implement, test, and package **AegisGate** — a standalone, commercial-grade, domain-agnostic **AI Guardrails & Governance Platform** built to be sold as an independent enterprise product and plugged in front of ANY AI system (Multi-Agent Fleets, Log Analysis pipelines, SOC Investigation agents, RAG systems, Voice/Copilot apps, or custom LLM workflows) without changing a single line of core engine code.

---

# 1. NON-NEGOTIABLE ARCHITECTURAL LAWS
You MUST enforce these laws across every file you write:

1. **Strict Separation of Mechanism from Policy:**
   - `core/` MUST contain **zero** domain-specific logic (no hardcoded SOC, SIEM, Log Analysis, Finance, or Agent-Framework assumptions).
   - Never import directly from `plugins/` or `policy_packs/` inside `core/pipeline/`. All scanners, context resolvers, policy engines, and notifiers MUST be loaded dynamically through `core/registry/PluginRegistry`.
2. **Extensibility by Design (Plug-and-Play Control):**
   - Operators must be able to add, edit, version, enable, disable, or hot-reload any Guardrail Scanner, Governance Rule, Policy Pack, Context Resolver, Budget, or Notifier via YAML, REST API, or the Admin UI without restarting services.
   - Every plugin MUST expose a Pydantic `ConfigSchema` so configuration is dynamically validated and auto-renderable in the Admin UI.
   - Support both **in-process Python plugins** (drop-in modules) and **out-of-process HTTP Webhook plugins** (so teams can add custom scanners/resolvers in any language).
3. **Dual Integration Surface (Framework-Agnostic, Zero Lock-In):**
   - **Zero-Code Proxy Mode (Primary):** OpenAI-compatible LLM Reverse Proxy (`/proxy/llm/v1/*`) + MCP & HTTP Tool Gateway Proxy (`/proxy/mcp/*`, `/proxy/tools/*`). Any existing AI system integrates simply by routing its LLM base URL and Tool/MCP endpoints through AegisGate.
   - **Direct PDP Mode:** Sub-15ms REST Policy Decision Point (`POST /v1/evaluate`) + thin Python and TypeScript SDKs for custom orchestrator hooks.
4. **Trusted Instructions vs. Untrusted Data Boundary:**
   - Every evaluation separates `trusted_instructions` (system/developer intent) from `untrusted_data` (raw server logs, SIEM alerts, scraped web pages, tool outputs, retrieved RAG chunks).
   - Guardrails MUST detect **Indirect Prompt Injection** embedded inside `untrusted_data` WITHOUT triggering false positives on benign technical/security content (e.g., `rm -rf`, `CVE-2025-xxxx`, `SQL injection`, `exploit`, `powershell -enc` appearing legitimately inside logs being analyzed).
5. **Local-First & Data-Sovereign by Default:**
   - Runs 100% self-hosted via Docker Compose with zero mandatory external cloud dependencies.
   - Tier-1 deterministic checks and Tier-2 ONNX/local ML classifiers run locally; Tier-3 LLM-as-a-Judge targets configurable local OpenAI-compatible endpoints (Ollama, vLLM, LM Studio) with cloud providers strictly optional.
6. **Commercial Multi-Tenant & Fail-Safe Readiness:**
   - Strict tenant isolation (`tenant_id` -> `workspace_id` -> `environment`) across DB queries, Redis keys, API keys, and audit logs.
   - Full policy lifecycle: `draft` -> `shadow` -> `active` -> `archived` with 1-click rollback.
   - Configurable execution modes per tenant/policy pack: `ENFORCE`, `SHADOW` (records `WOULD_BLOCK` / `WOULD_MODIFY` without interrupting live traffic), `FAIL_OPEN`, and `FAIL_CLOSED`.

---

# 2. TECH STACK
- **Core Engine & Gateways:** Python 3.11+, FastAPI, Pydantic v2, AsyncIO, HTTPX (pooled async client).
- **Database & Migrations:** PostgreSQL 16, SQLAlchemy 2.0 (asyncpg), Alembic (never use `create_all()` in production paths).
- **State, Budgets, Circuit Breakers & Cache:** Redis 7 (with atomic Lua scripts for quotas, sliding-window loop detection, and sub-millisecond kill switches).
- **Tier-2 Local ML:** ONNX Runtime (CPU/CUDA auto-fallback) behind an abstract classifier wrapper + deterministic lightweight fallback for CI/offline dev.
- **Policy Evaluation:** Built-in declarative YAML Policy DSL behind a `PolicyEngineInterface` + pluggable OPA/Rego HTTP adapter for enterprise deployments.
- **Admin Control Plane UI:** React 18 + TypeScript + Vite + Tailwind CSS (communicating strictly through Control Plane REST/WebSocket APIs).
- **Observability:** OpenTelemetry (OTLP traces & metrics), Prometheus `/metrics`, structured JSON logging (`structlog`).
- **Packaging:** Monorepo with one-command `docker-compose.yml`, multi-stage Dockerfiles, `.env.example`, and OpenAPI specs.

---

# 3. REPOSITORY STRUCTURE
Create and adhere to this clean monorepo layout:

```text
aegisgate/
├── core/
│   ├── schemas/               # Canonical Event, Verdict, Policy DSL, Tenant, HITL, Audit Pydantic models
│   ├── pipeline/              # Tiered Pipeline Orchestrator (parallel tiers, timeouts, short-circuit, shadow mirror)
│   ├── policy_engine/         # PolicyEngineInterface, Native YAML DSL Evaluator, OPA/Rego Adapter
│   ├── registry/              # Dynamic PluginRegistry (Scanners, Context Resolvers, Notifiers, Vaults)
│   ├── governance/            # RBAC/ABAC, Delegation Chain Validator, Redis Budgets, Loop Detector, Kill Switch
│   ├── hitl/                  # Suspend-and-Resume Approval Engine (Single/Dual approval, TTL, Parameter Override)
│   ├── audit/                 # Append-Only Cryptographic Hash-Chained Ledger, Integrity Verifier, Compliance Exporter
│   ├── pii_vault/             # Ephemeral Reversible PII/Secret Tokenization & Re-hydration Vault
│   └── tenancy/               # Tenant Isolation, API Key Scoping, Operator Auth (JWT) & RBAC
├── plugins/
│   ├── scanners/
│   │   ├── tier1_deterministic/  # Regex/Secrets, PII+Vault, JSON Schema, Tool Param Guard, SQL/Shell Risk, Entropy/Size
│   │   ├── tier2_local_ml/       # ONNX Prompt Injection / Jailbreak / Untrusted-Data Injection Classifier
│   │   ├── tier3_llm_judge/      # Local/Remote LLM-as-a-Judge (Groundedness, Evidence-ID Verification, Custom Rubric)
│   │   └── webhook_scanner.py    # Generic Remote HTTP Webhook Scanner plugin
│   ├── resolvers/             # BaseContextResolver, HTTPContextResolver, RedisStateResolver, StaticLookupResolver
│   └── notifiers/             # Webhook, Slack, Teams, SIEM (CEF/Syslog) notifiers
├── gateways/
│   ├── pdp_api/               # /v1/evaluate, /v1/approvals, /v1/simulate, /v1/policies, /v1/plugins, /v1/audit, /v1/kill-switch
│   ├── llm_proxy/             # OpenAI-compatible Reverse Proxy (/proxy/llm/v1/*) with SSE streaming guardrails
│   └── mcp_tool_gateway/      # MCP & HTTP Tool Proxy (/proxy/mcp/*, /proxy/tools/*) with pre-call & post-call hooks
├── policy_packs/              # Versioned pluggable YAML Policy Packs (strictly outside core/)
│   ├── base-enterprise/
│   ├── agent-fleet-pack/
│   ├── log-analysis-pack/
│   └── soc-investigation-pack/
├── sdks/
│   ├── python/                # Async/Sync client + @governed_tool and @governed_llm decorators
│   └── typescript/            # Typed TypeScript client
├── dashboard/                 # React + TypeScript Admin Control Plane UI
├── migrations/                # Alembic migrations
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── redteam/               # Indirect prompt injection & false-positive benchmark suite
│   └── benchmarks/            # P50/P95 latency benchmarks
├── deploy/                    # docker-compose.yml, Dockerfiles, prometheus.yml, .env.example
└── pyproject.toml
```

---

# 4. CANONICAL DATA CONTRACTS (IMPLEMENT FIRST)

### 4.1 `EvaluationRequest`
All gateways (LLM Proxy, MCP Proxy, Direct API, SDKs) normalize incoming events into this schema:

```json
{
  "request_id": "uuid",
  "tenant_id": "string",
  "workspace_id": "string",
  "environment": "dev | staging | prod",
  "policy_pack_id": "string",
  "policy_pack_version": "string | latest",
  "trace_id": "string",
  "span_id": "string",
  "session_id": "string",
  "stage": "llm_input | llm_output | tool_pre_call | tool_post_call | agent_handoff | memory_write | rag_retrieval",
  "actor": {
    "id": "string",
    "type": "human | agent | service",
    "role": "string",
    "delegation_chain": ["orchestrator_1", "worker_2"]
  },
  "action": {
    "name": "string",
    "target": "string | null",
    "parameters": {},
    "estimated_tokens": 0,
    "estimated_cost_usd": 0.0
  },
  "content": {
    "trusted_instructions": "string | null",
    "untrusted_data": "string | list | object | null",
    "output_payload": "string | object | null",
    "citations": ["evidence_id_1"]
  },
  "execution_mode_override": "enforce | shadow | null",
  "metadata": {}
}
```

### 4.2 `EvaluationVerdict`

```json
{
  "verdict_id": "uuid",
  "decision": "ALLOW | DENY | MODIFY | SUSPEND_FOR_APPROVAL | ESCALATE",
  "effective_mode": "enforce | shadow",
  "would_have_decided": "ALLOW | DENY | MODIFY | SUSPEND_FOR_APPROVAL | ESCALATE",
  "risk_score": 0.0,
  "mutated_content": null,
  "mutated_parameters": null,
  "redaction_map_ref": "string | null",
  "triggered_rules": [
    {
      "rule_id": "string",
      "policy_pack": "string",
      "policy_version": "string",
      "severity": "low | medium | high | critical",
      "reason": "string",
      "compliance_tags": ["OWASP-LLM01", "NIST-AI-RMF-MANAGE"]
    }
  ],
  "scanner_findings": [],
  "resolved_context": {},
  "budget_snapshot": {
    "tokens_used": 0,
    "tokens_limit": 0,
    "cost_used_usd": 0.0,
    "cost_limit_usd": 0.0,
    "tool_calls_used": 0,
    "tool_calls_limit": 0
  },
  "approval_ticket": {
    "ticket_id": "uuid | null",
    "status": "pending | approved | rejected | expired | null",
    "required_approvals": 1,
    "expires_at": "iso8601 | null"
  },
  "latency_ms": 0.0
}
```

---

# 5. DETAILED FUNCTIONAL SPECIFICATIONS

### 5.1 Tiered Guardrails Pipeline (`core/pipeline/` + `plugins/scanners/`)
- Abstract base class `BaseScanner` defining: `name`, `version`, `tier` (`1 | 2 | 3`), `supported_stages`, `config_schema: type[BaseModel]`, and `async def scan(request, context, config) -> ScannerResult`.
- Scanners within the same tier run concurrently (`asyncio.gather`) with per-scanner timeouts and configurable `on_timeout: allow | deny | flag`.
- **Short-Circuiting:** If a Tier-1 deterministic rule or Kill Switch returns a critical `DENY`, skip Tier-2/Tier-3 immediately.
- **Tier 1 — Deterministic Fast Path (Target: <10ms, Sync Blocking):**
  1. **PII & Secrets Scanner + Reversible Vault:** Detects emails, phone numbers, credit cards, SSNs, IPs, JWTs, AWS/API keys, PEM private keys, bearer tokens. Supports `MASK`, `HASH`, or `REVERSIBLE_TOKENIZE` (e.g., replaces `10.0.1.55` with `<AEGIS_IP_01>` stored in Redis with session TTL, and optionally re-hydrates on `llm_output` for authorized roles).
  2. **JSON Schema Enforcer:** Validates structured `output_payload` or `action.parameters` against JSON Schema defined in the active Policy Pack.
  3. **Tool Parameter & Command Guard:** Validates parameter regexes, CIDR/IP deny/allow ranges (e.g., never block internal DC/gateway subnets), SQL read-only AST/keyword checks, path traversal, and shell metacharacter guards.
  4. **Payload Size, Token & High-Entropy Secret Exfiltration Guard.**
  5. **Evidence/Citation Grounding Check (Deterministic):** Verifies that every citation ID listed in `content.citations` actually exists inside the session's tracked `untrusted_data` / tool outputs.
- **Tier 2 — Fast Local Semantic ML (Target: 15–80ms, Sync for configured stages):**
  1. **ONNX Prompt Injection & Jailbreak Classifier:** Explicitly inspects `untrusted_data` for instruction-override patterns targeting the LLM (Indirect Prompt Injection) while treating domain security strings inside log payloads as benign data unless paired with directive override cues.
  2. **Pluggable Local Model Loader:** Supports configuring any local ONNX text-classification model via YAML/UI; ships with a fast heuristic/lightweight fallback mode when ONNX weights are not mounted so CI and dev boots cleanly.
- **Tier 3 — Deep Semantic Judge (Async Audit by default OR Sync Blocking for critical actions only):**
  1. **LLM-as-a-Judge Plugin:** Calls any configured OpenAI-compatible local/remote endpoint with structured JSON rubric prompts defined inside the Policy Pack (e.g., groundedness check, policy compliance verification, hallucination detection).
- **Generic Webhook Scanner:** Calls any customer-hosted HTTP endpoint with signed HMAC headers so users can plug in proprietary detectors without touching Python code.

### 5.2 Governance Engine (`core/governance/` + `core/policy_engine/`)
- **Declarative YAML Policy Pack DSL:**
  - Supports inheritance (`extends: base-enterprise`), version metadata, execution mode (`enforce | shadow`), scanner configurations, context resolver bindings, budget definitions, and prioritized rules with boolean combinators (`all`, `any`, `not`) over `stage`, `actor`, `action`, `parameters`, `scanner_findings`, and `resolved_context`.
  - **Hot-Reload & Versioning:** Storing/publishing a Policy Pack via API immediately validates the YAML, versions it in PostgreSQL, broadcasts a Redis Pub/Sub invalidation event, and reloads active workers with zero downtime.
  - **OPA/Rego Adapter:** Optional `OPAPolicyEngine` implementing `PolicyEngineInterface` so enterprise clients can delegate complex rules to an OPA server.
- **Context Resolver Plugins (`plugins/resolvers/`):**
  - Enriches runtime evaluation before rules execute, with Redis TTL caching and strict timeout fallback.
  - Implement `HTTPContextResolver` (calls any external CMDB, Asset Inventory, IAM, or Workflow API with templated URL/headers), `RedisStateResolver`, and `StaticLookupResolver`.
- **Budgets, Quotas & Circuit Breakers (Redis Atomic Lua Scripts):**
  - Track and enforce limits per Tenant, Workspace, Session, and Agent: `max_tokens`, `max_cost_usd`, `max_tool_calls`, `max_consecutive_failures`.
  - **Runaway Loop Detector:** Hashes `(session_id, actor.id, action.name, canonical_parameters)` over a configurable sliding window; trips circuit breaker (`DENY` + alert) when threshold is exceeded.
  - **Delegation Governance:** Enforces `max_delegation_depth`, allowed `delegator_role -> delegatee_role` matrices, and prevents privilege escalation (a delegated worker cannot invoke tools denied to the originating actor).
  - **Sub-Millisecond Kill Switch:** Checked first on every request. Supports instant pause/block at `GLOBAL`, `TENANT`, `WORKSPACE`, `AGENT`, or `TOOL` granularity.

### 5.3 Human-in-the-Loop (HITL) Approval Engine (`core/hitl/`)
- When a rule evaluates to `SUSPEND_FOR_APPROVAL`, create a persistent `ApprovalTicket` containing: redacted request context, risk score, triggered rules, resolved context, proposed action & parameters, required approver role(s), `required_approvals` (1 for single approval, 2 for dual-approval / 4-eyes principle), and `expires_at` TTL.
- **Approve with Parameter Override:** Approvers can edit/sanitize `action.parameters` before approving, with both original and modified values recorded in the audit ledger.
- **Resume Mechanisms:**
  1. Async Webhook Callback (signed HMAC POST to caller's callback URL, e.g., Temporal signal or orchestrator webhook).
  2. Polling / Long-Poll API (`GET /v1/approvals/{ticket_id}`).
  3. Optional Synchronous Hold on the proxy/PDP request up to a configurable max wait timeout.

### 5.4 Immutable Tamper-Evident Audit Ledger & Compliance (`core/audit/`)
- Append-only PostgreSQL audit table where each record per tenant computes:
  `record_hash = SHA256(prev_hash || canonical_json(record_payload))`
- Expose `GET /v1/audit/verify` to cryptographically verify chain integrity across a tenant's log range and flag any tampering.
- Store full provenance: `trace_id`, `policy_pack_id`, `policy_pack_version`, `effective_mode`, `decision`, `would_have_decided`, `resolved_context`, `scanner_findings`, `redaction_counts`, `approver_ids`, and stage-by-stage `latency_ms`.
- Support compliance tag filtering (`OWASP-LLM`, `NIST-AI-RMF`, `ISO-42001`, `EU-AI-ACT`, `SOC2`) and export to **JSONL** and **CSV**.

### 5.5 Shadow Mode & Policy Simulation Lab
- **Live Shadow Evaluation:** Attach a `shadow_policy_pack_version` to any workspace; evaluate asynchronously alongside the active pack and record decision deltas (`active_decision != shadow_decision`) for safe rollout.
- **Historical Replay API (`POST /v1/simulate/replay`):** Replay past recorded audit events against any draft Policy Pack and return a diff report (total events, new blocks, false-positive candidates, latency delta).

### 5.6 Integration Gateways & SDKs
1. **OpenAI-Compatible LLM Reverse Proxy (`/proxy/llm/v1/chat/completions`, `/proxy/llm/v1/responses`):**
   - Evaluates `llm_input` (with optional reversible PII tokenization) before forwarding to the tenant's configured upstream LLM (vLLM / Ollama / LM Studio / OpenAI-compatible).
   - Evaluates `llm_output` (including **SSE Streaming Guardrails**: rolling window buffer scanning with mid-stream abort/redaction and optional PII re-hydration).
2. **MCP & HTTP Tool Gateway (`/proxy/mcp/*`, `/proxy/tools/{tool_name}`):**
   - Enforces `tool_pre_call` governance (Kill Switch, RBAC, Delegation, Budgets, Loop Detector, Parameter Guards, HITL) before forwarding to the upstream MCP server or HTTP tool.
   - Enforces `tool_post_call` scanning on returned payloads to catch Indirect Prompt Injection and redact sensitive data before it reaches the LLM context.
3. **Thin SDKs (`sdks/python/`, `sdks/typescript/`):**
   - Python SDK: `AegisClient` (async & sync), `@governed_tool` and `@governed_llm` decorators, automatic `trace_id`/`session_id` propagation, built-in `fail_open`/`fail_closed` handling.
   - TypeScript SDK: Typed client for `/v1/evaluate` and HITL polling.

### 5.7 Admin Control Plane UI (`dashboard/`)
Build a clean, dark-mode-ready enterprise React + TypeScript dashboard with Operator Auth & RBAC (`SuperAdmin`, `TenantAdmin`, `PolicyAuthor`, `Approver`, `Auditor`):
1. **Overview & Telemetry:** KPI cards (requests, block/modify rate, P95 latency, shadow deltas, active HITL queue), real-time event stream, budget burn charts.
2. **Policy Pack Studio:** Browse/create/edit Policy Packs (YAML editor with live schema validation), version history & diff view, promote `draft -> shadow -> active`, 1-click rollback.
3. **Plugin & Scanner Registry:** Toggle scanners per Policy Pack, edit scanner configs via dynamically generated forms from `ConfigSchema`, register custom HTTP Webhook Scanners and Context Resolvers.
4. **HITL Decision Room:** Actionable inbox displaying full risk explanation, resolved asset/workflow context, editable parameters, Approve / Reject / Dual-Approve controls.
5. **Kill Switch & Circuit Breakers:** Immediate emergency toggles per Global / Tenant / Workspace / Agent / Tool with audit reason prompt.
6. **Shadow Simulator & Forensic Audit Explorer:** Filterable audit log table, single-trace timeline drilldown, cryptographic Hash-Chain Integrity Verification button, Replay Simulator runner, and Compliance CSV/JSONL export.

---

# 6. REFERENCE PLUGGABLE POLICY PACKS (PROOF OF GENERALITY)
Author 3 production-realistic YAML Policy Packs inside `policy_packs/` that all run on the exact same untouched `core/`:

1. **`agent-fleet-pack` (Multi-Agent Orchestration):**
   - Inherits `base-enterprise`.
   - Enforces `max_delegation_depth: 3`, role-based tool allowlists, delegator -> delegatee matrix, sliding-window loop circuit breaker (3 identical tool calls in 60s), per-session token/cost caps, and strict JSON handoff schema validation.
2. **`log-analysis-pack` (High-Volume Log Anomaly Analysis):**
   - Separates raw logs into `untrusted_data`; runs Tier-2 Indirect Prompt Injection detection configured to ignore benign technical/error keywords (`rm -rf`, `SQL`, `CVE`, `segfault`) while catching directive override attacks embedded in logs.
   - Applies reversible tokenization for IPs, secrets, and PII before LLM calls; enforces strict JSON anomaly-report output schema; restricts upstream LLM routing to local sovereign endpoints only.
3. **`soc-investigation-pack` (Autonomous SOC Investigation & Containment):**
   - Binds `HTTPContextResolver` (with an included mock Asset Inventory service for E2E testing returning `asset_tier: tier0 | standard` and `is_domain_controller: bool`).
   - Auto-allows read-only SIEM/EDR query tools (`query_siem`, `get_host_telemetry`).
   - Denies containment actions targeting protected CIDR/Domain Controllers outright.
   - Triggers `SUSPEND_FOR_APPROVAL` on containment tools (`block_ip`, `isolate_host`, `disable_user`) — requiring single approval for `standard` assets and dual-approval (2 approvers) for `tier0` assets.
   - Enforces deterministic Evidence-ID citation grounding on final investigation reports + optional Tier-3 LLM-as-a-Judge audit.

---

# 7. PHASED EXECUTION PROTOCOL (STOP-GATE WORKFLOW)
Execute strictly one phase at a time. At the end of EVERY phase:
1. Run all unit, integration, and benchmark tests for that phase.
2. Verify all Definition of Done (DoD) criteria pass with zero skipped/broken tests.
3. Output a concise Phase Completion Report (files created, test results, latency metrics, any assumptions) and **wait for my confirmation** before starting the next phase.

### Phase 1: Foundation, Canonical Schemas, Plugin Registry, Tiered Pipeline & YAML Policy Engine
- Initialize monorepo, `pyproject.toml`, Docker Compose (PostgreSQL 16 + Redis 7), Alembic setup, structured logging.
- Implement Canonical Schemas, `PluginRegistry`, Tiered Pipeline Orchestrator (parallel tiers, timeouts, short-circuit, shadow mode), and `PolicyEngineInterface` + Native YAML DSL Evaluator (with inheritance & hot-reload via Redis Pub/Sub).
- Implement all Tier-1 Deterministic Scanners (Regex/Secrets, PII + Reversible Redis Vault, JSON Schema, Tool Parameter Guard, Entropy/Size, Deterministic Evidence-ID Grounding) + `WebhookScanner`.
- Expose `POST /v1/evaluate` and Policy Pack CRUD / Versioning / Promote / Rollback APIs.
- **DoD:** Unit & integration tests pass with >=85% coverage on `core/`; local benchmark proves Tier-1 P95 evaluation latency < 15ms.

### Phase 2: Governance Engine (Budgets, Loop Detector, RBAC, Delegation, Kill Switch, Context Resolvers)
- Implement Redis Lua atomic Budgets (tokens, USD, tool calls, consecutive failures), Sliding-Window Loop Detector, and Sub-Millisecond Kill Switch API.
- Implement Actor RBAC/ABAC and Delegation Chain privilege-escalation validator.
- Implement `BaseContextResolver`, `HTTPContextResolver`, `RedisStateResolver`, and `StaticLookupResolver` with Redis TTL caching and timeout fallbacks.
- Implement optional `OPAPolicyEngine` adapter behind `PolicyEngineInterface`.
- **DoD:** Integration tests prove atomic budget cutoff, loop circuit-breaker tripping, privilege-escalation denial, instant kill-switch blocking, and Context Resolver caching + timeout failover.

### Phase 3: Integration Gateways (LLM Proxy + MCP/Tool Gateway) & Thin SDKs
- Build OpenAI-compatible LLM Reverse Proxy supporting both standard responses and SSE streaming guardrails (chunk buffering, mid-stream abort/redaction, reversible PII re-hydration).
- Build MCP & HTTP Tool Gateway enforcing `tool_pre_call` and `tool_post_call` scanning.
- Build Python SDK (`@governed_tool`, `@governed_llm`, async/sync client) and TypeScript SDK.
- **DoD:** E2E tests demonstrate an unmodified OpenAI Python client (streaming & non-streaming) and a mock MCP tool server transparently governed through the proxies.

### Phase 4: Tier-2 Local ML Scanners & Tier-3 LLM-as-a-Judge
- Implement `tier2_local_ml` ONNX Runtime scanner wrapper + configurable local model loader + lightweight heuristic fallback for CI.
- Enforce `trusted_instructions` vs. `untrusted_data` boundary detection.
- Implement `tier3_llm_judge` plugin supporting local OpenAI-compatible endpoints (Ollama/vLLM/LM Studio) in both async-audit and sync-critical-gating modes.
- **DoD:** Red-Team test suite (`tests/redteam/`) passes: blocks >=95% of indirect prompt injections hidden inside simulated raw logs while achieving <2% false positives on a benign security-log corpus containing `exploit`, `CVE`, `rm -rf`, `SQLi`, and PowerShell strings.

### Phase 5: HITL Approval Engine, Hash-Chained Audit Ledger, Simulator & 3 Domain Policy Packs
- Implement HITL Approval Engine (tickets, TTL expiration, single/dual approval, parameter override, HMAC webhook callback, polling, optional sync hold).
- Implement Append-Only Cryptographic Hash-Chained Audit Ledger, `GET /v1/audit/verify`, and Compliance Export (JSONL/CSV).
- Implement Live Shadow Mode delta recording and `POST /v1/simulate/replay`.
- Implement Notifier plugins (Webhook, Slack, SIEM CEF/Syslog).
- Author and test all 3 Reference Policy Packs (`agent-fleet-pack`, `log-analysis-pack`, `soc-investigation-pack`) plus a lightweight mock Asset Inventory service for SOC E2E testing.
- **DoD:** Full E2E scenario tests pass for all 3 domains running simultaneously on the exact same untouched `core/`, including HITL suspend-modify-resume and audit chain tamper detection.

### Phase 6: Multi-Tenancy, Auth/RBAC, Observability, Admin Control Plane UI & Commercial Packaging
- Enforce tenant isolation across all DB queries, Redis namespaces, and scoped API keys; implement JWT Operator Auth & RBAC (`SuperAdmin`, `TenantAdmin`, `PolicyAuthor`, `Approver`, `Auditor`).
- Wire OpenTelemetry tracing + Prometheus `/metrics`.
- Build the complete React + TypeScript Admin Control Plane UI (`dashboard/`) covering Overview, Policy Pack Studio, Plugin/Scanner Configurator, HITL Decision Room, Kill Switch Panel, Shadow Simulator, and Audit Explorer.
- Finalize production `docker-compose.yml`, multi-stage Dockerfiles, `.env.example`, seed script (demo tenant + 3 packs), OpenAPI docs, and Quickstart `README.md`.
- **DoD:** `docker compose up --build` boots the full stack cleanly; Playwright/E2E smoke test verifies tenant creation, policy activation, proxied LLM/Tool call, HITL approval in UI, and passing audit hash-chain verification.

---

# 8. ENGINEERING QUALITY STANDARDS
- Strict type hints everywhere (mypy/pyright clean, TypeScript `strict: true`).
- Zero silent failures: every external call (upstream LLM, MCP server, Context Resolver, Webhook) MUST have explicit timeouts, structured error codes, and deterministic fail-open/fail-closed behavior.
- Never log raw unredacted secrets or PII in application logs.
- Use parameterized queries only; protect all webhook callbacks with HMAC-SHA256 signatures.
- Keep functions modular, readable, and well-documented with clear docstrings for extension points.

# START NOW
First, output a brief confirmation of the architecture and directory plan, then immediately begin executing **Phase 1**. Do not move to Phase 2 until Phase 1 tests and benchmarks pass and you have reported the results.