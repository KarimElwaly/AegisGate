# AegisGate v2 Upgrade Plan (Phases 7–10)

## 0. Mandatory Pre-Flight Audit & Engineering Laws
Before writing or modifying ANY code in a phase, you MUST inspect the existing repository implementation (`PROGRESS.md`, `core/`, `gateways/`, `plugins/`, `migrations/`, `dashboard/`, `tests/`) so you extend existing patterns cleanly instead of duplicating code.

Enforce these non-negotiable rules throughout Phases 7–10:
1. **Strict Backward Compatibility:** Do NOT break existing Phase 1–6 API contracts (`/v1/evaluate`, `/proxy/llm/v1/*`, `/proxy/mcp/*`, `/v1/policies`, `/v1/approvals`, `/v1/audit`, `/v1/kill-switch`), existing YAML Policy Packs, or existing tests. Never weaken or skip existing assertions.
2. **Zero Domain Logic in `core/`:** Keep `core/` 100% domain-agnostic. Never import directly from `plugins/` or `policy_packs/` inside `core/pipeline/`; resolve everything via `PluginRegistry`.
3. **Database Hygiene:** All schema changes MUST use incremental Alembic migrations continuing from the current migration head. Never use `create_all()` in production code.
4. **Dynamic Config Schemas:** Every new scanner, resolver, or plugin MUST expose a Pydantic `ConfigSchema` so the API and Admin UI can validate and render it dynamically.
5. **Audit-Before-Build:** If a requested feature is already partially implemented in v1, upgrade and harden the existing module cleanly rather than creating parallel implementations.
6. **Stop-Gate Discipline:** Execute strictly ONE phase at a time. Run the full regression suite (`pytest`) plus the new phase's DoD tests, update `PROGRESS.md`, and STOP for review and git commit before starting the next phase.

---

## Phase 7 (P0): Core Refactoring, Real Multi-Tenancy & Dynamic Plugin Control

### 7.1 Modularize Pipeline Orchestrator
- Inspect `core/pipeline/orchestrator.py` and decompose its responsibilities into composable, independently testable stage modules under `core/pipeline/stages/`:
  - `kill_switch_stage.py`
  - `identity_delegation_stage.py`
  - `context_resolution_stage.py`
  - `tiered_scanner_stage.py`
  - `policy_evaluation_stage.py`
  - `budget_circuit_stage.py`
  - `hitl_escalation_stage.py`
  - `audit_shadow_stage.py`
- Keep `orchestrator.py` focused strictly on stage sequencing, short-circuiting, fail-open/fail-closed error handling, and per-stage latency tracking.

### 7.2 Real Multi-Tenancy, Workspaces, Virtual API Keys & Budget API
- Add SQLAlchemy models under `core/models/tenant.py`: `Tenant`, `Workspace`, and `VirtualAPIKey` (storing hashed keys with prefix `ag_live_...`, `tenant_id`, `workspace_id`, `environment`, `default_policy_pack_id`, `allowed_models`, `budget_cap_usd`, `rate_limit_rpm`, `revoked_at`, `expires_at`).
- Create an Alembic migration for the new tables while preserving backward compatibility for existing seeded/test tenants.
- Implement `core/tenancy/` dependency/middleware to authenticate Virtual API Keys on PDP and Proxy routes and strictly enforce tenant isolation on all DB queries, Redis keys, and audit lookups.
- Add Control Plane routes under `gateways/pdp_api/routes/`:
  - `tenants.py`: CRUD for tenants and workspaces.
  - `api_keys.py`: Issue (return plaintext once), list, rotate, and revoke Virtual API Keys.
  - `budgets.py`: Inspect live Redis token/cost/call usage, update workspace quotas, and manually reset tripped loop circuit-breakers.

### 7.3 Dynamic Plugin & Config Management API
- Add a `PluginConfig` DB model + Alembic migration to persist dynamic plugin instances (custom `WebhookScanner`, `HTTPContextResolver`, custom Notifiers) and per-workspace scanner parameter overrides, synced across workers via Redis Pub/Sub hot-reload.
- Expand `gateways/pdp_api/routes/plugins.py` with:
  - `GET /v1/plugins/schemas` (exports JSON Schema from every plugin's `ConfigSchema`)
  - `POST /v1/plugins/instances` & `DELETE /v1/plugins/instances/{id}` (register/remove webhook scanners and HTTP context resolvers dynamically)
  - `PATCH /v1/plugins/{id}/config` (update and hot-reload scanner/plugin config)
  - `POST /v1/plugins/{id}/test` (dry-run / health-check test ping)

### 7.4 Standalone Python SDK Packaging
- Add `sdks/python/pyproject.toml` with minimal runtime dependencies (`httpx`, `pydantic`) so `sdks/python` installs cleanly as a standalone package (`pip install -e sdks/python`) without server dependencies.

### Phase 7 Definition of Done
- All Phase 1–6 tests pass with zero regressions; Tier-1 P95 latency remains < 15ms.
- Integration tests prove: cross-tenant isolation (Tenant A Virtual Key cannot access Tenant B policies/audits), Virtual Key revocation works immediately, dynamic Webhook Scanner registration hot-reloads without restart, and `sdks/python` installs and imports cleanly.

---

## Phase 8 (P1): Protocol-Aware MCP Gateway & Stateful Agentic Governance

### 8.1 Protocol-Aware MCP Gateway (`gateways/mcp_tool_gateway/`)
- Upgrade the MCP gateway to handle JSON-RPC 2.0 over Streamable HTTP / SSE:
  - **Upstream MCP Server Registry:** DB model + API to register upstream MCP servers per workspace (URL, auth headers, status).
  - **`tools/list` Interception & Role Filtering:** Filter out unauthorized tools based on actor role/Policy Pack *before* returning the tool catalog to the LLM/agent.
  - **Tool Schema & Description Pinning (Anti-Rug-Pull):** Store `SHA-256` hashes of approved tool schemas/descriptions. If an upstream MCP server silently modifies a tool description or input schema, block execution, quarantine the tool, and emit a critical alert/audit event.
  - **`tools/call` Governance:** Preserve pre-call governance (Kill Switch, RBAC, Budgets, Loop Detector, Parameter Guards, HITL) and post-call indirect injection scanning.

### 8.2 Stateful Session Taint Tracking & Toxic Tool-Chain Policies
- Implement `core/governance/taint_tracker.py` using Redis Sets with session TTL (`aegis:taint:{tenant}:{session_id}`).
- Extend the YAML Policy DSL (`core/policy_engine/yaml_engine.py`) with:
  - `add_taints`: rules or scanners attach labels (e.g., `confidential_read`, `untrusted_external_data`, `pii_accessed`).
  - Taint predicates (`session.taints contains_any / contains_all`) so policies can block toxic multi-step tool chains (e.g., reading confidential data followed by external email/HTTP/shell exfiltration) without domain hardcoding.
  - Optional `session.declared_scope` field to flag out-of-scope tool calls (goal drift detection).

### 8.3 Cryptographic Agent Identity & Signed Delegation Verification
- Add `core/auth/agent_identity.py` to mint and verify short-lived signed Agent JWTs (encoding `agent_id`, `role`, `allowed_tools`, `parent_jti`).
- Upgrade `core/governance/delegation.py` with a policy toggle `require_signed_delegation: true` that cryptographically verifies the delegation chain and enforces **monotonic permission attenuation** (child agent permissions are strictly the intersection of its role and its delegator's scopes).

### Phase 8 Definition of Done
- E2E MCP tests prove: unauthorized tools are stripped from `tools/list`, mutating an upstream tool description triggers an automatic rug-pull block, and `tools/call` runs pre/post checks.
- Stateful tests prove: two individually allowed tools (`read_secret` + `external_post`) trigger `DENY` when executed sequentially in the same session via taint rules.
- Security tests prove forged `actor.role` or escalated `delegation_chain` payloads are rejected when signed delegation is required.

---

## Phase 9 (P2): True Domain Generalization (RAG, Memory, NER & LLM Routing)

### 9.1 RAG Retrieval & Long-Term Memory Guardrails
- Add `plugins/scanners/tier1_deterministic/rag_acl_guard.py`: Enforces chunk-level metadata ACLs (`tenant_id`, `clearance_level`, `allowed_roles`) on `rag_retrieval`, stripping unauthorized chunks (`MODIFY`) before context assembly.
- Add `plugins/scanners/tier1_deterministic/memory_poison_guard.py`: Scans `memory_write` payloads to block embedded directive overrides, unauthorized role claims, and unredacted secrets/PII from persisting into long-term agent memory.

### 9.2 Expanded Tier-2 Local Classifiers & Contextual NER PII
- Add `plugins/scanners/tier2_local_ml/ner_pii_scanner.py`: Pluggable ONNX NER / Presidio adapter catching unstructured PII (names, organizations, addresses) missed by regex, wired into `core/pii_vault/vault.py` for reversible tokenization (with lightweight offline/CI fallback).
- Add `plugins/scanners/tier2_local_ml/topic_guard.py`: Configurable `allowed_topics` / `forbidden_topics` semantic boundary guard.
- Add `plugins/scanners/tier2_local_ml/safety_toxicity_scanner.py`: Local toxicity/safety classifier behind the same pluggable ONNX/fallback interface.

### 9.3 Multi-Provider Sovereignty Routing, Exact Token Reconciliation & Multimodal Hook
- Upgrade `gateways/llm_proxy/`:
  - **Provider Pools & Failover:** Workspace/policy-configurable upstream provider lists (local Ollama/vLLM/LM Studio + optional cloud OpenAI-compatible) with automatic failover on 429/5xx.
  - **Sovereignty-Aware Routing:** Policy directive `route_to_tier: local_only` forces requests containing detected PII/secrets or sensitive session taints strictly to local endpoints.
  - **Exact Token Reconciliation:** Parse actual `usage.prompt_tokens` / `completion_tokens` from responses (and final SSE stream chunks via `stream_options.include_usage`) to reconcile Redis budget counters accurately.
  - **Multimodal Metadata Hook:** Add optional `attachments` (`type`, `mime_type`, `sha256`, `transcript_or_ocr`) to `EvaluationRequest.content` so voice/vision pipelines flow through existing scanners.

### 9.4 Additional General Reference Policy Packs
- Author and test two new packs in `policy_packs/`:
  - `rag-copilot-pack/policy.yaml` (RAG ACL filtering, indirect injection on chunks, NER PII redaction, topic bounds).
  - `customer-support-voice-pack/policy.yaml` (low-latency Tier-1/Tier-2 budget, off-topic/competitor blocking, toxicity guard, HITL approval for account-mutating tools).

### Phase 9 Definition of Done
- Red-team tests confirm memory poisoning is blocked on `memory_write`, unauthorized RAG chunks are stripped on `rag_retrieval`, and NER redacts unstructured names/orgs.
- LLM proxy tests prove exact post-call token reconciliation and automatic `local_only` sovereignty rerouting when sensitive content is present.

---

## Phase 10 (P3): Enterprise Ops, Observability, GitOps CLI & Admin UI Parity

### 10.1 Full Observability Stack
- Instrument pipeline stages, scanners, upstream proxy calls, and Redis governance ops in `core/telemetry.py` with OTLP traces and Prometheus metrics (`aegis_eval_duration_seconds`, `aegis_decisions_total`, `aegis_budget_utilization_ratio`, `aegis_hitl_queue_depth`).
- Add `deploy/prometheus.yml`, `deploy/otel-collector-config.yaml`, and a pre-built Grafana dashboard JSON under `deploy/grafana/`, wired into `deploy/docker-compose.yml` under `--profile observability`.

### 10.2 Shadow AI / Asset Discovery Inventory
- Passively record observed `(actor_id, model_name, mcp_server, tool_name)` tuples from proxies into a `DiscoveredAsset` table, flagging undeclared items as `unregistered_shadow` and exposing `GET /v1/discovery/assets` + approve/block actions.

### 10.3 OIDC SSO, Ecosystem Adapters & `aegisctl` GitOps CLI
- Extend `core/auth/` with optional OIDC JWKS verification (Keycloak / Entra ID / Okta) mapping IdP groups to Operator RBAC roles while keeping local JWT auth intact.
- Add thin drop-in adapters in `sdks/python/aegisgate/adapters/` for **LangGraph**, **FastMCP**, **OpenAI SDK**, and **Temporal** (HITL callback helper).
- Build `cli/aegisctl/` (Typer/Click): `validate`, `test`, `replay`, and `deploy` commands for CI/CD Policy-as-Code workflows.

### 10.4 Admin Control Plane UI Parity (`dashboard/`)
- Add **Login / Auth Gate** (local JWT + optional OIDC button).
- Add **Tenants & Virtual Keys View** (manage tenants/workspaces, mint/revoke virtual keys, model allowlists, budget caps).
- Add **MCP Servers & Shadow AI Discovery View** (approve/pin MCP tool schemas, view rug-pull alerts, govern newly discovered agents/tools).
- Upgrade `PluginRegistryView.tsx` to render dynamic forms from `/v1/plugins/schemas`, register Webhook Scanners/HTTP Resolvers, and run live test pings.
- Add **Live Budget Burn & Circuit-Breaker Reset** controls to the governance UI.

### Phase 10 Definition of Done
- `docker compose --profile observability up --build` boots cleanly with Prometheus/Grafana scraping live metrics.
- `aegisctl validate` and `aegisctl replay` pass against a live engine in tests.
- Updated Playwright E2E script (`scripts/test_ui_backend_integration.mjs`) verifies login, tenant/virtual-key creation, dynamic webhook plugin registration, MCP pinning, taint-chain blocking, and audit verification.