# AegisGate Hardening, Security Self-Defense & v4 Universal Plan (Phases 14–15)

## 0. Mandatory Pre-Flight Audit & Non-Negotiable Laws
Before editing ANY file, inspect the existing implementation thoroughly (`PROGRESS.md`, `core/`, `gateways/`, `plugins/`, `deploy/`, `scripts/`, `dashboard/`, `tests/`). Fix and harden existing modules cleanly—do NOT duplicate logic or break existing features.

Enforce these laws strictly:
1. **Zero Regressions:** All Phase 1–13 unit, integration, red-team, benchmark, TypeScript SDK, and Dashboard tests MUST remain passing without weakening assertions.
2. **Core Isolation:** `core/` MUST remain 100% domain-agnostic. Never import directly from `plugins/` or `policy_packs/` inside `core/pipeline/`; resolve via `PluginRegistry`.
3. **Database Hygiene:** Any schema change MUST use an incremental Alembic migration continuing from `0007_phase13_kms_signatures.py` (`0008_*`). Never call `create_all()` in production code paths.
4. **Security-First Defaults:** Never weaken auth, tenant scoping, or outbound network checks to make a test pass; fix the test fixtures or configuration properly instead.
5. **Real Verification:** Verify Docker builds, Helm template rendering, real cryptographic rotation, and Playwright UI flows—do not rely solely on mocked unit tests.

---

## Phase 14 (v3.2): Security Self-Defense, Production Wiring & Verification Sprint

### 14.1 Gateway Self-Defense Layer (Critical Security Hardening)
1. **Input Canonicalization & De-Obfuscation (`core/pipeline/canonicalizer.py`):**
   - Add a fast, deterministic pre-scanner normalization step wired into `core/pipeline/stages/tiered_scanner_stage.py` (running before Tier-1 and Tier-2 scanners while preserving raw payload for downstream forwarding unless mutated):
     - Strip zero-width & invisible Unicode control characters (e.g., U+200B–U+200F, U+202A–U+202E, U+FEFF).
     - Apply Unicode NFKC homoglyph normalization so visually spoofed characters normalize cleanly.
     - Selectively decode and inspect Base64, Hex, and URL-encoded segments (bounded by max depth=2 and max decoded bytes to prevent zip/expansion bombs) so encoded prompt injections, secrets, and PII cannot bypass scanners.
2. **Outbound SSRF Protection (`core/security/ssrf.py`):**
   - Implement a centralized async URL/IP validator (`validate_outbound_url`) that resolves DNS and blocks loopback (`127.0.0.0/8`, `::1`), link-local / cloud metadata (`169.254.0.0/16`, `fe80::/10`), and private RFC1918/ULA ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`) unless explicitly permitted via `AEGIS_SSRF_ALLOWLIST_CIDRS` (for local dev/self-hosted LAN testing) and blocks non-HTTP(S) schemes and open redirect hops to blocked IPs.
   - Enforce `validate_outbound_url` on registration AND execution across:
     - `plugins/scanners/webhook_scanner.py`
     - `plugins/resolvers/http_resolver.py`
     - `plugins/notifiers/webhook_notifier.py` & `slack_notifier.py`
     - `gateways/mcp_tool_gateway/tool_gateway.py` & `gateways/pdp_api/routes/mcp_servers.py`
     - `gateways/pdp_api/routes/plugins.py` (including `/test` ping endpoints)
3. **Cross-Tenant IDOR Audit & Strict Scoping:**
   - Audit EVERY route in `gateways/pdp_api/routes/` (`approvals.py`, `audit.py`, `budgets.py`, `discovery.py`, `mcp_servers.py`, `plugins.py`, `policies.py`, `simulate.py`, `api_keys.py`, `tenants.py`, `kill_switch.py`).
   - Guarantee `tenant_id` is ALWAYS derived from the authenticated JWT/Virtual API Key context (never overridable by request body or query params unless the caller holds `SuperAdmin`), enforced in every SQL `WHERE` clause and every Redis key namespace.
4. **Streaming Split-Token & ReDoS Hardening:**
   - Audit `gateways/llm_proxy/streaming.py`: ensure chunked SSE scanning maintains a **sliding overlap tail buffer** (e.g., last 128–256 chars carried across chunk boundaries) so secrets (`sk-proj-...`), PII, or forbidden phrases split across two SSE tokens/chunks cannot bypass redaction or mid-stream abort.
   - Audit all Tier-1 regex scanners (`pii_scanner.py`, `secrets_scanner.py`, `tool_param_guard.py`, `memory_poison_guard.py`, `prompt_leakage_scanner.py`) for catastrophic backtracking (ReDoS), enforce max JSON nesting depth and payload byte limits, and add a timeout/bounded-scan test against pathological 1 MB payloads.

### 14.2 Fix Incomplete v3.1 Wiring (Docker, KMS, Helm, Config, Telemetry, UI Scripts)
1. **Production Dockerfiles (`deploy/Dockerfile.engine`, `deploy/Dockerfile.dashboard`):**
   - Inspect and update `deploy/Dockerfile.engine`:
     - Copy `cli/` and all required runtime directories (`core/`, `gateways/`, `plugins/`, `policy_packs/`, `migrations/`, `alembic.ini`).
     - Install from `pyproject.toml` cleanly so `aegisctl` is available on `$PATH` inside the container, and support build args (`INSTALL_EXTRAS="cli,oidc,kms"` or `"ml,cli,oidc,kms"`) plus minimal OS packages needed for OCR/crypto if enabled.
     - Run as a non-root user and expose a real `HEALTHCHECK` against `/health`.
   - Verify `deploy/Dockerfile.dashboard` builds cleanly with multi-stage Node + Nginx and serves all SPA routes cleanly.
2. **Audit KMS Key Rotation & Verification (`core/crypto/kms.py`, `core/audit/ledger.py`, `core/audit/verifier.py`, `core/models/audit.py`):**
   - Inspect `0007_phase13_kms_signatures.py`, `ledger.py`, and `verifier.py`.
   - Ensure every audit row signed with KMS persists `kms_key_version` (add migration `0008_phase14_audit_key_version.py` if missing) and `verifier.py` verifies each historical record against its recorded `kms_key_version` so rotating to a new key version (`v1` -> `v2`) NEVER breaks historical chain verification.
   - Verify `core/pii_vault/vault.py` decrypts existing tokens cleanly after key rotation.
3. **Complete Kubernetes Helm Chart (`deploy/helm/aegisgate/`):**
   - Inspect all files in `deploy/helm/aegisgate/templates/` and `values.yaml`.
   - Add missing production templates:
     - `hpa.yaml` (HorizontalPodAutoscaler for Engine)
     - `pdb.yaml` (PodDisruptionBudget for Engine & Dashboard)
     - `serviceaccount.yaml`
     - `secret.yaml` (supports `existingSecret` reference or templated secrets)
   - Ensure `engine-deployment.yaml` and `dashboard-deployment.yaml` include proper `Service` definitions, `livenessProbe`/`readinessProbe`, resource requests/limits, and hardened non-root `securityContext` (`readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`).
4. **Centralize Configuration & Wire Missing Telemetry (`core/config.py`, `core/telemetry.py`):**
   - Audit the codebase for scattered raw `os.getenv()` calls and consolidate settings into typed Pydantic `BaseSettings` fields in `core/config.py` (with safe defaults and backward-compatible env var names).
   - Ensure `core/telemetry.py` instruments `anthropic_proxy.py`, `gemini_proxy.py`, `streaming.py`, `tool_gateway.py`, and `core/crypto/kms.py` with OTel spans and Prometheus counters/histograms (`aegis_proxy_requests_total{provider=...}`, `aegis_kms_ops_total`, `aegis_ssrf_blocks_total`).
5. **Update E2E UI & Demo Scripts for `LoginView.tsx` & v3 Features:**
   - Update `scripts/verify_v2_ui.mjs`, `scripts/test_ui_backend_integration.mjs`, `scripts/seed_demo.py`, and `scripts/demo_showcase.py` so they authenticate cleanly through `LoginView.tsx`, verify live Budget Burn & Circuit-Breaker Reset in `KillSwitchView.tsx`, and verify Compliance Report export in `AuditForensicsView.tsx`.

### 14.3 Expanded v3 Red-Team & Security Test Suite
- Create `tests/redteam/test_v3_security_and_universal.py` covering:
  1. Unicode zero-width & NFKC homoglyph obfuscation bypasses + Base64-encoded prompt injections & secrets.
  2. Outbound SSRF attacks (registering `http://169.254.169.254/latest/meta-data`, `http://127.0.0.1:6379`, and private IPs via Webhook Scanner, HTTP Resolver, and MCP Server APIs).
  3. Cross-tenant IDOR matrix tests (Tenant A trying to read/modify/delete Tenant B's approvals, audits, budgets, policies, plugins, and MCP servers).
  4. SSE streaming split-token secret & forbidden-phrase smuggling across chunk boundaries.
  5. ReDoS / pathological large-payload latency bounds on all Tier-1 scanners.
  6. Phase 12 universal attack surfaces: system prompt extraction variants, NLI hallucination evasion, visual OCR prompt injection payloads, and Anthropic/Gemini tool-call smuggling.
  7. KMS key rotation verification (`v1` -> `v2` audit chain verification + PII vault decryption).

### Phase 14 Definition of Done
- All Phase 1–13 tests + all new Phase 14 security/red-team/KMS tests pass with zero regressions.
- `tests/redteam/test_v3_security_and_universal.py` achieves >=95% detection on obfuscation/universal attacks and 100% block rate on SSRF, IDOR, and split-token streaming leaks.
- `deploy/Dockerfile.engine` and `deploy/Dockerfile.dashboard` build cleanly (`docker compose --profile observability config` valid; run `docker build` if Docker daemon is available).
- Helm chart templates render with zero YAML/template errors.
- Dashboard (`npm run build`), TypeScript SDK (`npm test` / `tsc --noEmit`), and updated UI integration script pass cleanly.

---

## Phase 15 (v4.0 — Optional, Execute ONLY After Phase 14 Passes & Is Committed): Universal Platform Completion

### 15.1 Multi-Turn Conversational Risk Accumulation (Crescendo Defense)
- Add `core/governance/conversation_risk.py` backed by Redis sliding windows (`aegis:conv_risk:{tenant}:{session_id}`) tracking decaying cumulative risk scores across turns in a session.
- Expose `session.cumulative_risk_score` and `session.high_risk_turns` to `core/policy_engine/yaml_engine.py` so any Policy Pack can escalate (`MODIFY` / `SUSPEND_FOR_APPROVAL` / `DENY`) gradual multi-turn jailbreaks even when individual turns score below single-turn thresholds.

### 15.2 AWS Bedrock Converse & Azure OpenAI Protocol Translators
- Add `gateways/llm_proxy/translators/bedrock_translator.py` + `bedrock_proxy.py` (`/proxy/bedrock/model/{model_id}/converse` and `/converse-stream`).
- Add `gateways/llm_proxy/translators/azure_openai_translator.py` + route support (`/proxy/azure/openai/deployments/{deployment}/chat/completions`) handling `api-version` query params and `api-key` headers cleanly through `core_handler.py`.

### 15.3 SQL AST Governance Scanner (`plugins/scanners/tier1_deterministic/sql_ast_guard.py`)
- Implement a dedicated SQL AST parser scanner (using `sqlglot` with safe fallback parser) registered via `PluginRegistry` for `tool_pre_call` and `llm_output`:
  - Enforce allowed statement types (e.g., `SELECT`-only mode blocking `DROP`, `DELETE`, `TRUNCATE`, `ALTER`, `GRANT`, `UNION` exfiltration).
  - Enforce table/column allowlists and denylists (e.g., block `users.password_hash`, `pg_shadow`).
  - Optionally auto-inject or require `LIMIT <= max_rows` and mandatory `WHERE tenant_id = ...` predicates (`MODIFY` or `DENY`).
- Add a reference `policy_packs/text-to-sql-pack/policy.yaml`.

### 15.4 Bidirectional WebSocket / Realtime Voice Proxy (`gateways/realtime_proxy/`)
- Add `gateways/realtime_proxy/ws_proxy.py` mounted at `/proxy/realtime/v1` (supporting OpenAI Realtime API / generic JSON WebSocket event streams):
  - Intercepts client transcript/text events (`llm_input`), assistant output transcript deltas (`llm_output`), and realtime `function_call` events (`tool_pre_call` / `tool_post_call`) through the exact same `core/pipeline/orchestrator.py`, with instant WebSocket kill-switch termination and session budget accounting.

### Phase 15 Definition of Done
- Unit & integration tests prove: multi-turn Crescendo risk accumulation trips policy escalation across 5 benign-looking progressive turns; Bedrock Converse & Azure OpenAI proxies govern sync and streaming calls cleanly; `sql_ast_guard` blocks destructive/unauthorized queries and enforces `LIMIT`/tenant predicates; WebSocket realtime proxy intercepts and blocks forbidden tool calls & PII mid-session.
- All Phase 1–15 tests, red-team benchmarks, TypeScript SDK, and Dashboard builds pass with zero regressions.