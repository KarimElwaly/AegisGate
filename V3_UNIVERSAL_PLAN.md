# AegisGate v2.1 -> v3.1 Universal Enterprise Upgrade Plan (Phases 11–13)

## 0. Mandatory Pre-Flight Audit & Architectural Laws
Before writing or modifying ANY code in a phase, inspect the existing files referenced in that phase so you upgrade and harden existing code cleanly instead of duplicating modules.

Non-Negotiable Laws (Enforce Strictly):
1. **Strict Backward Compatibility:** Never break existing Phase 1–10 REST endpoints, proxy routes, Policy Pack schemas, Alembic migrations (`0001` through `0006`), or existing tests. Never weaken or skip existing assertions.
2. **Zero Domain Logic in `core/`:** `core/` MUST remain 100% domain-agnostic. Never import directly from `plugins/` or `policy_packs/` inside `core/pipeline/`; resolve all scanners, resolvers, and notifiers dynamically via `PluginRegistry`.
3. **Database Hygiene:** All schema updates MUST use incremental Alembic migrations starting at `0007_*`. Never use `create_all()` in production code paths.
4. **Honest Implementations (No Fake Stubs):** Every scanner, auth verifier, and proxy translator must implement genuine production logic. For local ML/ONNX models, implement the real ONNX/Presidio/CrossEncoder runtime loader plus a clean, explicitly flagged `fallback_mode` when model weights are not mounted in CI.
5. **Dynamic Config Schemas:** Every new scanner, protocol adapter, or plugin MUST expose a Pydantic `ConfigSchema` discoverable via `/v1/plugins/schemas`.
6. **Clean Dependencies & Packaging:** Keep `pyproject.toml`, `sdks/python/pyproject.toml`, `sdks/typescript/package.json`, and Dockerfiles fully in sync with all runtime dependencies and CLI entrypoints.

---

## Phase 11 (v2.1): Hardening, Incomplete Wiring Fixes & Full v2 Parity

### 11.1 Wire Observability Stack & Packaging
- **Docker Compose & Env:** Inspect `deploy/docker-compose.yml`, `deploy/.env.example`, `deploy/nginx.conf`, `deploy/prometheus.yml`, `deploy/otel-collector-config.yaml`, and `deploy/grafana/dashboard.json`.
  - Add `prometheus`, `otel-collector`, and `grafana` services (auto-provisioning the Prometheus datasource and `dashboard.json`) to `deploy/docker-compose.yml` under `profiles: ["observability"]`.
  - Update `deploy/.env.example` with all v2/v3 variables (OIDC, OTEL exporter endpoint, KMS provider, upstream LLM pools, model cache directory).
  - Verify `deploy/nginx.conf` cleanly proxies all v2 routes (`/v1/*`, `/proxy/*`, `/metrics`, WebSocket/SSE with buffering disabled for streaming endpoints).
- **Root `pyproject.toml`:** Register `aegisctl = "cli.aegisctl.main:app"` (or matching callable) under `[project.scripts]` and declare all optional extras cleanly (`[project.optional-dependencies]` for `ml`, `kms`, `oidc`, `cli`, `dev`).

### 11.2 Streaming Proxy Parity (`gateways/llm_proxy/streaming.py`)
- Inspect `gateways/llm_proxy/proxy.py` and `gateways/llm_proxy/streaming.py`.
- Bring SSE streaming to full parity with non-streaming calls:
  - Inject `stream_options: {"include_usage": true}` when forwarding to OpenAI-compatible upstreams (configurable per provider).
  - Parse exact `usage.prompt_tokens` / `usage.completion_tokens` from the final SSE usage chunk and reconcile the delta against Redis budgets in `core/governance/budgets.py` (with accurate character/token estimation fallback if an upstream omits usage).
  - Apply the same multi-provider failover (on pre-stream 429/5xx) and `route_to_tier: local_only` sovereignty routing used in `proxy.py`.
  - Ensure mid-stream guardrail aborts emit a clean SSE termination payload + audit record with partial token accounting.

### 11.3 Harden OIDC Verification (`core/auth/oidc.py`)
- Inspect `core/auth/oidc.py` and `core/auth/dependencies.py`.
- Ensure real OIDC JWT verification: fetch and cache JWKS from the configured `OIDC_JWKS_URI` (or discover via `.well-known/openid-configuration`) with TTL refresh and key-rotation retry on unknown `kid`, validate `iss`, `aud`, `exp`, `nbf`, and cryptographic RS256/ES256 signature, and map configurable group/role claims (`OIDC_ROLE_CLAIM`) to AegisGate Operator RBAC roles.

### 11.4 Admin Dashboard Parity (`dashboard/`)
- Inspect `dashboard/src/App.tsx`, `Navbar.tsx`, `Sidebar.tsx`, `OverviewView.tsx`, `KillSwitchView.tsx`, `PluginRegistryView.tsx`, and `api.ts`.
- Add a clean **Login / Auth Gate View** (`LoginView.tsx`) supporting local JWT login + conditional OIDC SSO login button when OIDC is enabled, storing session tokens cleanly and handling 401 expiry gracefully (while preserving a dev/demo quick-fill helper if seeded).
- Upgrade **KillSwitchView.tsx** (or add a dedicated **Budgets & Quotas** panel) wired to `/v1/budgets` to display live Redis token/cost burn per tenant/workspace, edit quota limits, and reset tripped loop circuit-breakers in 1 click.
- Upgrade **OverviewView.tsx** to surface live v2 metrics (shadow discovery count, active MCP servers, budget utilization, and P95 latency).

### 11.5 TypeScript SDK v2 Parity (`sdks/typescript/`)
- Update `sdks/typescript/src/types.ts` and `client.ts` to full v2 parity:
  - Support Virtual API Key authentication (`x-aegis-api-key` / `Authorization: Bearer ag_live_...`).
  - Add `attachments` (multimodal metadata), `declared_scope`, `session_taints`, and signed agent identity headers.
  - Add HITL approval polling helpers (`waitForApproval`) and a thin `wrapTool` / Vercel AI SDK-compatible middleware helper.
  - Add TypeScript build + unit test verification (`npm run build` / vitest or node test runner).

### 11.6 Expand Red-Team Suite & Real E2E Latency Benchmarks
- Expand `tests/redteam/` with adversarial test suites covering all v2 attack surfaces:
  1. RAG cross-tenant & clearance-bypass chunk extraction attempts.
  2. Long-term memory poisoning (`memory_write` directive override & secret persistence).
  3. MCP tool-description rug-pull & unauthorized `tools/list` probing.
  4. Multi-step stateful taint exfiltration (`read_confidential` -> `external_http_post`).
  5. Forged `actor.role` and privilege-escalated `delegation_chain` attacks.
- Add `tests/benchmarks/test_e2e_http_benchmark.py` measuring **real end-to-end HTTP P50/P95/P99 latency** across FastAPI + Redis + PostgreSQL (clearly distinguished in `PROGRESS.md` from the in-memory Tier-1 microbenchmark).

### Phase 11 Definition of Done
- All Phase 1–10 tests pass with zero regressions.
- `docker compose --profile observability config` validates cleanly and boots Prometheus/OTel/Grafana alongside the stack.
- Streaming proxy tests prove exact SSE token reconciliation and `local_only` sovereignty routing.
- OIDC JWKS verification tests pass with generated RSA test keys (valid token, expired token, wrong audience, rotated `kid`).
- Expanded v2 Red-Team suite achieves >=95% attack detection with <2% false positives.
- `sdks/typescript` compiles with `tsc --noEmit` (`strict: true`) and passes unit tests; `dashboard` builds cleanly (`npm run build`) and passes updated `scripts/verify_v2_ui.mjs` / Playwright checks.

---

## Phase 12 (v3.0): Universal Multi-Provider Proxy & Real Local ML Depth

### 12.1 Universal LLM Protocol Translation (`gateways/llm_proxy/`)
Refactor `gateways/llm_proxy/` into a clean protocol-adapter architecture so non-OpenAI clients integrate with zero code rewrites:
- Create `gateways/llm_proxy/translators/`:
  - `base.py`: `BaseProtocolTranslator` (`to_canonical_input`, `apply_input_mutations`, `to_canonical_output`, `translate_stream_chunk`).
  - `openai_translator.py`: Existing OpenAI `/proxy/llm/v1/*` logic cleanly separated.
  - `anthropic_translator.py`: Native Anthropic Messages API (`/proxy/anthropic/v1/messages`) handling `system`, `messages` (text, tool_use, tool_result, image blocks), and native SSE streaming (`event: content_block_delta`, `message_delta` usage reconciliation).
  - `gemini_translator.py`: Native Google Gemini API (`/proxy/gemini/v1beta/models/{model}:generateContent` and `:streamGenerateContent`) handling `systemInstruction`, `contents`, `functionCall`/`functionResponse`, and `usageMetadata` reconciliation.
- Every translator routes through the exact same `core/pipeline/orchestrator.py`, PII Vault, Sovereignty Router, Budgets, and Audit Ledger.

### 12.2 Upgrade Tier-2 ML Scanners to Real Pluggable Runtimes + Model Bootstrap CLI
- Inspect `plugins/scanners/tier2_local_ml/` (`onnx_classifier.py`, `ner_pii_scanner.py`, `safety_toxicity_scanner.py`, `topic_guard.py`).
- Upgrade each scanner so it supports a **real local ML execution backend** (configurable via `ConfigSchema`) with clean CI fallback when weights are absent:
  - `ner_pii_scanner.py`: Support Microsoft Presidio Analyzer and/or ONNX Token Classification NER (`dslim/bert-base-NER` / multilingual ONNX) wired directly into `core/pii_vault/vault.py` for reversible tokenization of unstructured names, orgs, and addresses.
  - `topic_guard.py`: Real local embedding cosine-similarity runtime (ONNX sentence-transformer, e.g., `all-MiniLM-L6-v2` / `bge-small-en`) comparing input/output embeddings against Policy Pack `allowed_topics` and `forbidden_topics` prototypes.
  - `safety_toxicity_scanner.py`: Real local classifier adapter supporting **Llama Guard 4 / Prompt Guard 2** (via local vLLM/Ollama endpoint or local ONNX safety classifier) covering standard harm taxonomy (hate, harassment, self-harm, sexual, violence, cyberattack/code-interpreter abuse, CBRN).
- Extend `cli/aegisctl/main.py` with `aegisctl models status` and `aegisctl models pull <profile>` so operators can inspect and download local ONNX model bundles reproducibly into `AEGIS_MODEL_DIR`.

### 12.3 New High-ROI Universal Scanners
Add three new domain-agnostic scanner plugins registered dynamically via `PluginRegistry`:
1. **`plugins/scanners/tier2_local_ml/nli_faithfulness_scanner.py` (RAG Hallucination / Groundedness):**
   - Local cross-encoder NLI entailment model (e.g., ONNX MiniLM-NLI / DeBERTa-NLI with lightweight lexical-overlap fallback in CI) verifying that sentences in `output_payload` are entailed by the retrieved chunks in `untrusted_data` without calling an external LLM.
2. **`plugins/scanners/tier1_deterministic/prompt_leakage_scanner.py` (System Prompt Extraction Guard):**
   - Deterministic n-gram Jaccard/containment + normalized edit-distance scanner comparing `output_payload` against `trusted_instructions` (or registered workspace system-prompt hashes/fingerprints) to block system prompt exfiltration attacks.
3. **`plugins/scanners/tier2_local_ml/multimodal_ocr_scanner.py` (Vision & Document Pre-Flight Guard):**
   - Inspects `content.attachments` (and OpenAI/Anthropic/Gemini inline image blocks): extracts text via pluggable local OCR adapter (RapidOCR/Tesseract ONNX or provided `transcript_or_ocr`), then feeds extracted text through PII/Secrets + Indirect Prompt Injection scanning (catching visual prompt injection overlays and sensitive documents before they reach upstream models).

### Phase 12 Definition of Done
- E2E tests verify unmodified Anthropic-format and Gemini-format clients (both non-streaming and SSE streaming) are transparently governed, redacted, budgeted, and audited through `/proxy/anthropic/*` and `/proxy/gemini/*`.
- Unit & red-team tests pass for NLI faithfulness (catches hallucinated claims not supported by retrieved context while passing entailed summaries), system prompt leakage detection, and multimodal image-text injection/PII detection.
- `aegisctl models status` reports configured runtimes and active fallback vs. loaded ONNX status cleanly.

---

## Phase 13 (v3.1): Enterprise KMS, Turnkey Compliance Packs, Ecosystem Adapters & Production DevOps

### 13.1 Pluggable Enterprise KMS & Key Rotation (`core/crypto/`)
- Create `core/crypto/kms.py` defining a clean `KeyProvider` interface (`encrypt_dek`, `decrypt_dek`, `sign_hmac`, `verify_hmac`, `current_key_version`) with three implementations:
  1. `LocalEnvKeyProvider` (default local-first dev/self-hosted AES-256-GCM envelope encryption + HKDF key derivation).
  2. `HashiCorpVaultKeyProvider` (Vault Transit secrets engine HTTP client for envelope encrypt/decrypt & HMAC).
  3. `AWSKMSKeyProvider` (pluggable boto3/HTTP KMS envelope encryption adapter).
- Wire `KeyProvider` into:
  - `core/pii_vault/vault.py` (encrypt stored PII vault mappings at rest using envelope DEKs + `key_version` metadata).
  - `core/audit/ledger.py` & `core/audit/verifier.py` (support KMS-backed HMAC signatures alongside hash chaining, while preserving backward compatibility for verifying historical v1/v2 records).

### 13.2 Turnkey Regulatory Compliance Policy Packs & Auditor Report API
- Author 4 production-grade compliance policy packs in `policy_packs/`:
  1. `eu-ai-act-pack/policy.yaml` (Article 9/12/14 human oversight HITL gates, logging provenance, prohibited-practice topic blocks, transparency tags).
  2. `hipaa-pack/policy.yaml` (strict PHI regex + NER redaction, mandatory `local_only` sovereignty routing or zero-retention upstream enforcement, audit chain retention tags).
  3. `pci-dss-pack/policy.yaml` (PAN/CVV/track-data blocking + Luhn validation, strict secret/credential exfiltration prevention, dual-approval for payment/account tools).
  4. `nist-ai-rmf-pack/policy.yaml` (Map/Measure/Manage controls covering prompt injection, loop breakers, delegation limits, shadow discovery alerts, and continuous red-team telemetry).
- Add `GET /v1/audit/compliance-report` (`framework=eu-ai-act|hipaa|pci-dss|nist-ai-rmf`, `from`, `to`, `format=json|markdown`) generating a structured auditor evidence package containing: active policy versions, control-by-control enforcement counts (`ALLOW`/`DENY`/`MODIFY`/`HITL`), HITL approver summary, shadow AI exceptions, and a live cryptographic hash-chain integrity verification certificate.
- Expose a one-click **Compliance Report Exporter** inside `dashboard/src/views/AuditForensicsView.tsx`.

### 13.3 Broader Python Ecosystem Adapters
- Expand `sdks/python/aegisgate/adapters/` (alongside existing `fastmcp_guard.py`, `langgraph_guard.py`, `openai_adapter.py`, `temporal_adapter.py`) with:
  - `crewai_guard.py`: Drop-in CrewAI task/tool guardrail wrapper.
  - `llamaindex_guard.py`: LlamaIndex post-retrieval (`rag_retrieval`) and response (`llm_output`) guardrail callback/postprocessor.
- Keep optional third-party imports lazy so installing `aegisgate-sdk` never forces CrewAI or LlamaIndex as mandatory dependencies.

### 13.4 Production CI/CD & Kubernetes Helm Chart
- Add `.github/workflows/ci.yml`:
  - Python lint/typecheck (`ruff`, `mypy`)
  - Unit + Integration + Red-Team pytest suite (with PostgreSQL 16 + Redis 7 service containers)
  - TypeScript SDK build & Dashboard Vite build
  - Docker image build verification for Engine & Dashboard
- Add production Kubernetes Helm Chart under `deploy/helm/aegisgate/`:
  - `Chart.yaml`, `values.yaml`, and templates for Engine Deployment (with HPA, `/health` readiness & liveness probes, non-root securityContext), Dashboard Deployment, Ingress (with SSE proxy annotations), ConfigMap, Secret references, and Alembic migration pre-upgrade Job hook.
- Update `README.md`, `ARCHITECTURE.md`, and `DEMO_GUIDE.md` to reflect v3.1 capabilities accurately.

### Phase 13 Definition of Done
- KMS tests pass for `LocalEnvKeyProvider` (including live key-version rotation decrypting older vault tokens and verifying older audit records) and mocked `HashiCorpVaultKeyProvider` / `AWSKMSKeyProvider`.
- All 4 regulatory policy packs pass validation (`aegisctl validate`), unit tests, and end-to-end compliance report generation with verified hash-chain integrity.
- CrewAI and LlamaIndex adapter unit tests pass without requiring heavy upstream packages installed.
- `.github/workflows/ci.yml` YAML validates cleanly; Helm templates render cleanly (`helm template` if available, or YAML lint validation).
- Full regression suite (`pytest`) + TypeScript SDK + Dashboard build + Playwright UI verification all pass cleanly.