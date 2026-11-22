# Phase 16 (v4.1): Deep Security Remediation, Bug Fixes & Stub Elimination

## 0. Mandatory Rules
1. Fix every root cause below directly in the referenced files—do NOT add workarounds or weaken existing tests.
2. Also audit `gateways/mcp_tool_gateway/tool_gateway.py`, `gateways/pdp_api/routes/`, `gateways/realtime_proxy/ws_proxy.py`, and `deploy/` for the exact same classes of bugs (missing auth, missing SSRF checks, ignored MODIFY/SUSPEND verdicts, missing tenant scoping) and fix any findings in this phase.
3. Preserve zero domain logic inside `core/` and zero imports from `plugins/` or `policy_packs/` inside `core/pipeline/`.
4. Every fix MUST ship with a dedicated regression test in `tests/redteam/test_phase16_remediation.py` that would have failed before the fix.

---

## 1. P0 — Critical Security & Governance Bypasses

### 1.1 Fix LLM Proxy Auth, Redaction Enforcement, HITL, SSRF & Prod Fail-Open (`gateways/llm_proxy/core_handler.py` & protocol proxy routes)
- **Authenticate Proxy Calls:** Enforce `get_pdp_actor` / Virtual API Key (`ag_live_...`) or Bearer JWT authentication on `/proxy/llm/v1/*`, `/proxy/anthropic/*`, `/proxy/gemini/*`, `/proxy/bedrock/*`, and `/proxy/azure/*` (binding `tenant_id`, `workspace_id`, `allowed_models`, and `default_policy_pack_id` from the authenticated actor rather than trusting raw `x-aegis-tenant-id` headers in non-test environments).
- **Apply `MODIFY` Mutations to Upstream Request:** When `verdict_input.decision == DecisionEnum.MODIFY` and `verdict_input.mutated_content` is present, apply the redacted/tokenized text back into the upstream request `body` via a translator method (`apply_input_mutations`) BEFORE sending to the upstream LLM. Never forward unredacted PII after tokenization.
- **Enforce `SUSPEND_FOR_APPROVAL` and `ESCALATE`:** Handle `SUSPEND_FOR_APPROVAL` (return HTTP 202 with `approval_ticket` metadata) and `ESCALATE` (return HTTP 403 or configured action) instead of letting them fall through as `ALLOW`.
- **Enforce Outbound SSRF Validation:** Run `validate_outbound_url()` on every candidate URL derived from `x_aegis_upstream_url` before opening any `httpx` connection.
- **Remove Production Fail-Open Mock:** On `httpx.RequestError`, ONLY return a mock completion when `settings.AEGIS_ENV == "test"`. In `dev`/`staging`/`prod`, return HTTP 502/503 with structured error JSON and record proxy error telemetry.
- **Preserve Context at `LLM_OUTPUT`:** Pass `trusted_instructions=trusted_instr` and `untrusted_data=untrusted_data` into the `StageEnum.LLM_OUTPUT` `ContentModel` alongside `output_payload=assistant_content` so `PromptLeakageScanner` and `NliFaithfulnessScanner` actually function on proxied traffic.
- **Fix Default Upstream Path per Protocol:** Do not append OpenAI's `/chat/completions` when proxying Anthropic, Gemini, Bedrock, or Azure requests.

### 1.2 Eliminate OIDC Unsigned-JWT Bypass & Tenant Spoofing (`core/auth/oidc.py`, `core/auth/dependencies.py`)
- In `core/auth/oidc.py`, **DELETE** the `else:` branch that calls `jwt.decode(token, options={"verify_signature": False})`. If `OIDC_ENABLED=True` and neither `key` nor a valid `jwks_client` is available, raise `ValueError("OIDC JWKS verification is not configured")` (fail closed).
- In `core/auth/dependencies.py`:
  - Derive OIDC `tenant_id` from a validated JWT claim (e.g. `claims.get("tenant_id")`) instead of trusting the arbitrary `X-Aegis-Tenant-Id` header (only allow header override for `SuperAdmin`).
  - Never assign `role="SuperAdmin"` to anonymous callers outside explicit `AEGIS_ENV == "test"` (use `role="Anonymous"` or reject when auth is required).

### 1.3 Stop Leaking Plaintext PII in Redis Keys (`core/pii_vault/vault.py`)
- Replace `forward_key = f"{session_key}:fwd:{original_value}"` with an HMAC-SHA256 digest of `original_value` keyed by the KMS/secret key (`hmac_digest = hashlib.sha256(... )` or `hmac.new(key, original_value.encode(), hashlib.sha256).hexdigest()`), so raw emails, SSNs, IPs, and credit cards NEVER appear in Redis key names or logs.

### 1.4 Fix `NerPiiScanner` Swapped Arguments & Missing Mutations (`plugins/scanners/tier2_local_ml/ner_pii_scanner.py`)
- Fix the reversed arguments in `vault.tokenize(...)` to `(request.tenant_id, request.session_id, ent["entity_type"], ent["value"])`.
- When `cfg.tokenize_entities` is True, actually replace detected spans in `mutated_content` and return `mutated_content` + `redaction_map` in `ScannerResult` (matching `PiiScanner`).

### 1.5 Fix SQL Tenant-Isolation Precedence & Escaping (`plugins/scanners/tier1_deterministic/sql_ast_guard.py`)
- Add `sqlglot>=25.0.0` to `pyproject.toml` so real AST parsing is installed by default.
- Sanitize/escape `tenant_id` strictly (validate against safe identifier pattern or escape single quotes `tenant_id.replace("'", "''")`) before injecting SQL predicates.
- In `_analyze_with_fallback`, when a `WHERE` clause already exists, wrap the original `WHERE` expression in parentheses before prepending `tenant_id = '...' AND (...)` (stopping before `GROUP BY`/`ORDER BY`/`LIMIT`) so `OR 1=1` cannot bypass tenant isolation.

### 1.6 Close Remaining Outbound SSRF Gaps
- Enforce `validate_outbound_url()` before outbound connections in:
  - `core/hitl/engine.py` (`_send_callback`)
  - `plugins/notifiers/siem_cef_notifier.py` (`siem_endpoint_url` and `siem_host` IP resolution)
  - `plugins/scanners/tier2_local_ml/safety_toxicity_scanner.py` (`endpoint_url`)
  - `core/policy_engine/opa_engine.py` (`opa_url`)
  - `gateways/realtime_proxy/ws_proxy.py` (upstream WebSocket URL)

---

## 2. P1 — Multi-Protocol Streaming, Broken Policy Packs & SDK Fixes

### 2.1 Protocol-Aware `SSEStreamGuard` (`gateways/llm_proxy/streaming.py` & `translators/`)
- Make `SSEStreamGuard` accept the active `translator: BaseProtocolTranslator` instead of hardcoding OpenAI's `choices[0].delta.content` and `data: [DONE]`.
- Add translator stream hooks (`extract_stream_delta`, `replace_stream_delta`, `extract_stream_usage`, `build_stream_abort_chunk`) for OpenAI, Azure OpenAI, Anthropic (`content_block_delta` / `message_delta`), Gemini (`candidates[0].content.parts[0].text` / `usageMetadata`), and Bedrock (`contentBlockDelta` / `metadata.usage`) so secret-leak aborts, PII rehydration, and exact token reconciliation work across ALL 5 protocols.

### 2.2 Fix All 6 Broken Reference Policy Packs (`policy_packs/*/policy.yaml`)
- `soc-investigation-pack/policy.yaml`: fix `http_context_resolver` config key `url` -> `url_template`, support dotted paths (`{action.parameters.asset_id}`) in `HTTPContextResolver._format_template()`, and use a configurable placeholder/allowlisted host.
- `eu-ai-act-pack/policy.yaml` & `pci-dss-pack/policy.yaml`: move `required_approvals` and `required_approver_roles` inside `action.approval_config` (and also support top-level fallback in `YamlPolicyEngine` for backward safety).
- `agent-fleet-pack/policy.yaml` & `nist-ai-rmf-pack/policy.yaml`: expose computed `actor.delegation_depth = len(actor.delegation_chain)` and `metadata.loop_count` inside `YamlPolicyEngine` context bundle so existing depth and loop rules actually fire.
- `hipaa-pack/policy.yaml` & `pci-dss-pack/policy.yaml`: fix invalid scanner config keys (`enable_tokenization`/`action_on_detect` -> `mode: reversible_tokenize` on `pii_scanner`, `action_on_detect` -> `action_on_match: block` on `secrets_scanner`).
- `text-to-sql-pack/policy.yaml`: change singular `stage:` -> `stages: [...]` and move `severity:` under `action:`.
- `log-analysis-pack/policy.yaml`: match `action.target` (or `any` of `action.target` / `metadata.model`) for sovereign model enforcement.
- Add a strict schema validation check in `aegisctl validate` that rejects unknown scanner config keys and invalid rule fields (`stage` instead of `stages`).

### 2.3 Fix `PolicyReplaySimulator` Crash & Python SDK Gaps
- `core/simulator/replay.py`: fix `self.yaml_engine.load_pack_from_yaml(...)` -> `self.yaml_engine.load_from_yaml_string(...)`.
- `sdks/python/aegisgate/decorators.py`: in `@governed_llm`, pass user `prompt` into `untrusted_data=prompt` (with optional `system_prompt` into `trusted_instructions`) so prompt injection classifiers inspect user input.
- `sdks/python/aegisgate/adapters/` (`crewai_guard.py`, `fastmcp_guard.py`, `langgraph_guard.py`, `llamaindex_guard.py`, `temporal_adapter.py`) & `decorators.py`: handle `SUSPEND_FOR_APPROVAL` (raise a dedicated `ApprovalRequiredError(ticket_id=...)`), `ESCALATE`, and `MODIFY` (apply `mutated_parameters` / `mutated_content`).
- `sdks/python/aegisgate/models.py`: align `ContentModel` (add `output_payload`, `citations`), `ActorModel` (add `delegation_chain`), and `BudgetSnapshot` (`tokens_used`, `tokens_limit`, `cost_used_usd`, `cost_limit_usd`, `tool_calls_used`, `tool_calls_limit`) with `core/schemas/`.

---

## 3. P2 — Concurrency, Multi-Worker & Pipeline Correctness

- **Serialize Audit Hash-Chain Writes (`core/audit/ledger.py`, `core/models/audit.py`):** Prevent concurrent hash-chain forks per tenant using a per-tenant lock (PostgreSQL `pg_advisory_xact_lock` on Postgres + asyncio per-tenant lock for SQLite/single-process) and a unique constraint on `(tenant_id, prev_hash)` (migration `0009_phase16_audit_chain_unique.py`) with bounded retry on conflict.
- **Fix HITL Multi-Worker Split-Brain (`core/hitl/engine.py`):** Make `list_tickets()` query PostgreSQL directly (falling back to `_mem_tickets` only when DB is unavailable), and reload ticket state from DB inside `decide_ticket()` so multi-worker/restarted containers never lose tickets.
- **Fail Fast on Redis Outage in Prod (`core/redis_client.py`):** In `AEGIS_ENV == "prod"`, do NOT permanently cache `FakeRedis()` when Redis is unreachable; raise/retry cleanly so distributed Kill Switches, Budgets, and Taints never silently split-brain across replicas.
- **Deduplicate `PluginRegistry` Aliases (`core/registry/registry.py`):** Store aliases in a separate `_scanner_aliases: dict[str, str]` lookup map instead of inserting duplicate entries into `self._scanners`, preventing double execution in `get_scanners_for_stage()` and duplicate entries in `/v1/plugins/schemas`.
- **Clean Canonicalizer & Mutation Separation (`core/pipeline/canonicalizer.py`, `core/pipeline/stages/tiered_scanner_stage.py`):**
  - Tighten `BASE64_PATTERN` (require min length >= 24 or explicit padding `=` / mixed case+digits / entropy check) so normal English words (`password`, `customer`, `database`) are never decoded.
  - Do not allow canonicalizer-appended decoded text to bleed into `verdict.mutated_content`: run mutating redaction scanners (`pii_scanner`, `secrets_scanner`) against original text while running detection on canonicalized text (or return mutations strictly over raw text).

---

## 4. P3 — Honest ML & KMS Runtimes (Eliminate Disguised Stubs)

- **KMS (`core/crypto/kms.py`):**
  - Wire `get_key_provider()` to actually inspect `settings.AEGIS_KMS_PROVIDER` (`local` | `vault` | `aws`).
  - Implement real Vault Transit HTTP calls (`/v1/transit/encrypt/{key}`, `/decrypt/{key}`, `/hmac/{key}`) in `HashiCorpVaultKeyProvider` and real `boto3` KMS calls in `AWSKMSKeyProvider` (with explicit `fallback_to_local: bool = False` defaulting to `False` in prod so misconfigured KMS fails loudly instead of silently using a local key).
- **Honest Local ML & OCR Scanners (`plugins/scanners/tier2_local_ml/`):**
  - `onnx_classifier.py`: when `self._session is not None`, execute real tokenization + `self._session.run(...)` inference (or if tokenizer/inputs are missing, explicitly report `engine: "heuristic_fallback"`, `fallback_used: True`—NEVER report `engine: "onnx_runtime"` while running regex).
  - `topic_guard.py`, `nli_faithfulness_scanner.py`, `multimodal_ocr_scanner.py`: wire real optional backends (ONNX/sentence-transformers cosine similarity, ONNX CrossEncoder NLI, RapidOCR/pytesseract on decoded image bytes) and ALWAYS include `"backend_actual"` and `"fallback_used": true|false` in `details` when running heuristic/lexical fallback.
  - `cli/aegisctl/main.py`: remove the fake comment-writing stub in `aegisctl models pull`; validate real ONNX headers/checksums in `aegisctl models status` (showing `INVALID_FILE` instead of `LOADED` for dummy text files) and download real model artifacts from configurable HuggingFace/URL manifests (or fail cleanly with instructions when offline).

---

## 5. Phase 16 Definition of Done
- All Phase 1–15 tests pass with zero regressions.
- New `tests/redteam/test_phase16_remediation.py` passes verifying every single fix above:
  1. LLM proxy forwards tokenized `<AEGIS_EMAIL_1>` instead of raw email to upstream, blocks SSRF via `x-aegis-upstream-url`, and returns 202 on `SUSPEND_FOR_APPROVAL`.
  2. Anthropic, Gemini, and Bedrock SSE streams trigger mid-stream secret abort and exact usage reconciliation.
  3. OIDC with missing JWKS fails closed (401), never accepts unsigned JWTs.
  4. Redis PII vault contains zero plaintext PII in any key name.
  5. `NerPiiScanner` calls `vault.tokenize` with correct arg order and produces valid `<AEGIS_...>` tokens.
  6. `SqlAstGuard` protects `WHERE status = 'open' OR 1=1` by parenthesizing before `AND` tenant filter and blocks quote-injection in `tenant_id`.
  7. Concurrent audit writes (20 parallel `asyncio.gather` calls for same tenant) produce zero hash-chain forks and pass `verify_tenant_chain()`.
  8. `HITLEngine.list_tickets()` returns tickets from DB after clearing `_mem_tickets`.
  9. `PolicyReplaySimulator.run_replay()` succeeds with raw `candidate_pack_yaml`.
  10. All 11 `policy_packs/*/policy.yaml` pass strict `aegisctl validate` with zero unknown scanner keys or schema mismatches.