# AegisGate

> **Commercial-Grade, Domain-Agnostic AI Guardrails & Governance Policy Decision Point (PDP)**
> Built for mission-critical enterprise AI agent fleets, autonomous tool execution, and sovereign LLM workflows.

---

## 1. Executive Summary & Architectural Guarantees

AegisGate is a high-throughput, sub-15ms Policy Decision Point (PDP) designed to govern autonomous LLM agents and tools with cryptographic guarantees, verifiable compliance, and zero domain pollution.

```text
                          +-------------------------------------------------------+
                          |                   INCOMING TRAFFIC                    |
                          | (OpenAI LLM Proxy, MCP JSON-RPC, REST Tool Gateway)  |
                          +-------------------------------------------------------+
                                                     |
                                                     v
+-------------------------------------------------------------------------------------------------+
|                                 SUB-MILLISECOND KILL SWITCH                                     |
|             Redis MGET Evaluation (Global -> Tenant -> Workspace -> Agent -> Tool)              |
|                              Latencies < 0.5ms | Fail-Closed                                    |
+-------------------------------------------------------------------------------------------------+
                                                     |
                                                     v
+-------------------------------------------------------------------------------------------------+
|                                TIERED PIPELINE ORCHESTRATOR                                     |
|                                                                                                 |
|   +-----------------------------------------------------------------------------------------+   |
|   | Tier 1: Deterministic Engine (< 15ms target; 0.33ms measured P95)                        |   |
|   |  - Ephemeral Reversible PII Vault (AES-256-GCM tokenization & deterministic restore)    |   |
|   |  - High-Entropy Secrets & Credential Scanner (Shannon entropy + regex lookaheads)       |   |
|   |  - AST & Dangerous Parameter Guards (rm -rf, DROP TABLE, shell metas, regex timeouts)  |   |
|   |  - Native YAML DSL Engine (All/Any expressions, string/numeric ops, context enrichment) |   |
|   |  - Redis Lua Atomic Token/Dollar Budgets & Sliding-Window Delegation Loop Breakers      |   |
|   +-----------------------------------------------------------------------------------------+   |
|                                                     | (Escalate on Ambiguity)                   |
|                                                     v                                           |
|   +-----------------------------------------------------------------------------------------+   |
|   | Tier 2: Local ML Embedding / ONNX Classifier (10-30ms)                                  |   |
|   |  - High-precision prompt injection & jailbreak detection (0.00% FP baseline)           |   |
|   |  - Zero-network, offline-first fallback with heuristic semantic validation              |   |
|   +-----------------------------------------------------------------------------------------+   |
|                                                     | (Escalate on High-Risk Action)            |
|                                                     v                                           |
|   +-----------------------------------------------------------------------------------------+   |
|   | Tier 3: Sovereign LLM Semantic Judge (50-200ms)                                         |   |
|   |  - Structured JSON reasoning for complex boundary decisions and deep policy alignment   |   |
|   +-----------------------------------------------------------------------------------------+   |
|                                                     |                                           |
|                                                     v                                           |
|   +-----------------------------------------------------------------------------------------+   |
|   | Human-in-the-Loop (HITL) Decision Engine                                                |   |
|   |  - Asynchronous ticket lifecycle, dual 4-eyes approval, parameter overrides            |   |
|   |  - HMAC-SHA256 signed webhooks on human authorization/rejection                        |   |
|   +-----------------------------------------------------------------------------------------+   |
+-------------------------------------------------------------------------------------------------+
                                                     |
                                                     v
+-------------------------------------------------------------------------------------------------+
|                        CRYPTOGRAPHIC HASH-CHAINED AUDIT LEDGER                                  |
|               record_hash = SHA256(prev_hash || canonical_json(record_payload))                 |
|             Immutable Merkle-chain verification | OWASP-LLM & SOC 2 Export Formats               |
+-------------------------------------------------------------------------------------------------+
```

### Key Performance & Governance Benchmarks
- **Sub-15ms Fast Path:** Tier-1 deterministic evaluation achieves **0.65ms P95 latency** (0.47ms P50, 0.71ms P99) under real enterprise workloads (DoD target: < 15ms).
- **Full-Stack End-to-End HTTP Latency:** Real web stack (FastAPI + Redis + SQLite/PostgreSQL + Full Orchestrator) delivers **28.72ms P95 latency** (25.38ms P50, 29.89ms P99; target: < 35ms).
- **Universal Multi-Provider LLM Proxies:** Native, streaming-capable reverse proxies with SSRF validation, PII rehydration, and exact token reconciliation for:
  - OpenAI Chat Completions (`/proxy/llm/v1/*`)
  - Anthropic Messages (`/proxy/anthropic/v1/messages`)
  - Google Gemini GenerateContent (`/proxy/gemini/v1beta/*`)
  - AWS Bedrock Converse & Converse-Stream (`/proxy/bedrock/model/{model_id}/converse`)
  - Azure OpenAI Deployments (`/proxy/azure/openai/deployments/{deployment}/chat/completions`)
- **Realtime Voice & WebSocket Streaming Proxy:** Bidirectional WebSocket proxy (`/proxy/realtime/v1/ws`) with authenticated connection handshake, sub-millisecond kill switch, input/output transcript scanning, and tool pre-call governance.
- **Multi-Turn Crescendo Defense:** Sliding-window conversational risk accumulation with exponential decay (`ConversationRiskTracker`), automatically exposing cumulative risk scores to Policy Packs.
- **SQL AST Guard & Text-to-SQL Governance:** AST parser scanner (`SqlAstGuard`) enforcing SELECT-only mode, table/column denylists, automatic `LIMIT` and tenant isolation predicate injection with parentheses safety.
- **Enterprise KMS & Envelope Encryption:** Pluggable `LocalEnvKeyProvider`, `HashiCorpVaultKeyProvider`, and `AWSKMSKeyProvider` for PII Vault envelope encryption at rest, zero plaintext PII in Redis key storage, and KMS HMAC signatures on audit records with key version tracking.
- **Turnkey Regulatory Compliance:** 11 production reference policy packs for EU AI Act, HIPAA, PCI DSS, NIST AI RMF, Text-to-SQL, Agent Fleet, Log Analysis, and SOC Investigation with automated audit compliance reports (`GET /v1/audit/compliance-report`).
- **Red-Team Injection Benchmark:** Achieves **100.0% prompt injection detection** (41/41 attacks caught) with **0.00% False Positive Rate** (0/41 benign logs flagged) on security evaluation corpora.
- **Protocol-Aware MCP Anti-Rug-Pull:** Pinned SHA-256 schema hashing detects upstream drift, auto-quarantines tools, strips them from `tools/list`, and enforces monotonic tool scope attenuation.
- **Stateful Session Taints:** Multi-step tool-chain governance backed by Redis sets prevents toxic composite actions (confidential read followed by external exfiltration).
- **Strict Decoupling:** Core governance mechanics (`core/`) contain **zero domain-specific code**; all domain logic is strictly isolated in `plugins/` and `policy_packs/`.
- **Tamper-Evident Ledger:** Every policy verdict is chained to its predecessor via `prev_hash` with `UniqueConstraint("tenant_id", "prev_hash")` to prevent forks, and signed with KMS HMAC, enabling continuous topological Merkle integrity checks.
- **Comprehensive Documentation:** Full technical specifications in [ARCHITECTURE.md](ARCHITECTURE.md) and step-by-step showcase in [DEMO_GUIDE.md](DEMO_GUIDE.md).

---

## 2. Quickstart & Deployment

### Run Complete Multi-Container Stack (Docker Compose)
Start PostgreSQL 16, Redis 7, AegisGate PDP Engine, and Control Plane Dashboard:

```bash
cd deploy
docker compose up --build -d
```

### Bootstrap Demo Tenant & Reference Packs
Run the idempotent seeding wizard to initialize schema, register SuperAdmin, issue scoped API keys, and compile reference policy packs:

```bash
python scripts/seed_demo.py
```

### Run Interactive Showcase & System Verification
To verify all 16 core enterprise scenarios (secrets masking, HITL dual approval, prompt injection, loop breaker, kill switch, MCP anti-rug-pull, session taints, RAG ACL, and audit chain verification):

```bash
python scripts/demo_showcase.py
python scripts/verify_system.py
```

---

## 3. Endpoints & Gateways

AegisGate runs on standard ports (`3000`/`8000`) or dedicated conflict-free development ports (`3088`/`8088`):

| Component | Port (Dev / Docker) | Path / URL | Description |
| :--- | :--- | :--- | :--- |
| **Control Plane Dashboard** | `3088` / `3000` | `http://localhost:3088` | React 18 + TS UI (Policy Studio, Tenants, MCP, HITL, Kill Switch, Merkle Forensics, Compliance Exporter) |
| **PDP Evaluation Gateway** | `8088` / `8000` | `/v1/evaluate` | Primary REST PDP endpoint for tool, RAG, and LLM evaluation |
| **OpenAI LLM Reverse Proxy** | `8088` / `8000` | `/proxy/llm/v1/chat/completions` | Transparent OpenAI gateway with failover, sovereignty routing, and token true-up |
| **Anthropic Messages Proxy** | `8088` / `8000` | `/proxy/anthropic/v1/messages` | Native Anthropic Messages API gateway with streaming SSE & token reconciliation |
| **Google Gemini Proxy** | `8088` / `8000` | `/proxy/gemini/v1beta/models/{model}:generateContent` | Native Google Gemini API gateway with contents, system instructions & streaming |
| **AWS Bedrock Converse Proxy** | `8088` / `8000` | `/proxy/bedrock/model/{model_id}/converse` | Native AWS Bedrock Converse & Converse-Stream API gateway |
| **Azure OpenAI Proxy** | `8088` / `8000` | `/proxy/azure/openai/deployments/{deployment}/chat/completions` | Native Azure OpenAI Deployments API gateway |
| **Realtime Voice/WebSocket Proxy** | `8088` / `8000` | `/proxy/realtime/v1/ws` | Bidirectional WebSocket voice/event stream proxy with sub-ms kill switch |
| **MCP Tool Gateway** | `8088` / `8000` | `/proxy/mcp/jsonrpc` | Protocol-Aware MCP JSON-RPC 2.0 gateway with Anti-Rug-Pull schema pinning |
| **MCP Server Management** | `8088` / `8000` | `/v1/mcp/servers`, `/v1/mcp/tools/*` | Upstream MCP server registry, tool schema pinning, and quarantine controls |
| **Multi-Tenancy & Keys** | `8088` / `8000` | `/v1/tenants`, `/v1/api-keys`, `/v1/budgets` | Tenant isolation, scoped Virtual API Keys, and live Redis budget quotas |
| **Shadow AI Discovery** | `8088` / `8000` | `/v1/discovery/assets` | Auto-discovered models, rogue tools, and approve/block governance |
| **REST Tool Gateway** | `8088` / `8000` | `/proxy/tools/{tool_name}` | Generic HTTP tool execution guardrail proxy |
| **HITL Approvals Inbox** | `8088` / `8000` | `/v1/approvals` | Human-in-the-Loop decision and parameter override API |
| **Audit & Merkle Verifier** | `8088` / `8000` | `/v1/audit/verify` | Cryptographic hash-chain continuity and KMS HMAC tamper detection |
| **Compliance Report Exporter** | `8088` / `8000` | `/v1/audit/compliance-report` | Regulatory compliance evidence package (EU AI Act, HIPAA, PCI DSS, NIST AI RMF) |
| **Circuit Breakers** | `8088` / `8000` | `/v1/kill-switch` | 5-level emergency circuit breaker controls |
| **Policy Studio API** | `8088` / `8000` | `/v1/policies` | Policy pack CRUD, shadow promotion, and 1-click rollback |
| **Health Check** | `8088` / `8000` | `/healthz` | Kubernetes liveness and readiness probe |
| **Prometheus Telemetry** | `8088` / `8000` | `/metrics` | Real-time Prometheus metrics for scrapers and Grafana |

---

## 4. Quick PDP Evaluation Example

Evaluate an agent's intended tool execution against the `soc-investigation-pack`:

```bash
curl -X POST http://localhost:8088/v1/evaluate \
  -H "Content-Type: application/json" \
  -H "X-Aegis-Tenant-Id: acme-corp" \
  -d '{
    "tenant_id": "acme-corp",
    "workspace_id": "prod",
    "stage": "tool_pre_call",
    "policy_pack_id": "soc-investigation-pack",
    "actor": {
      "id": "agent-01",
      "role": "security_agent"
    },
    "action": {
      "name": "isolate_host",
      "parameters": {
        "asset_id": "srv-dc-01"
      }
    }
  }'
```

### Response (Blocked Domain Controller Containment):
```json
{
  "trace_id": "tr-550e8400-e29b-41d4-a716-446655440000",
  "decision": "DENY",
  "reason": "Target asset is an essential Domain Controller",
  "latency_ms": 7.42,
  "triggered_rules": [
    {
      "rule_id": "soc-deny-domain-controller-containment",
      "reason": "Target asset is an essential Domain Controller",
      "severity": "CRITICAL",
      "compliance_tags": ["SOC2-CC6.1", "OWASP-LLM06"]
    }
  ],
  "scanner_findings": []
}
```

---

## 5. Production Reference Policy Packs

AegisGate ships with four production-ready, domain-specific reference policy packs in `policy_packs/`:

### 1. `base-enterprise`
Universal baseline guardrails for any enterprise deployment:
- High-entropy credential and API key detection (AWS, GitHub, Slack tokens).
- Reversible PII tokenization (email addresses, SSNs, credit cards, IP addresses).
- Shell parameter safety guards (blocks `rm -rf /`, dangerous forks, unquoted shell metas).

### 2. `soc-investigation-pack`
Autonomous Security Operations Center (SOC) agent governance:
- Dynamic CMDB asset enrichment via `http_context_resolver`.
- Hard-blocks containment on active Domain Controllers and critical infrastructure.
- Enforces dual 4-eyes Human-in-the-Loop (`require_approval`) for Tier-0 network asset isolation.
- Dispatches security event alerts to SIEM via Common Event Format (`siem_cef_notifier`).

### 3. `agent-fleet-pack`
Multi-agent collaborative orchestration guardrails:
- Maximum delegation depth cap (enforces call-stack limits to prevent runaway delegation chains).
- Agent role tool allowlisting (e.g. `summarizer` agent cannot execute infrastructure modification tools).
- Sliding-window loop breaker (detects cyclic duplicate tool invocations within a rolling window).
- Dispatches loop alerts to operators via Slack (`slack_notifier`).

### 4. `log-analysis-pack`
High-volume SIEM and server log security:
- Tier-2 ONNX ML classifier scans incoming raw logs for embedded prompt injections.
- Reversible PII masking protects employee/customer identities before feeding logs to LLMs.
- Strict output JSON schema validation guarantees consistent forensic anomaly reports.

### 5. `rag-copilot-pack`
Enterprise knowledge base & Copilot security:
- Mathematical chunk-level metadata ACL clearance enforcement (`rag_acl_guard`).
- Memory write poisoning protection blocking embedded prompt overrides (`memory_poison_guard`).
- Named entity recognition (NER) masking unstructured employee and customer PII.
- Session taint protection blocking external data exfiltration following confidential data access.

### 6. `customer-support-voice-pack`
Omnichannel customer service and voice agent guardrails:
- Real-time semantic topic boundary enforcement blocking off-topic or competitor queries.
- Safety & toxicity scanner catching harassment, profanity, and threats with local ML.
- Sub-5ms low latency Tier-1/Tier-2 fast path for interactive voice sessions.

### 7. `eu-ai-act-pack`
Turnkey compliance with EU Artificial Intelligence Act (Regulation 2024/1689):
- Article 5 prohibited practice blocking (social scoring, biometric categorization, emotion manipulation).
- Article 9 & 14 human oversight enforcement: mandatory HITL approvals for high-risk autonomous decisions.
- Article 12 automatic chronological audit logging with tamper-evident cryptographic proofs.

### 8. `hipaa-pack`
Health Insurance Portability and Accountability Act (HIPAA) compliance for healthcare agents:
- Reversible tokenization of 18 PHI identifiers (names, MRNs, dates, locations, contact info) via KMS-backed vault.
- Enforces strict `local_only` sovereignty routing preventing external transmission of unredacted health data.
- Blocks unauthorized external exfiltration tools following clinical data access.

### 9. `pci-dss-pack`
Payment Card Industry Data Security Standard (PCI DSS v4.0) guardrails:
- Zero-tolerance blocking and masking for Primary Account Numbers (PAN) with Luhn checksum validation.
- CVV/CVC and card magnetic track data exfiltration prevention.
- Mandatory dual-approval (4-eyes) HITL escalation for payment processing and refund dispatch tools.

### 10. `nist-ai-rmf-pack`
NIST Artificial Intelligence Risk Management Framework (AI RMF 1.0) controls:
- **Map:** Continuous Shadow AI asset discovery and cataloging.
- **Measure:** Tier-1/Tier-2 prompt injection, toxicity, and NLI faithfulness scoring.
- **Manage:** Multi-layer circuit breakers, budget limits, and delegation loop breakers.
- **Govern:** Centralized multi-tenant policy enforcement, role-based tool access, and tamper-evident audit ledger.

### 11. `text-to-sql-pack`
Enterprise Text-to-SQL & Database Query Guardrails:
- Strict SELECT-only execution mode (hard-blocks `DROP`, `DELETE`, `TRUNCATE`, `ALTER`, `GRANT`, `REVOKE`, `INSERT`, `UPDATE`).
- Sensitive catalog and credential table denylist (`pg_shadow`, `pg_authid`, `system_secrets`, `users_credentials`).
- Sensitive column blocking (`password_hash`, `secret_key`, `auth_token`, `ssn`, `credit_card`).
- Automatic `LIMIT` clamping and mandatory tenant isolation predicate injection (`WHERE (user_where) AND tenant_id = '...'`).
- Multi-turn Crescendo escalation on high cumulative query risk scores.

---

## 6. Developer SDKs & Ecosystem Adapters

### Standalone Python SDK (`aegisgate`)
Install as a lightweight standalone package without server dependencies:
```bash
pip install -e sdks/python
```

#### Native Framework Adapters

##### LangGraph Agent Guard
```python
from aegisgate.adapters import LangGraphGuard

guard = LangGraphGuard(policy_pack_id="agent-fleet-pack")

# Wrap LangGraph node functions with pre-step and post-step guardrails
governed_search = guard.wrap_node(search_node, node_name="search_step")
```

##### FastMCP Server Tool Interceptor
```python
from aegisgate.adapters import FastMcpGuard

guard = FastMcpGuard(policy_pack_id="base-enterprise")

@guard.tool(name="execute_query")
async def execute_query(sql: str) -> dict:
    # Tool pre-call and post-call validation automatically executed
    return await db.fetch(sql)
```

##### CrewAI Task & Tool Guard
```python
from aegisgate.adapters import CrewAIGuard

guard = CrewAIGuard(policy_pack_id="base-enterprise", agent_role="analyst")

# Wrap individual CrewAI tools with pre-call parameter checking and post-call output redaction
governed_tool = guard.wrap_tool(database_query_tool, tool_name="db_query")
```

##### LlamaIndex RAG & Query Engine Guard
```python
from aegisgate.adapters import LlamaIndexGuard

guard = LlamaIndexGuard(policy_pack_id="rag-copilot-pack", actor_role="internal")

# Filter retrieved document nodes according to caller clearance before LLM synthesis
filtered_nodes = await guard.post_retrieval_filter(retrieved_nodes, query_str=user_query)

# Guard final synthesized response against hallucination and data leakage
safe_response = await guard.post_response_guard(response.response, query_str=user_query)
```

##### OpenAI SDK Client Adapter
```python
from openai import OpenAI
from aegisgate.adapters import AegisOpenAIAdapter

adapter = AegisOpenAIAdapter(
    base_url="http://localhost:8088/proxy/llm/v1",
    api_key="ag_live_client_key_here",
    policy_pack_id="rag-copilot-pack",
)
client = OpenAI(**adapter.get_client_kwargs())
```

### TypeScript / JavaScript SDK (`@aegisgate/sdk`)
Install for Node.js, Bun, or Browser environments:
```bash
npm install @aegisgate/sdk
```
Supports Virtual API Key authentication, streaming proxy inspection, HITL polling (`waitForApproval`), and Vercel AI SDK middleware wrapping (`wrapTool`).

---

## 7. GitOps CLI (`aegisctl`)

The `aegisctl` CLI validates and simulates policies within CI/CD pipelines before production deployment:

```bash
# Validate policy syntax, schema, and plugin registry scanner availability
python -m cli.aegisctl.main validate policy_packs/rag-copilot-pack/policy.yaml

# Run automated test assertions against a policy pack
python -m cli.aegisctl.main test policy_packs/rag-copilot-pack/policy.yaml tests/fixtures/test_cases.json

# Replay historical audit logs through candidate policy packs to preview blast-radius
python -m cli.aegisctl.main replay policy_packs/rag-copilot-pack/policy.yaml tests/fixtures/audit_log.json
```

---

## 8. Regulatory Compliance Mapping

AegisGate satisfies international AI governance, financial, and cybersecurity compliance frameworks:

| Framework | Control / Standard | AegisGate Implementation |
| :--- | :--- | :--- |
| **OWASP Top 10 for LLM** | **LLM01: Prompt Injection** | Tier-1 regex/entropy guards + Tier-2 ONNX local classifier + Tier-3 LLM judge. |
| **OWASP Top 10 for LLM** | **LLM02: Sensitive Info Disclosure** | Ephemeral Reversible PII Vault with AES-256-GCM tokenization & secrets scanner. |
| **OWASP Top 10 for LLM** | **LLM06: Excessive Agency** | Sliding-window loop breaker, delegation depth limit, role-based tool allowlists. |
| **SOC 2 Type II** | **CC6.1 - Logical Access & Least Privilege** | Multi-tenant RBAC, scoped API keys, parameter validation guards. |
| **SOC 2 Type II** | **CC6.8 - Non-Repudiation & Audit Trail** | Cryptographic hash-chained audit ledger: `SHA256(prev_hash || payload)`. |
| **EU AI Act** | **Article 12: Record-Keeping** | Automated chronological logging of all agent actions, prompts, and verdicts. |
| **EU AI Act** | **Article 14: Human Oversight** | Mandatory 4-eyes Human-in-the-Loop approval workflows for high-risk actions. |

---

## 9. Testing & Quality Verification

Run full test suite (148 tests across Phases 1–16 with 100% pass rate and >=85% core coverage):
```bash
pytest --cov=core --cov-report=term-missing
```

Run Phase 16 Deep Security Remediation Suite:
```bash
pytest tests/redteam/test_phase16_remediation.py -v
```

Run Red-Team Injection Benchmark:
```bash
pytest tests/redteam/test_injection_benchmark.py -v -s
```

Run Fast-Path P95 Latency Benchmark & E2E HTTP Latency Benchmark:
```bash
pytest tests/benchmarks/ -v -s
```

Validate All 11 Policy Packs:
```bash
Get-ChildItem -Path policy_packs -Recurse -Filter "policy.yaml" | ForEach-Object { python -m cli.aegisctl.main validate $_.FullName }
```

Run TypeScript SDK Tests & Dashboard Build:
```bash
npm --prefix sdks/typescript test && npm --prefix sdks/typescript run build
npm --prefix dashboard run build
```

---

## 10. Shipped Features & Universal Roadmap

### Shipped in Phases 1–16 (Universal Platform v4.0):
1. **Universal Multi-Protocol Proxies:** Native streaming reverse proxies for OpenAI, Anthropic Claude, Google Gemini, AWS Bedrock Converse, and Azure OpenAI with SSE credential leak abort and token reconciliation.
2. **Realtime Voice & WebSocket Streaming Proxy:** Bidirectional WebSocket stream proxy (`/proxy/realtime/v1/ws`) with sub-millisecond kill switch, input/output transcript scanning, and tool pre-call governance.
3. **Multi-Turn Crescendo Defense:** Sliding-window conversational risk accumulation with exponential decay (`ConversationRiskTracker`).
4. **SQL AST Governance Scanner:** AST rewriting parser (`SqlAstGuard`) with `sqlglot` dialect support, SELECT-only mode, and safe WHERE-clause parenthesization.
5. **Zero-Plaintext Key PII Vault & Enterprise KMS:** HMAC-SHA256 hashed Redis keys (`aegis:vault:pii_hash:{hash}`) with pluggable Vault Transit and AWS KMS providers.
6. **Turnkey Regulatory Packs:** 11 production YAML policy packs (EU AI Act, HIPAA, PCI DSS, NIST AI RMF, Text-to-SQL, Agent Fleet, SOC, Log Analysis, etc.) with 1-click compliance export.
7. **Ecosystem Adapters:** LangGraph, FastMCP, CrewAI, LlamaIndex, and Temporal activity adapters handling suspension, escalation, and parameter mutations.
8. **GitOps Strict Validation:** `aegisctl validate` verifying scanner config schemas and valid pipeline stages.

### Upcoming Architecture Roadmap:
1. **Intelligent FinOps & Resiliency:** Semantic caching for instant 0ms responses, automatic provider failover, and dynamic model tier routing.
2. **Enterprise IAM & Directory Sync:** SCIM 2.0 provisioning and Okta/Entra ID automated group-to-role mappings.
3. **Distributed Edge PDP:** Envoy WASM filters and eBPF sidecar daemons for zero-network-hop microsecond governance at the pod level.

For complete architectural deep-dives, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## License
Apache License 2.0. Copyright (c) 2026 AegisGate Authors.
