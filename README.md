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
- **Sub-15ms Fast Path:** Tier-1 deterministic evaluation achieves **0.33ms P95 latency** under real workloads (DoD target: < 15ms).
- **Red-Team Injection Benchmark:** Achieves **100.0% prompt injection detection** (41/41 attacks caught) with **0.00% False Positive Rate** (0/41 benign logs flagged) on security evaluation corpora.
- **Strict Decoupling:** Core governance mechanics (`core/`) contain **zero domain-specific code**; all domain logic is strictly isolated in `plugins/` and `policy_packs/`.
- **Tamper-Evident Ledger:** Every policy verdict is chained to its predecessor via `prev_hash`, enabling continuous topological Merkle integrity checks.
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
To verify all 6 core enterprise scenarios (secrets masking, HITL dual approval, prompt injection, loop breaker, kill switch, and audit chain verification) without external dependencies:

```bash
python scripts/demo_showcase.py
python scripts/verify_system.py
```

---

## 3. Endpoints & Gateways

AegisGate can run on standard ports (`3000`/`8000`) or dedicated conflict-free development ports (`3088`/`8088`):

| Component | Port (Dev / Docker) | Path / URL | Description |
| :--- | :--- | :--- | :--- |
| **Control Plane Dashboard** | `3088` / `3000` | `http://localhost:3088` | React 18 + TS UI (Policy Studio, HITL, Kill Switch, Merkle Forensics) |
| **PDP Evaluation Gateway** | `8088` / `8000` | `/v1/evaluate` | Primary REST PDP endpoint for tool and LLM evaluation |
| **OpenAI LLM Reverse Proxy** | `8088` / `8000` | `/proxy/llm/v1/chat/completions` | Transparent LLM gateway with rolling SSE token stream evaluation |
| **MCP Tool Gateway** | `8088` / `8000` | `/proxy/mcp/jsonrpc` | Model Context Protocol JSON-RPC 2.0 tool guardrail gateway |
| **REST Tool Gateway** | `8088` / `8000` | `/proxy/tools/{tool_name}` | Generic HTTP tool execution guardrail proxy |
| **HITL Approvals Inbox** | `8088` / `8000` | `/v1/approvals` | Human-in-the-Loop decision and parameter override API |
| **Audit & Merkle Verifier** | `8088` / `8000` | `/v1/audit/verify` | Cryptographic hash-chain continuity and tamper detection |
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

---

## 6. Developer SDKs

### Python SDK (`aegisgate`)
```python
from aegisgate import AegisClient, governed_tool, governed_llm

client = AegisClient(
    endpoint="http://localhost:8088",
    api_key="aegis_live_your_key_here",
    tenant_id="acme-corp",
)

# Protect a tool function with automatic pre/post call guardrails
@governed_tool(client=client, policy_pack="soc-investigation-pack")
def isolate_host(asset_id: str):
    # This code only executes if AegisGate returns ALLOW
    return f"Isolated {asset_id}"

# Protect LLM invocations with automatic prompt and response screening
@governed_llm(client=client, policy_pack="base-enterprise")
def analyze_data(prompt: str) -> str:
    # Prompt is scrubbed for PII and secrets prior to reaching provider
    return openai_client.chat.completions.create(...)
```

### TypeScript / Node SDK (`@aegisgate/sdk`)
```typescript
import { AegisClient } from '@aegisgate/sdk';

const client = new AegisClient({
  endpoint: 'http://localhost:8088',
  apiKey: process.env.AEGIS_API_KEY!,
  tenantId: 'acme-corp',
});

const verdict = await client.evaluate({
  stage: 'tool_pre_call',
  policyPackId: 'agent-fleet-pack',
  actor: { id: 'agent-worker-03', role: 'researcher' },
  action: { name: 'deploy_container', parameters: { image: 'alpine:latest' } },
});

if (verdict.decision !== 'ALLOW') {
  throw new Error(`Execution blocked by AegisGate: ${verdict.reason}`);
}
```

---

## 7. Regulatory Compliance Mapping

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

## 8. Testing & Quality Verification

Run full test suite:
```bash
pytest --cov=core --cov-report=term-missing
```

Run Red-Team Injection Benchmark:
```bash
pytest tests/redteam/test_injection_benchmark.py -v -s
```

Run Fast-Path P95 Latency Benchmark:
```bash
pytest tests/benchmarks/test_tier1_benchmark.py -v -s
```

Run End-to-End System Verification:
```bash
python scripts/verify_system.py
```

Build Control Plane UI:
```bash
npm --prefix dashboard run build
```

---

## 9. Architecture Roadmap (Road to Universal Governance)

To scale into a global, universal guardrails and governance platform, the architectural evolution roadmap encompasses:
1. **Universal Protocol Translation:** Native adapter endpoints for Anthropic Claude (Messages API), Google Gemini, AWS Bedrock, and Ollama.
2. **Multimodal Guardrails:** OCR PII scanning on uploaded documents and vision-based adversarial injection detection.
3. **Turnkey Framework Integrations:** Native 1-line callback handlers for LangChain/LangGraph, LlamaIndex, CrewAI, and Semantic Kernel.
4. **Intelligent FinOps & Resiliency:** Semantic caching for instant 0ms responses, automatic provider failover, and dynamic model tier routing.
5. **Enterprise IAM & Key Management:** SAML 2.0 / OIDC SSO (Okta, Microsoft Entra ID), SCIM provisioning, and Cloud KMS (AWS KMS, HashiCorp Vault).
6. **Distributed Edge PDP:** Envoy WASM filters and sidecar daemons for zero-network-hop microsecond governance at the pod level.

For complete architectural deep-dives, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## License
Apache License 2.0. Copyright (c) 2026 AegisGate Authors.
