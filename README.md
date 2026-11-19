# AegisGate

> **Commercial-Grade, Domain-Agnostic AI Guardrails & Governance Policy Decision Point (PDP)**
> Built for mission-critical enterprise AI agent fleets, autonomous tool execution, and sovereign LLM workflows.

---

## 1. Executive Summary & Architectural Guarantees

AegisGate is a high-throughput, sub-15ms Policy Decision Point (PDP) designed to govern autonomous LLM agents and tools with cryptographic guarantees, verifiable compliance, and zero domain pollution.

```
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
|   | Tier 1: Deterministic Engine (< 15ms target; 7.86ms measured P95)                       |   |
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
|   |  - High-precision prompt injection & jailbreak detection (0% FP baseline)               |   |
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

### Key Performance & Governance Metrics
- **Sub-15ms Fast Path:** Tier-1 deterministic evaluation achieves **7.86ms P95 latency** under real workloads.
- **Red-Team Injection Benchmark:** Achieves **100.0% prompt injection detection** with **0.00% False Positive Rate** on standard evasion corpora.
- **Strict Decoupling:** Core governance mechanics (`core/`) contain **zero domain-specific code**; all domain logic is strictly isolated in `plugins/` and `policy_packs/`.
- **Tamper-Evident Ledger:** Every policy verdict is chained to its predecessor via `prev_hash`, enabling continuous topological Merkle integrity checks.

---

## 2. Quickstart & Deployment

### Run Complete Multi-Container Stack (Docker Compose)
Start the PostgreSQL 16 database, Redis 7 cache, AegisGate PDP Engine, and Control Plane Dashboard with one command:

```bash
cd deploy
docker compose up --build -d
```

### Bootstrap Demo Tenant & Reference Packs
Run the idempotent seeding wizard to initialize the database schema, register the SuperAdmin user, issue scoped API keys, and compile reference policy packs:

```bash
python scripts/seed_demo.py
```

### Endpoints
| Component | URL | Description |
| :--- | :--- | :--- |
| **Control Plane Dashboard** | `http://localhost:3000` | Full Web UI (Policy Studio, HITL, Kill Switches, Audit Merkle Lab) |
| **PDP Evaluation Gateway** | `http://localhost:8000/v1/evaluate` | Primary REST PDP endpoint for tool and LLM evaluation |
| **OpenAI LLM Proxy** | `http://localhost:8000/v1/chat/completions` | Transparent LLM gateway with rolling SSE token stream evaluation |
| **MCP Tool Gateway** | `http://localhost:8000/v1/mcp` | Model Context Protocol JSON-RPC 2.0 tool guardrail gateway |
| **Health Check** | `http://localhost:8000/healthz` | Kubernetes liveness and readiness probe |
| **Prometheus Telemetry** | `http://localhost:8000/metrics` | Real-time Prometheus metrics for scrapers and Grafana |

---

## 3. Quick PDP Evaluation Example

Evaluate an agent's intended tool execution against the `soc-investigation-pack`:

```bash
curl -X POST http://localhost:8000/v1/evaluate \
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
      "name": "contain_host",
      "parameters": {
        "asset_id": "srv-dc-01",
        "action": "isolate"
      }
    }
  }'
```

### Response (Blocked Domain Controller Containment):
```json
{
  "trace_id": "tr-550e8400-e29b-41d4-a716-446655440000",
  "decision": "DENY",
  "reason": "Host srv-dc-01 is designated as a critical Domain Controller in CMDB. Autonomous containment prohibited.",
  "latency_ms": 7.42,
  "triggered_rules": [
    {
      "rule_id": "soc-deny-domain-controller-containment",
      "reason": "Containment strictly prohibited on Domain Controllers without executive authorization",
      "severity": "CRITICAL",
      "compliance_tags": ["SOC2-CC6.1", "OWASP-LLM06"]
    }
  ],
  "scanner_findings": []
}
```

---

## 4. Production Reference Policy Packs

AegisGate ships with four production-ready, domain-specific reference policy packs in `policy_packs/`:

### 1. `base-enterprise`
Universal baseline guardrails for any enterprise deployment:
- High-entropy credential and API key detection (AWS, GitHub, Slack tokens).
- Reversible PII tokenization (email addresses, SSNs, credit cards).
- Shell parameter safety guards (blocks `rm -rf /`, dangerous forks, unquoted shell metas).

### 2. `soc-investigation-pack`
Autonomous Security Operations Center (SOC) agent governance:
- Dynamic CMDB asset enrichment via `http_context_resolver`.
- Hard-blocks containment on active Domain Controllers and critical assets.
- Enforces dual 4-eyes Human-in-the-Loop (`require_approval`) for tier-1 network segment isolation.
- Dispatches security event alerts to SIEM via Common Event Format (`siem_cef_notifier`).

### 3. `agent-fleet-pack`
Multi-agent collaborative orchestration guardrails:
- Maximum delegation depth cap (enforces max call-stack limit to prevent recursive agent exhaustion).
- Agent role tool allowlisting (e.g. `summarizer` agent cannot execute infrastructure modification tools).
- Sliding-window loop breaker (detects cyclic duplicate tool invocations within a rolling window of N calls).
- Dispatches loop alerts to operators via Slack (`slack_notifier`).

### 4. `log-analysis-pack`
High-volume SIEM and server log security:
- Tier-2 ONNX ML classifier scans incoming raw logs for embedded prompt injections.
- Reversible PII masking protects employee/customer identities before feeding logs to external LLMs.
- Strict output JSON schema validation guarantees consistent forensic anomaly reports.

---

## 5. Developer SDKs

### Python SDK (`aegisgate`)
Install via pip or include in your application:

```python
from aegisgate import AegisClient, governed_tool, governed_llm

client = AegisClient(
    endpoint="http://localhost:8000",
    api_key="aegis_live_your_key_here",
    tenant_id="acme-corp",
)

# Protect a tool function with automatic pre/post call guardrails
@governed_tool(client=client, policy_pack="soc-investigation-pack")
def contain_host(asset_id: str, action: str):
    # This code only executes if AegisGate returns ALLOW
    return f"Contained {asset_id} with {action}"

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
  endpoint: 'http://localhost:8000',
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

## 6. Regulatory Compliance Mapping

AegisGate is built to satisfy international AI governance, financial, and cybersecurity compliance frameworks:

| Framework | Control / Standard | AegisGate Implementation |
| :--- | :--- | :--- |
| **OWASP Top 10 for LLM** | **LLM01: Prompt Injection** | Tier-1 regex/entropy guards + Tier-2 ONNX local classifier + Tier-3 LLM semantic judge. |
| **OWASP Top 10 for LLM** | **LLM02: Sensitive Info Disclosure** | Ephemeral Reversible PII Vault with AES-256-GCM tokenization & secrets scanner. |
| **OWASP Top 10 for LLM** | **LLM06: Excessive Agency** | Sliding-window loop breaker, delegation depth limit, role-based tool allowlists. |
| **SOC 2 Type II** | **CC6.1 - Logical Access & Least Privilege** | Multi-tenant RBAC, scoped API keys, parameter validation guards. |
| **SOC 2 Type II** | **CC6.8 - Non-Repudiation & Audit Trail** | Cryptographic hash-chained audit ledger: `SHA256(prev_hash || payload)`. |
| **EU AI Act** | **Article 12: Record-Keeping** | Automated chronological logging of all agent actions, prompts, and verdicts. |
| **EU AI Act** | **Article 14: Human Oversight** | Mandatory 4-eyes Human-in-the-Loop approval workflows for high-risk actions. |

---

## 7. Testing & Quality Verification

Run the full test suite with coverage:
```bash
pytest --cov=core --cov-report=term-missing
```

Run Red-Team Injection Benchmark:
```bash
python -m pytest tests/benchmarks/test_injection_benchmark.py -v -s
```

Run Fast-Path P95 Latency Benchmark:
```bash
python -m pytest tests/benchmarks/test_fast_path_latency.py -v -s
```

---

## License
Apache License 2.0. Copyright (c) 2026 AegisGate Authors.
