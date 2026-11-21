# AegisGate Python SDK

Thin, asynchronous and synchronous Python SDK for the **AegisGate AI Guardrails & Governance Policy Decision Point**.

## Installation

```bash
pip install aegisgate
```

## Quickstart

```python
from aegisgate import AegisClient, governed_tool

client = AegisClient(
    base_url="http://localhost:8088",
    api_key="ag_live_your_key_here",
    tenant_id="acme-corp",
)

@governed_tool(client=client, name="contain_host")
def contain_host(asset_id: str):
    return f"Contained {asset_id}"
```
