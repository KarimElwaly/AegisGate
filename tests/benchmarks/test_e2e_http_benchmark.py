import time
import numpy as np
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_e2e_http_latency_benchmark(api_client: AsyncClient):
    """Measures real end-to-end HTTP request/response latency across

    FastAPI route handling + security + Redis state + Tier-1 PDP pipeline + JSON encoding.
    Clearly distinguishes network/HTTP stack overhead from in-memory engine microbenchmark.
    """
    payload = {
        "tenant_id": "benchmark-tenant",
        "policy_pack_id": "base-enterprise",
        "stage": "llm_input",
        "actor": {"id": "http-bench-actor", "role": "service"},
        "action": {"name": "query_telemetry", "parameters": {"host": "server-99"}},
        "content": {"trusted_instructions": "Summarize system telemetry metrics for host server-99."},
    }

    # Warm-up 10 runs
    for _ in range(10):
        resp = await api_client.post("/v1/evaluate", json=payload)
        assert resp.status_code == 200

    # Benchmark 100 runs over real HTTP ASGI transport
    latencies = []
    for _ in range(100):
        t0 = time.perf_counter()
        resp = await api_client.post("/v1/evaluate", json=payload)
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1000.0)
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "ALLOW"

    p50 = float(np.percentile(latencies, 50))
    p95 = float(np.percentile(latencies, 95))
    p99 = float(np.percentile(latencies, 99))

    print("\n--- Real E2E HTTP Latency Benchmark (100 HTTP requests) ---")
    print(f"HTTP P50 Latency: {p50:.2f} ms")
    print(f"HTTP P95 Latency: {p95:.2f} ms")
    print(f"HTTP P99 Latency: {p99:.2f} ms")
    print("Target: HTTP P95 < 35.0 ms (Full Web Stack)")

    assert p95 < 35.0, f"Real E2E HTTP P95 latency {p95:.2f}ms exceeded 35.0ms threshold"
