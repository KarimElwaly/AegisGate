import time
import numpy as np
import pytest
from core.pipeline.orchestrator import PipelineOrchestrator
from core.schemas.events import ActionModel, ContentModel, EvaluationRequest


@pytest.mark.asyncio
async def test_tier1_p95_latency_benchmark():
    orchestrator = PipelineOrchestrator()
    req = EvaluationRequest(
        tenant_id="benchmark-tenant",
        policy_pack_id="base-enterprise",
        stage="llm_input",
        content=ContentModel(trusted_instructions="Summarize system telemetry metrics for host server-99."),
        action=ActionModel(name="query_telemetry", parameters={"host": "server-99"}),
    )

    # Warm-up 10 runs
    for _ in range(10):
        await orchestrator.evaluate(req)

    # Benchmark 100 iterations
    latencies = []
    for _ in range(100):
        t0 = time.perf_counter()
        verdict = await orchestrator.evaluate(req)
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1000.0)
        assert verdict.decision == "ALLOW"

    p50 = float(np.percentile(latencies, 50))
    p95 = float(np.percentile(latencies, 95))
    p99 = float(np.percentile(latencies, 99))

    print(f"\n--- Tier-1 Fast Path Benchmark Results (100 runs) ---")
    print(f"P50 Latency: {p50:.2f} ms")
    print(f"P95 Latency: {p95:.2f} ms")
    print(f"P99 Latency: {p99:.2f} ms")
    print(f"Target: P95 < 15.0 ms")

    # Assert P95 satisfies DoD threshold
    assert p95 < 15.0, f"Tier-1 P95 latency {p95:.2f}ms exceeded 15.0ms threshold"
