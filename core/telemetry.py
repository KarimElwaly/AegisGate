from prometheus_client import Counter, Histogram

from core.logger import get_logger

logger = get_logger("core.telemetry")

EVALUATION_COUNTER = Counter(
    "aegisgate_evaluations_total",
    "Total policy evaluation requests processed by PDP",
    ["tenant_id", "stage", "decision"],
)

EVALUATION_LATENCY = Histogram(
    "aegisgate_evaluation_latency_seconds",
    "PDP evaluation latency distribution in seconds",
    ["stage"],
    buckets=[0.001, 0.003, 0.005, 0.010, 0.015, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0, 2.5],
)

KILL_SWITCH_COUNTER = Counter(
    "aegisgate_kill_switch_trips_total",
    "Total requests blocked by the emergency kill switch",
    ["scope"],
)

HITL_TICKET_COUNTER = Counter(
    "aegisgate_hitl_tickets_total",
    "Total Human-in-the-Loop tickets created or finalized",
    ["action_type", "status"],
)


def record_evaluation_metric(tenant_id: str, stage: str, decision: str, latency_seconds: float) -> None:
    try:
        EVALUATION_COUNTER.labels(tenant_id=tenant_id, stage=stage, decision=decision).inc()
        EVALUATION_LATENCY.labels(stage=stage).observe(latency_seconds)
    except Exception as e:
        logger.debug("telemetry_record_failed", error=str(e))

