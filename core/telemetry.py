from prometheus_client import Counter, Gauge, Histogram

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

TOKEN_USAGE_COUNTER = Counter(
    "aegisgate_tokens_used_total",
    "Total LLM tokens tracked and governed",
    ["tenant_id", "model"],
)

SCANNER_VIOLATION_COUNTER = Counter(
    "aegisgate_scanner_violations_total",
    "Total scanner violations detected across pipeline tiers",
    ["scanner_name", "status"],
)

QUARANTINED_TOOL_GAUGE = Gauge(
    "aegisgate_quarantined_tools_total",
    "Current count of MCP tools quarantined under Anti-Rug-Pull governance",
    ["tenant_id"],
)


def record_evaluation_metric(tenant_id: str, stage: str, decision: str, latency_seconds: float) -> None:
    try:
        EVALUATION_COUNTER.labels(tenant_id=tenant_id, stage=stage, decision=decision).inc()
        EVALUATION_LATENCY.labels(stage=stage).observe(latency_seconds)
    except Exception as e:
        logger.debug("telemetry_record_failed", error=str(e))


def record_scanner_violation(scanner_name: str, status: str) -> None:
    try:
        SCANNER_VIOLATION_COUNTER.labels(scanner_name=scanner_name, status=status).inc()
    except Exception as e:
        logger.debug("scanner_violation_telemetry_failed", error=str(e))


def record_token_metric(tenant_id: str, model: str, tokens: int) -> None:
    try:
        TOKEN_USAGE_COUNTER.labels(tenant_id=tenant_id, model=model).inc(tokens)
    except Exception as e:
        logger.debug("token_telemetry_failed", error=str(e))

