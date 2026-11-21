from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field

from core.logger import get_logger
from core.registry.interfaces import BaseNotifier
from core.security.ssrf import SSRFProtectionError, validate_outbound_url

logger = get_logger("plugins.notifiers.slack")


class SlackNotifierConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    webhook_url: str = Field(..., description="Slack Incoming Webhook URL")
    channel: str = Field(default="", description="Optional channel override")
    include_risk_score: bool = Field(default=True, description="Whether to include numeric risk score")


class SlackNotifier(BaseNotifier):
    name: str = "slack_notifier"
    version: str = "1.0.0"
    config_schema: type[BaseModel] = SlackNotifierConfig

    async def notify(
        self,
        event_type: str,
        payload: dict[str, Any],
        config: BaseModel,
    ) -> bool:
        cfg = config if isinstance(config, SlackNotifierConfig) else SlackNotifierConfig(**config.model_dump())
        decision = payload.get("decision", "UNKNOWN")
        trace_id = payload.get("trace_id", "N/A")
        risk = payload.get("risk_score", 0.0)

        color = "#36a64f" if decision == "ALLOW" else ("#ffcc00" if decision == "SUSPEND_FOR_APPROVAL" else "#ff0000")

        fields = [
            {"title": "Event Type", "value": event_type, "short": True},
            {"title": "Decision", "value": decision, "short": True},
            {"title": "Trace ID", "value": trace_id, "short": True},
        ]
        if cfg.include_risk_score:
            fields.append({"title": "Risk Score", "value": f"{risk:.2f}", "short": True})

        slack_body = {
            "attachments": [
                {
                    "color": color,
                    "title": f"AegisGate Alert: {event_type} [{decision}]",
                    "fields": fields,
                    "footer": "AegisGate Security & Governance Engine",
                }
            ]
        }
        if cfg.channel:
            slack_body["channel"] = cfg.channel

        # SSRF validation
        try:
            await validate_outbound_url(cfg.webhook_url, target_type="slack_notifier")
        except SSRFProtectionError as e:
            logger.warning("slack_notifier_ssrf_blocked", url=cfg.webhook_url, error=str(e))
            return False

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(cfg.webhook_url, json=slack_body)
                return resp.status_code < 400
        except Exception as e:
            logger.warning("slack_notification_failed", url=cfg.webhook_url, error=str(e))
            return False

