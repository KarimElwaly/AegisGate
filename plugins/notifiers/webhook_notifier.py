import hashlib
import hmac
import json
from typing import Any, Dict, Type
import httpx
from pydantic import BaseModel, ConfigDict, Field
from core.logger import get_logger
from core.registry.interfaces import BaseNotifier

logger = get_logger("plugins.notifiers.webhook")


class WebhookNotifierConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    endpoint_url: str = Field(..., description="Destination HTTP webhook endpoint URL")
    secret: str = Field(default="", description="Secret for HMAC-SHA256 signature")
    timeout_seconds: float = Field(default=5.0, description="HTTP request timeout in seconds")


class WebhookNotifier(BaseNotifier):
    name: str = "webhook_notifier"
    version: str = "1.0.0"
    config_schema: Type[BaseModel] = WebhookNotifierConfig

    async def notify(
        self,
        event_type: str,
        payload: Dict[str, Any],
        config: BaseModel,
    ) -> bool:
        cfg = config if isinstance(config, WebhookNotifierConfig) else WebhookNotifierConfig(**config.model_dump())
        body_dict = {
            "event_type": event_type,
            "payload": payload,
        }
        body_bytes = json.dumps(body_dict, default=str, separators=(",", ":")).encode("utf-8")

        headers = {"Content-Type": "application/json"}
        if cfg.secret:
            sig = hmac.new(cfg.secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
            headers["X-Aegis-Signature"] = f"sha256={sig}"

        try:
            async with httpx.AsyncClient(timeout=cfg.timeout_seconds) as client:
                resp = await client.post(cfg.endpoint_url, content=body_bytes, headers=headers)
                return resp.status_code < 400
        except Exception as e:
            logger.warning("webhook_notification_failed", url=cfg.endpoint_url, error=str(e))
            return False
