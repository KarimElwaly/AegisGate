import asyncio
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field

from core.logger import get_logger
from core.registry.interfaces import BaseNotifier

logger = get_logger("plugins.notifiers.siem_cef")


class SiemCefNotifierConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    siem_endpoint_url: str | None = Field(default=None, description="HTTP/Syslog collector endpoint URL")
    siem_host: str | None = Field(default=None, description="Target SIEM host for socket syslog")
    siem_port: int = Field(default=514, description="Target SIEM syslog port")
    facility: str = Field(default="local4", description="Syslog facility")


class SiemCefNotifier(BaseNotifier):
    name: str = "siem_cef_notifier"
    version: str = "1.0.0"
    config_schema: type[BaseModel] = SiemCefNotifierConfig

    def format_cef(self, event_type: str, payload: dict[str, Any]) -> str:
        """
        Formats event into standard ArcSight Common Event Format (CEF):
        CEF:0|AegisGate|PDP|1.0|SignatureID|Name|Severity|Extension
        """
        decision = payload.get("decision", "UNKNOWN")
        severity = 10 if decision == "DENY" else (7 if decision == "SUSPEND_FOR_APPROVAL" else 3)
        tenant_id = payload.get("tenant_id", "default")
        trace_id = payload.get("trace_id", "unknown")
        action = payload.get("action", {}).get("name") if isinstance(payload.get("action"), dict) else str(payload.get("action", "unknown"))
        risk = payload.get("risk_score", 0.0)

        ext = f"src={tenant_id} act={action} cs1={trace_id} cs1Label=TraceID cfp1={risk} cfp1Label=RiskScore msg={decision}"
        return f"CEF:0|AegisGate|PDP|1.0|{event_type}|PolicyDecision|{severity}|{ext}"

    async def notify(
        self,
        event_type: str,
        payload: dict[str, Any],
        config: BaseModel,
    ) -> bool:
        cfg = config if isinstance(config, SiemCefNotifierConfig) else SiemCefNotifierConfig(**config.model_dump())
        cef_line = self.format_cef(event_type, payload)

        if cfg.siem_endpoint_url:
            try:
                async with httpx.AsyncClient(timeout=4.0) as client:
                    resp = await client.post(cfg.siem_endpoint_url, content=cef_line.encode("utf-8"), headers={"Content-Type": "text/plain"})
                    return resp.status_code < 400
            except Exception as e:
                logger.warning("siem_http_notification_failed", url=cfg.siem_endpoint_url, error=str(e))
                return False

        if cfg.siem_host:
            # Send via TCP/UDP stream if host is configured
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(cfg.siem_host, cfg.siem_port),
                    timeout=2.0,
                )
                writer.write((cef_line + "\n").encode("utf-8"))
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return True
            except Exception as e:
                logger.warning("siem_socket_notification_failed", host=cfg.siem_host, error=str(e))
                return False

        # In local/test mode without remote SIEM, log at info
        logger.info("siem_cef_alert", cef=cef_line)
        return True

