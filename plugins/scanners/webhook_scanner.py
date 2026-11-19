import hashlib
import hmac
import json
import time
from typing import Any, Dict, Optional
import httpx
from pydantic import BaseModel, ConfigDict, Field
from core.registry.interfaces import BaseScanner, ScannerResult
from core.schemas.events import EvaluationRequest


class WebhookScannerConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    enabled: bool = True
    endpoint_url: str = "http://localhost:9000/scan"
    secret_key: str = "default-webhook-secret"
    timeout_ms: int = 500
    on_timeout: str = "flag"  # "allow" | "deny" | "flag"
    custom_headers: Dict[str, str] = Field(default_factory=dict)


class WebhookScanner(BaseScanner):
    name = "webhook_scanner"
    version = "1.0.0"
    tier = 1
    supported_stages = [
        "llm_input",
        "llm_output",
        "tool_pre_call",
        "tool_post_call",
        "agent_handoff",
    ]
    config_schema = WebhookScannerConfig

    async def scan(
        self,
        request: EvaluationRequest,
        context: dict[str, Any],
        config: BaseModel,
    ) -> ScannerResult:
        cfg = config if isinstance(config, WebhookScannerConfig) else WebhookScannerConfig(**config.model_dump())
        if not cfg.enabled or not cfg.endpoint_url:
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        payload = {
            "request_id": request.request_id,
            "tenant_id": request.tenant_id,
            "workspace_id": request.workspace_id,
            "stage": request.stage.value if hasattr(request.stage, "value") else str(request.stage),
            "actor": request.actor.model_dump(),
            "action": request.action.model_dump(),
            "content": request.content.model_dump(),
            "context": context,
        }
        body_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        timestamp = str(int(time.time()))

        # Compute HMAC-SHA256 signature
        signature = hmac.new(
            cfg.secret_key.encode("utf-8"),
            msg=timestamp.encode("utf-8") + b"." + body_bytes,
            digestmod=hashlib.sha256,
        ).hexdigest()

        headers = {
            "Content-Type": "application/json",
            "X-AegisGate-Timestamp": timestamp,
            "X-AegisGate-Signature": f"sha256={signature}",
            **cfg.custom_headers,
        }

        timeout_sec = max(0.05, cfg.timeout_ms / 1000.0)

        try:
            async with httpx.AsyncClient(timeout=timeout_sec) as client:
                resp = await client.post(cfg.endpoint_url, content=body_bytes, headers=headers)
                if resp.status_code != 200:
                    return ScannerResult(
                        scanner_name=self.name,
                        tier=self.tier,
                        status="flag",
                        score=0.5,
                        details={"http_status": resp.status_code, "body": resp.text[:200]},
                        message=f"Webhook scanner HTTP error {resp.status_code}",
                    )
                data = resp.json()
                return ScannerResult(
                    scanner_name=self.name,
                    tier=self.tier,
                    status=data.get("status", "pass"),
                    score=float(data.get("score", 0.0)),
                    details=data.get("details", {}),
                    message=data.get("message"),
                    mutated_content=data.get("mutated_content"),
                    mutated_parameters=data.get("mutated_parameters"),
                )
        except (httpx.TimeoutException, httpx.RequestError) as e:
            fallback_status = "block" if cfg.on_timeout == "deny" else "flag" if cfg.on_timeout == "flag" else "pass"
            return ScannerResult(
                scanner_name=self.name,
                tier=self.tier,
                status=fallback_status,
                score=0.5 if fallback_status != "pass" else 0.0,
                details={"error": str(e), "on_timeout": cfg.on_timeout},
                message=f"Webhook scanner timeout/error: {str(e)} (fallback: {fallback_status})",
            )
