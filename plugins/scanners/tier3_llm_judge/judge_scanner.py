import asyncio
import json
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict

from core.config import get_settings
from core.logger import get_logger
from core.registry.interfaces import BaseScanner, ScannerResult
from core.schemas.events import EvaluationRequest

logger = get_logger("plugins.scanners.tier3_llm_judge")


class LLMJudgeConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    enabled: bool = True
    mode: str = "async_audit"  # "async_audit" | "sync_blocking"
    endpoint_url: str = "http://localhost:11434/v1"
    api_key: str = "ollama"
    model: str = "llama3.2"
    rubric_prompt: str = (
        "Analyze the provided content against safety, groundedness, and enterprise policy. "
        "Respond strictly in JSON with format: {\"compliant\": bool, \"risk_score\": float, \"explanation\": str}"
    )
    threshold: float = 0.75
    timeout_ms: int = 2000
    action_on_violation: str = "block"  # "block" | "flag"


class LLMJudgeScanner(BaseScanner):
    name = "tier3_llm_judge"
    version = "1.0.0"
    tier = 3
    supported_stages = ["llm_output", "tool_post_call", "agent_handoff"]
    config_schema = LLMJudgeConfig

    async def _call_judge_endpoint(
        self,
        content: str,
        cfg: LLMJudgeConfig,
    ) -> dict[str, Any]:
        settings = get_settings()
        if settings.AEGIS_ENV == "test":
            # Deterministic test mock
            is_risky = "violates enterprise policy" in content.lower()
            return {
                "compliant": not is_risky,
                "risk_score": 0.9 if is_risky else 0.1,
                "explanation": "Judge evaluated rubric compliance" if not is_risky else "Severe policy violation detected by rubric",
            }

        url = f"{cfg.endpoint_url.rstrip('/')}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {cfg.api_key}",
        }
        prompt = (
            f"{cfg.rubric_prompt}\n\n"
            f"Content to evaluate:\n```\n{content}\n```"
        )
        body = {
            "model": cfg.model,
            "messages": [{"role": "user", "content": prompt}],
            "response_format": {"type": "json_object"},
            "temperature": 0.0,
        }

        timeout_sec = max(0.1, cfg.timeout_ms / 1000.0)
        async with httpx.AsyncClient(timeout=timeout_sec) as client:
            resp = await client.post(url, json=body, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                text = data["choices"][0]["message"]["content"]
                return json.loads(text)
            raise RuntimeError(f"Judge returned HTTP {resp.status_code}: {resp.text}")

    async def scan(
        self,
        request: EvaluationRequest,
        context: dict[str, Any],
        config: BaseModel,
    ) -> ScannerResult:
        cfg = config if isinstance(config, LLMJudgeConfig) else LLMJudgeConfig(**config.model_dump())
        if not cfg.enabled:
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        # Select payload to judge
        target_content = ""
        if request.content.output_payload is not None:
            target_content = str(request.content.output_payload)
        elif request.content.untrusted_data is not None:
            target_content = str(request.content.untrusted_data)

        if not target_content:
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        if cfg.mode == "async_audit":
            # Non-blocking async audit: run in background task, return pass with audit tracking
            async def run_audit():
                try:
                    res = await self._call_judge_endpoint(target_content, cfg)
                    logger.info("Async LLM-as-a-Judge audit completed", result=res)
                except Exception as e:
                    logger.warning("Async LLM judge audit failed", error=str(e))

            asyncio.create_task(run_audit())
            return ScannerResult(
                scanner_name=self.name,
                tier=self.tier,
                status="pass",
                details={"mode": "async_audit", "status": "dispatched"},
            )
        else:
            # Sync blocking evaluation
            try:
                res = await self._call_judge_endpoint(target_content, cfg)
                risk_score = float(res.get("risk_score", 0.0))
                compliant = bool(res.get("compliant", True))
                explanation = str(res.get("explanation", ""))

                if not compliant or risk_score >= cfg.threshold:
                    status = cfg.action_on_violation
                    return ScannerResult(
                        scanner_name=self.name,
                        tier=self.tier,
                        status=status,
                        score=risk_score,
                        details=res,
                        message=f"LLM-as-a-Judge flagged violation (risk {risk_score:.2f}): {explanation}",
                    )
                return ScannerResult(
                    scanner_name=self.name,
                    tier=self.tier,
                    status="pass",
                    score=risk_score,
                    details=res,
                )
            except Exception as e:
                logger.warning("Sync LLM judge evaluation failed", error=str(e))
                return ScannerResult(
                    scanner_name=self.name,
                    tier=self.tier,
                    status="flag",
                    score=0.5,
                    details={"error": str(e)},
                    message=f"LLM judge failed: {e!s}",
                )

