import asyncio
from contextvars import ContextVar
import uuid
from typing import Any, Dict, List, Optional
import httpx
from core.schemas.common import DecisionEnum, StageEnum
from core.schemas.events import ActionModel, ActorModel, ContentModel, EvaluationRequest
from core.schemas.verdicts import EvaluationVerdict
from sdks.python.aegisgate.exceptions import AegisGateError, PolicyViolationError

current_session_id: ContextVar[Optional[str]] = ContextVar("aegis_session_id", default=None)
current_trace_id: ContextVar[Optional[str]] = ContextVar("aegis_trace_id", default=None)


class AegisClient:
    """Thin Python SDK client for AegisGate Policy Decision Point & Proxies."""

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        api_key: Optional[str] = None,
        tenant_id: str = "default",
        workspace_id: str = "default",
        policy_pack_id: str = "base-enterprise",
        fail_open: bool = False,
        timeout: float = 5.0,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.tenant_id = tenant_id
        self.workspace_id = workspace_id
        self.policy_pack_id = policy_pack_id
        self.fail_open = fail_open
        self.timeout = timeout
        self.transport = transport

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "X-Aegis-Tenant-Id": self.tenant_id,
            "X-Aegis-Workspace-Id": self.workspace_id,
            "X-Aegis-Policy-Pack": self.policy_pack_id,
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        sess = current_session_id.get()
        if sess:
            headers["X-Aegis-Session-Id"] = sess
        return headers

    async def evaluate(
        self,
        stage: StageEnum | str,
        action_name: str = "default_action",
        parameters: Optional[Dict[str, Any]] = None,
        trusted_instructions: Optional[str] = None,
        untrusted_data: Optional[Any] = None,
        output_payload: Optional[Any] = None,
        actor_id: str = "sdk_caller",
        actor_role: str = "worker",
        delegation_chain: Optional[List[str]] = None,
        citations: Optional[List[str]] = None,
    ) -> EvaluationVerdict:
        """Async policy evaluation request."""
        session_id = current_session_id.get()
        trace_id = current_trace_id.get() or str(uuid.uuid4())

        req = EvaluationRequest(
            tenant_id=self.tenant_id,
            workspace_id=self.workspace_id,
            policy_pack_id=self.policy_pack_id,
            session_id=session_id,
            trace_id=trace_id,
            stage=StageEnum(stage) if isinstance(stage, str) else stage,
            actor=ActorModel(id=actor_id, role=actor_role, delegation_chain=delegation_chain or []),
            action=ActionModel(name=action_name, parameters=parameters or {}),
            content=ContentModel(
                trusted_instructions=trusted_instructions,
                untrusted_data=untrusted_data,
                output_payload=output_payload,
                citations=citations or [],
            ),
        )

        try:
            async with httpx.AsyncClient(timeout=self.timeout, transport=self.transport) as client:
                resp = await client.post(
                    f"{self.base_url}/v1/evaluate",
                    json=req.model_dump(),
                    headers=self._get_headers(),
                )
                if resp.status_code == 200:
                    return EvaluationVerdict(**resp.json())
                else:
                    raise AegisGateError(f"PDP evaluate failed HTTP {resp.status_code}: {resp.text}")
        except Exception as exc:
            if self.fail_open:
                return EvaluationVerdict(decision=DecisionEnum.ALLOW, would_have_decided=DecisionEnum.ALLOW)
            raise AegisGateError(f"AegisGate connection error: {str(exc)}") from exc

    def evaluate_sync(
        self,
        stage: StageEnum | str,
        action_name: str = "default_action",
        parameters: Optional[Dict[str, Any]] = None,
        trusted_instructions: Optional[str] = None,
        untrusted_data: Optional[Any] = None,
        output_payload: Optional[Any] = None,
        actor_id: str = "sdk_caller",
        actor_role: str = "worker",
        delegation_chain: Optional[List[str]] = None,
        citations: Optional[List[str]] = None,
    ) -> EvaluationVerdict:
        """Synchronous wrapper for evaluate."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    return pool.submit(
                        asyncio.run,
                        self.evaluate(
                            stage=stage,
                            action_name=action_name,
                            parameters=parameters,
                            trusted_instructions=trusted_instructions,
                            untrusted_data=untrusted_data,
                            output_payload=output_payload,
                            actor_id=actor_id,
                            actor_role=actor_role,
                            delegation_chain=delegation_chain,
                            citations=citations,
                        ),
                    ).result()
            return loop.run_until_complete(
                self.evaluate(
                    stage=stage,
                    action_name=action_name,
                    parameters=parameters,
                    trusted_instructions=trusted_instructions,
                    untrusted_data=untrusted_data,
                    output_payload=output_payload,
                    actor_id=actor_id,
                    actor_role=actor_role,
                    delegation_chain=delegation_chain,
                    citations=citations,
                )
            )
        except Exception as e:
            if self.fail_open:
                return EvaluationVerdict(decision=DecisionEnum.ALLOW)
            raise e
