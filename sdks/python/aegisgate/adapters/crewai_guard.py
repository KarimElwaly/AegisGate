import inspect
from collections.abc import Callable
from typing import Any

from aegisgate.client import AegisClient
from aegisgate.exceptions import PolicyViolationError
from aegisgate.models import ActionModel, ActorModel, ContentModel, EvaluationRequest, StageEnum


class CrewAIGuard:
    """AegisGate Governance Adapter for CrewAI Agents, Tasks, and Custom Tools."""

    def __init__(
        self,
        client: AegisClient | None = None,
        policy_pack_id: str = "base-enterprise",
        agent_role: str = "crewai_agent",
        tenant_id: str = "default",
    ) -> None:
        self.client = client or AegisClient()
        self.policy_pack_id = policy_pack_id
        self.agent_role = agent_role
        self.tenant_id = tenant_id

    def wrap_tool(self, tool_func: Callable[..., Any], tool_name: str | None = None) -> Callable[..., Any]:
        """Wraps a CrewAI tool function with tool_pre_call and tool_post_call guardrails."""
        name = tool_name or getattr(tool_func, "__name__", "crewai_tool")

        async def _governed_tool_async(*args: Any, **kwargs: Any) -> Any:
            # 1. TOOL_PRE_CALL Evaluation
            eval_req_pre = EvaluationRequest(
                tenant_id=self.tenant_id,
                policy_pack_id=self.policy_pack_id,
                stage=StageEnum.TOOL_PRE_CALL,
                actor=ActorModel(id=name, role=self.agent_role),
                action=ActionModel(name=name, parameters=kwargs or {"args": list(args)}),
                content=ContentModel(untrusted_data=str(args) + " " + str(kwargs)),
            )

            verdict_pre = await self.client.evaluate(eval_req_pre)
            if verdict_pre.decision == "DENY":
                reason = verdict_pre.triggered_rules[0].reason if verdict_pre.triggered_rules else "Pre-call blocked"
                raise PolicyViolationError(f"AegisGate CrewAI Tool '{name}' Denied: {reason}", verdict_pre)

            # 2. Execute underlying tool
            if inspect.iscoroutinefunction(tool_func):
                output = await tool_func(*args, **kwargs)
            else:
                output = tool_func(*args, **kwargs)

            # 3. TOOL_POST_CALL Evaluation
            eval_req_post = EvaluationRequest(
                tenant_id=self.tenant_id,
                policy_pack_id=self.policy_pack_id,
                stage=StageEnum.TOOL_POST_CALL,
                actor=ActorModel(id=name, role=self.agent_role),
                action=ActionModel(name=name, parameters=kwargs or {}),
                content=ContentModel(output_payload=str(output)),
            )

            verdict_post = await self.client.evaluate(eval_req_post)
            if verdict_post.decision == "DENY":
                reason = verdict_post.triggered_rules[0].reason if verdict_post.triggered_rules else "Post-call blocked"
                raise PolicyViolationError(f"AegisGate CrewAI Tool Output '{name}' Denied: {reason}", verdict_post)

            return output

        def _governed_tool_sync(*args: Any, **kwargs: Any) -> Any:
            # Sync execution for non-async CrewAI runners
            import asyncio
            import concurrent.futures

            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None

            if loop and loop.is_running():
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    return pool.submit(lambda: asyncio.run(_governed_tool_async(*args, **kwargs))).result()
            else:
                return asyncio.run(_governed_tool_async(*args, **kwargs))

        if inspect.iscoroutinefunction(tool_func):
            return _governed_tool_async
        return _governed_tool_sync

    def wrap_task(self, task_callback: Callable[..., Any], task_name: str | None = None) -> Callable[..., Any]:
        """Wraps a CrewAI task callback with agent_handoff governance."""
        name = task_name or getattr(task_callback, "__name__", "crewai_task")

        async def _governed_task_async(task_output: Any, *args: Any, **kwargs: Any) -> Any:
            eval_req = EvaluationRequest(
                tenant_id=self.tenant_id,
                policy_pack_id=self.policy_pack_id,
                stage=StageEnum.AGENT_HANDOFF,
                actor=ActorModel(id=name, role=self.agent_role),
                action=ActionModel(name=name),
                content=ContentModel(output_payload=str(task_output)),
            )

            verdict = await self.client.evaluate(eval_req)
            if verdict.decision == "DENY":
                reason = verdict.triggered_rules[0].reason if verdict.triggered_rules else "Task output blocked"
                raise PolicyViolationError(f"AegisGate CrewAI Task '{name}' Denied: {reason}", verdict)

            if inspect.iscoroutinefunction(task_callback):
                return await task_callback(task_output, *args, **kwargs)
            return task_callback(task_output, *args, **kwargs)

        return _governed_task_async
