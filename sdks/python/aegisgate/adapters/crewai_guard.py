import inspect
from collections.abc import Callable
from typing import Any

from aegisgate.client import AegisClient
from aegisgate.exceptions import ApprovalRequiredError, PolicyViolationError
from aegisgate.models import ActionModel, ActorModel, ContentModel, DecisionEnum, EvaluationRequest, StageEnum


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
            if verdict_pre.decision in ("SUSPEND_FOR_APPROVAL", DecisionEnum.SUSPEND_FOR_APPROVAL):
                ticket_id = verdict_pre.approval_ticket.ticket_id if verdict_pre.approval_ticket else None
                raise ApprovalRequiredError(f"AegisGate CrewAI Tool '{name}' suspended: Human approval required", ticket_id=ticket_id, verdict=verdict_pre)
            if verdict_pre.decision in ("DENY", "ESCALATE", DecisionEnum.DENY, DecisionEnum.ESCALATE):
                reason = verdict_pre.triggered_rules[0].reason if verdict_pre.triggered_rules else "Pre-call blocked"
                raise PolicyViolationError(f"AegisGate CrewAI Tool '{name}' Denied: {reason}", verdict_pre)

            effective_kwargs = verdict_pre.mutated_parameters if verdict_pre.mutated_parameters else kwargs

            # 2. Execute underlying tool
            if inspect.iscoroutinefunction(tool_func):
                output = await tool_func(*args, **effective_kwargs)
            else:
                output = tool_func(*args, **effective_kwargs)

            # 3. TOOL_POST_CALL Evaluation
            eval_req_post = EvaluationRequest(
                tenant_id=self.tenant_id,
                policy_pack_id=self.policy_pack_id,
                stage=StageEnum.TOOL_POST_CALL,
                actor=ActorModel(id=name, role=self.agent_role),
                action=ActionModel(name=name, parameters=effective_kwargs or {}),
                content=ContentModel(output_payload=str(output)),
            )

            verdict_post = await self.client.evaluate(eval_req_post)
            if verdict_post.decision in ("SUSPEND_FOR_APPROVAL", DecisionEnum.SUSPEND_FOR_APPROVAL):
                ticket_id = verdict_post.approval_ticket.ticket_id if verdict_post.approval_ticket else None
                raise ApprovalRequiredError(f"AegisGate CrewAI Tool Output '{name}' suspended: Human approval required", ticket_id=ticket_id, verdict=verdict_post)
            if verdict_post.decision in ("DENY", "ESCALATE", DecisionEnum.DENY, DecisionEnum.ESCALATE):
                reason = verdict_post.triggered_rules[0].reason if verdict_post.triggered_rules else "Post-call blocked"
                raise PolicyViolationError(f"AegisGate CrewAI Tool Output '{name}' Denied: {reason}", verdict_post)

            if verdict_post.mutated_content:
                output = verdict_post.mutated_content.get("output_payload", output)

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
            if verdict.decision in ("SUSPEND_FOR_APPROVAL", DecisionEnum.SUSPEND_FOR_APPROVAL):
                ticket_id = verdict.approval_ticket.ticket_id if verdict.approval_ticket else None
                raise ApprovalRequiredError(f"AegisGate CrewAI Task '{name}' suspended: Human approval required", ticket_id=ticket_id, verdict=verdict)
            if verdict.decision in ("DENY", "ESCALATE", DecisionEnum.DENY, DecisionEnum.ESCALATE):
                reason = verdict.triggered_rules[0].reason if verdict.triggered_rules else "Task output blocked"
                raise PolicyViolationError(f"AegisGate CrewAI Task '{name}' Denied: {reason}", verdict)

            effective_output = task_output
            if verdict.mutated_content and "output_payload" in verdict.mutated_content:
                effective_output = verdict.mutated_content["output_payload"]

            if inspect.iscoroutinefunction(task_callback):
                return await task_callback(effective_output, *args, **kwargs)
            return task_callback(effective_output, *args, **kwargs)

        return _governed_task_async
