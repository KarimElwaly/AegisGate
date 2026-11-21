from collections.abc import Callable
from typing import Any

from aegisgate.client import AegisClient
from aegisgate.exceptions import PolicyViolationError
from aegisgate.models import ActionModel, ActorModel, ContentModel, EvaluationRequest, StageEnum


class LangGraphGuard:
    """AegisGate Middleware/Hook for LangGraph agent nodes and state transitions."""

    def __init__(
        self,
        client: AegisClient | None = None,
        policy_pack_id: str = "base-enterprise",
        agent_role: str = "langgraph_agent",
    ) -> None:
        self.client = client or AegisClient()
        self.policy_pack_id = policy_pack_id
        self.agent_role = agent_role

    def wrap_node(self, node_func: Callable[..., Any], node_name: str | None = None) -> Callable[..., Any]:
        """Wraps a LangGraph node function with pre-execution input and post-execution output guardrails."""
        name = node_name or getattr(node_func, "__name__", "langgraph_node")

        async def _governed_node_async(state: dict[str, Any], *args: Any, **kwargs: Any) -> dict[str, Any]:
            # 1. Inspect state messages / prompt entering node
            messages = state.get("messages", [])
            last_message = str(messages[-1].content) if messages and hasattr(messages[-1], "content") else str(state)

            eval_req = EvaluationRequest(
                policy_pack_id=self.policy_pack_id,
                stage=StageEnum.AGENT_HANDOFF,
                actor=ActorModel(id=name, role=self.agent_role),
                action=ActionModel(name=name, parameters={"state_keys": list(state.keys())}),
                content=ContentModel(untrusted_data=last_message),
            )

            verdict = await self.client.evaluate(eval_req)
            if verdict.decision == "DENY":
                reason = verdict.triggered_rules[0].reason if verdict.triggered_rules else "LangGraph step blocked"
                raise PolicyViolationError(f"AegisGate LangGraph Node '{name}' Denied: {reason}", verdict)

            # 2. Execute underlying LangGraph node
            if asyncio_iscoroutinefunction(node_func):
                result = await node_func(state, *args, **kwargs)
            else:
                result = node_func(state, *args, **kwargs)

            return result

        return _governed_node_async


def asyncio_iscoroutinefunction(func: Any) -> bool:
    import inspect
    return inspect.iscoroutinefunction(func)

