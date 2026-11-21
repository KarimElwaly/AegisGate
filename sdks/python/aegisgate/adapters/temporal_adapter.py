from collections.abc import Callable
from typing import Any

from aegisgate.client import AegisClient
from aegisgate.exceptions import PolicyViolationError
from aegisgate.models import ActionModel, ActorModel, EvaluationRequest, StageEnum


class AegisTemporalActivityGuard:
    """Interceptor for Temporal Activities enforcing pre-call and post-call governance."""

    def __init__(
        self,
        client: AegisClient | None = None,
        policy_pack_id: str = "base-enterprise",
        actor_role: str = "temporal_worker",
    ) -> None:
        self.client = client or AegisClient()
        self.policy_pack_id = policy_pack_id
        self.actor_role = actor_role

    def activity(self, name: str | None = None) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator for Temporal activity definitions."""
        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            activity_name = name or func.__name__

            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                # Pre-activity execution check
                req = EvaluationRequest(
                    policy_pack_id=self.policy_pack_id,
                    stage=StageEnum.TOOL_PRE_CALL,
                    actor=ActorModel(id="temporal_workflow", role=self.actor_role),
                    action=ActionModel(name=activity_name, parameters=kwargs),
                )
                verdict = await self.client.evaluate(req)
                if verdict.decision == "DENY":
                    reason = (
                        verdict.triggered_rules[0].reason
                        if verdict.triggered_rules
                        else "Temporal activity denied"
                    )
                    raise PolicyViolationError(
                        f"AegisGate Activity '{activity_name}' Denied: {reason}", verdict
                    )

                result = await func(*args, **kwargs) if asyncio_iscoroutinefunction(func) else func(*args, **kwargs)
                return result

            return wrapper
        return decorator


def asyncio_iscoroutinefunction(func: Any) -> bool:
    import inspect
    return inspect.iscoroutinefunction(func)

