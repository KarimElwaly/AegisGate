import functools
import hashlib
import inspect
import json
from collections.abc import Callable
from typing import Any

from aegisgate.client import AegisClient
from aegisgate.exceptions import ApprovalRequiredError, PolicyViolationError
from aegisgate.models import ActionModel, ActorModel, ContentModel, DecisionEnum, EvaluationRequest, StageEnum


class FastMcpGuard:
    """AegisGate Decorator and Interceptor for FastMCP Server Tools."""

    def __init__(
        self,
        client: AegisClient | None = None,
        policy_pack_id: str = "base-enterprise",
        caller_role: str = "agent",
    ) -> None:
        self.client = client or AegisClient()
        self.policy_pack_id = policy_pack_id
        self.caller_role = caller_role

    def tool(self, name: str | None = None) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator for FastMCP tool functions to enforce runtime AegisGate governance."""
        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            tool_name = name or func.__name__

            @functools.wraps(func)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                # 1. TOOL PRE-CALL
                eval_req = EvaluationRequest(
                    policy_pack_id=self.policy_pack_id,
                    stage=StageEnum.TOOL_PRE_CALL,
                    actor=ActorModel(id="fastmcp_client", role=self.caller_role),
                    action=ActionModel(name=tool_name, parameters=kwargs),
                )
                verdict = await self.client.evaluate(eval_req)
                if verdict.decision in ("SUSPEND_FOR_APPROVAL", DecisionEnum.SUSPEND_FOR_APPROVAL):
                    ticket_id = verdict.approval_ticket.ticket_id if verdict.approval_ticket else None
                    raise ApprovalRequiredError(f"AegisGate FastMCP Tool '{tool_name}' suspended: Human approval required", ticket_id=ticket_id, verdict=verdict)
                if verdict.decision in ("DENY", "ESCALATE", DecisionEnum.DENY, DecisionEnum.ESCALATE):
                    reason = verdict.triggered_rules[0].reason if verdict.triggered_rules else "Tool execution denied"
                    raise PolicyViolationError(f"AegisGate FastMCP Tool '{tool_name}' Denied: {reason}", verdict)

                effective_kwargs = verdict.mutated_parameters if verdict.mutated_parameters else kwargs

                # 2. EXECUTE TOOL
                if inspect.iscoroutinefunction(func):
                    result = await func(*args, **effective_kwargs)
                else:
                    result = func(*args, **effective_kwargs)

                # 3. TOOL POST-CALL
                post_req = EvaluationRequest(
                    policy_pack_id=self.policy_pack_id,
                    stage=StageEnum.TOOL_POST_CALL,
                    actor=ActorModel(id="fastmcp_client", role=self.caller_role),
                    action=ActionModel(name=tool_name, parameters=effective_kwargs),
                    content=ContentModel(untrusted_data=result),
                )
                post_verdict = await self.client.evaluate(post_req)
                if post_verdict.decision in ("SUSPEND_FOR_APPROVAL", DecisionEnum.SUSPEND_FOR_APPROVAL):
                    ticket_id = post_verdict.approval_ticket.ticket_id if post_verdict.approval_ticket else None
                    raise ApprovalRequiredError(f"AegisGate FastMCP Tool '{tool_name}' Output suspended: Human approval required", ticket_id=ticket_id, verdict=post_verdict)
                if post_verdict.decision in ("DENY", "ESCALATE", DecisionEnum.DENY, DecisionEnum.ESCALATE):
                    reason = (
                        post_verdict.triggered_rules[0].reason
                        if post_verdict.triggered_rules
                        else "Tool output denied"
                    )
                    raise PolicyViolationError(
                        f"AegisGate FastMCP Tool '{tool_name}' Output Denied: {reason}",
                        post_verdict,
                    )

                if post_verdict.mutated_content:
                    result = post_verdict.mutated_content.get("untrusted_data", result)

                return result

            return wrapper
        return decorator

