import functools
import inspect
from collections.abc import Callable
from typing import Any

from .client import AegisClient
from .exceptions import PolicyViolationError
from .models import DecisionEnum, StageEnum

_global_client: AegisClient | None = None


def get_default_sdk_client() -> AegisClient:
    global _global_client
    if _global_client is None:
        _global_client = AegisClient()
    return _global_client


def governed_tool(
    name: str | None = None,
    client: AegisClient | None = None,
    fail_open: bool = False,
):
    """Decorator for automatic pre-call governance and post-call output scanning of tools."""

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        tool_name = name or fn.__name__
        sdk_client = client or get_default_sdk_client()

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args, **kwargs):
                params = kwargs.copy()
                if args:
                    params["_args"] = list(args)

                # 1. Pre-call evaluation
                pre_verdict = await sdk_client.evaluate(
                    stage=StageEnum.TOOL_PRE_CALL,
                    action_name=tool_name,
                    parameters=params,
                )
                if pre_verdict.decision == DecisionEnum.DENY and not fail_open:
                    reason = pre_verdict.triggered_rules[0].reason if pre_verdict.triggered_rules else "Tool Pre-Call Denied"
                    raise PolicyViolationError(f"Governed tool '{tool_name}' blocked by policy: {reason}", verdict=pre_verdict)

                # 2. Execute target function
                result = await fn(*args, **kwargs)

                # 3. Post-call evaluation
                post_verdict = await sdk_client.evaluate(
                    stage=StageEnum.TOOL_POST_CALL,
                    action_name=tool_name,
                    parameters=params,
                    untrusted_data=result,
                )
                if post_verdict.decision == DecisionEnum.DENY and not fail_open:
                    reason = post_verdict.triggered_rules[0].reason if post_verdict.triggered_rules else "Tool Output Denied"
                    raise PolicyViolationError(f"Governed tool '{tool_name}' output blocked by policy: {reason}", verdict=post_verdict)

                if post_verdict.mutated_content and "untrusted_data" in post_verdict.mutated_content:
                    return post_verdict.mutated_content["untrusted_data"]

                return result

            return async_wrapper
        else:

            @functools.wraps(fn)
            def sync_wrapper(*args, **kwargs):
                params = kwargs.copy()
                if args:
                    params["_args"] = list(args)

                # 1. Pre-call evaluation
                pre_verdict = sdk_client.evaluate_sync(
                    stage=StageEnum.TOOL_PRE_CALL,
                    action_name=tool_name,
                    parameters=params,
                )
                if pre_verdict.decision == DecisionEnum.DENY and not fail_open:
                    reason = pre_verdict.triggered_rules[0].reason if pre_verdict.triggered_rules else "Tool Pre-Call Denied"
                    raise PolicyViolationError(f"Governed tool '{tool_name}' blocked by policy: {reason}", verdict=pre_verdict)

                # 2. Execute target function
                result = fn(*args, **kwargs)

                # 3. Post-call evaluation
                post_verdict = sdk_client.evaluate_sync(
                    stage=StageEnum.TOOL_POST_CALL,
                    action_name=tool_name,
                    parameters=params,
                    untrusted_data=result,
                )
                if post_verdict.decision == DecisionEnum.DENY and not fail_open:
                    reason = post_verdict.triggered_rules[0].reason if post_verdict.triggered_rules else "Tool Output Denied"
                    raise PolicyViolationError(f"Governed tool '{tool_name}' output blocked by policy: {reason}", verdict=post_verdict)

                if post_verdict.mutated_content and "untrusted_data" in post_verdict.mutated_content:
                    return post_verdict.mutated_content["untrusted_data"]

                return result

            return sync_wrapper

    return decorator


def governed_llm(
    client: AegisClient | None = None,
    fail_open: bool = False,
):
    """Decorator to govern raw LLM caller functions."""

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        sdk_client = client or get_default_sdk_client()

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(prompt: str, *args, **kwargs):
                verdict = await sdk_client.evaluate(
                    stage=StageEnum.LLM_INPUT,
                    trusted_instructions=prompt,
                )
                if verdict.decision == DecisionEnum.DENY and not fail_open:
                    raise PolicyViolationError(f"LLM input blocked: {verdict.triggered_rules[0].reason}", verdict=verdict)

                result = await fn(prompt, *args, **kwargs)

                out_verdict = await sdk_client.evaluate(
                    stage=StageEnum.LLM_OUTPUT,
                    output_payload=str(result),
                )
                if out_verdict.decision == DecisionEnum.DENY and not fail_open:
                    raise PolicyViolationError(f"LLM output blocked: {out_verdict.triggered_rules[0].reason}", verdict=out_verdict)

                return result

            return async_wrapper
        else:

            @functools.wraps(fn)
            def sync_wrapper(prompt: str, *args, **kwargs):
                verdict = sdk_client.evaluate_sync(
                    stage=StageEnum.LLM_INPUT,
                    trusted_instructions=prompt,
                )
                if verdict.decision == DecisionEnum.DENY and not fail_open:
                    raise PolicyViolationError(f"LLM input blocked: {verdict.triggered_rules[0].reason}", verdict=verdict)

                result = fn(prompt, *args, **kwargs)

                out_verdict = sdk_client.evaluate_sync(
                    stage=StageEnum.LLM_OUTPUT,
                    output_payload=str(result),
                )
                if out_verdict.decision == DecisionEnum.DENY and not fail_open:
                    raise PolicyViolationError(f"LLM output blocked: {out_verdict.triggered_rules[0].reason}", verdict=out_verdict)

                return result

            return sync_wrapper

    return decorator

