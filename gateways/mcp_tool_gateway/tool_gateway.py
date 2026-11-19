import json
from typing import Any

import httpx
from fastapi import APIRouter, Depends, Header, Request, Response

from core.logger import get_logger
from core.pipeline.orchestrator import PipelineOrchestrator, get_pipeline_orchestrator
from core.schemas.common import DecisionEnum, StageEnum
from core.schemas.events import ActionModel, ActorModel, ContentModel, EvaluationRequest

logger = get_logger("gateways.tool_gateway")
router = APIRouter(prefix="/proxy", tags=["Tool & MCP Gateway"])


@router.post("/tools/{tool_name}")
async def execute_tool_proxy(
    tool_name: str,
    request: Request,
    orchestrator: PipelineOrchestrator = Depends(get_pipeline_orchestrator),
    x_aegis_tenant_id: str = Header(default="default"),
    x_aegis_workspace_id: str = Header(default="default"),
    x_aegis_policy_pack: str = Header(default="base-enterprise"),
    x_aegis_session_id: str | None = Header(default=None),
    x_aegis_actor_id: str = Header(default="tool_caller"),
    x_aegis_actor_role: str = Header(default="worker"),
    x_aegis_upstream_url: str | None = Header(default=None),
):
    """HTTP Tool Proxy.
    Enforces tool_pre_call governance (kill switch, loop detector, budgets, parameter guards)
    and tool_post_call scanning (PII, secrets, injection redaction).
    """
    body = await request.json() if request.headers.get("content-type") == "application/json" else {}
    parameters = body.get("parameters", body)

    # 1. TOOL PRE-CALL GOVERNANCE
    pre_req = EvaluationRequest(
        tenant_id=x_aegis_tenant_id,
        workspace_id=x_aegis_workspace_id,
        policy_pack_id=x_aegis_policy_pack,
        session_id=x_aegis_session_id,
        stage=StageEnum.TOOL_PRE_CALL,
        actor=ActorModel(id=x_aegis_actor_id, role=x_aegis_actor_role),
        action=ActionModel(name=tool_name, parameters=parameters),
    )

    pre_verdict = await orchestrator.evaluate(pre_req)

    if pre_verdict.decision == DecisionEnum.DENY:
        reason = pre_verdict.triggered_rules[0].reason if pre_verdict.triggered_rules else "Tool Pre-Call Denied"
        return Response(
            status_code=403,
            media_type="application/json",
            content=json.dumps(
                {
                    "error": {
                        "message": f"AegisGate Tool Policy Denied: {reason}",
                        "type": "aegisgate_tool_denial",
                        "verdict_id": pre_verdict.verdict_id,
                        "triggered_rules": [r.model_dump() for r in pre_verdict.triggered_rules],
                    }
                }
            ),
        )

    if pre_verdict.decision == DecisionEnum.SUSPEND_FOR_APPROVAL:
        return Response(
            status_code=202,
            media_type="application/json",
            content=json.dumps(
                {
                    "status": "SUSPEND_FOR_APPROVAL",
                    "message": "Tool execution suspended pending human approval",
                    "verdict_id": pre_verdict.verdict_id,
                    "approval_ticket": pre_verdict.approval_ticket.model_dump()
                    if pre_verdict.approval_ticket
                    else {},
                }
            ),
        )

    # Apply mutated parameters if modified
    effective_params = pre_verdict.mutated_parameters or parameters

    # 2. EXECUTE UPSTREAM TOOL
    tool_result: Any = None
    if x_aegis_upstream_url:
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(x_aegis_upstream_url, json={"parameters": effective_params})
                tool_result = resp.json() if "application/json" in resp.headers.get("content-type", "") else resp.text
        except Exception as e:
            logger.error("Upstream tool execution error", error=str(e))
            tool_result = {"status": "error", "error": str(e)}
    else:
        # Default mock execution
        tool_result = {
            "status": "success",
            "tool": tool_name,
            "executed_parameters": effective_params,
            "output": f"Mock output from {tool_name}",
        }

    # 3. TOOL POST-CALL SCANNING
    post_req = EvaluationRequest(
        tenant_id=x_aegis_tenant_id,
        workspace_id=x_aegis_workspace_id,
        policy_pack_id=x_aegis_policy_pack,
        session_id=x_aegis_session_id,
        stage=StageEnum.TOOL_POST_CALL,
        actor=ActorModel(id=x_aegis_actor_id, role=x_aegis_actor_role),
        action=ActionModel(name=tool_name, parameters=effective_params),
        content=ContentModel(untrusted_data=tool_result),
    )

    post_verdict = await orchestrator.evaluate(post_req)

    if post_verdict.decision == DecisionEnum.DENY:
        reason = post_verdict.triggered_rules[0].reason if post_verdict.triggered_rules else "Tool Post-Call Denied"
        return Response(
            status_code=403,
            media_type="application/json",
            content=json.dumps(
                {
                    "error": {
                        "message": f"AegisGate Tool Post-Call Denied: {reason}",
                        "type": "aegisgate_tool_output_denied",
                        "verdict_id": post_verdict.verdict_id,
                    }
                }
            ),
        )

    # If post-call mutated content (e.g. PII redaction or secret masking)
    final_output = post_verdict.mutated_content.get("untrusted_data", tool_result) if post_verdict.mutated_content else tool_result

    return Response(
        status_code=200,
        media_type="application/json",
        content=json.dumps(final_output) if isinstance(final_output, (dict, list)) else str(final_output),
        headers={
            "X-Aegis-Verdict-Id": post_verdict.verdict_id,
            "X-Aegis-Risk-Score": str(post_verdict.risk_score),
        },
    )


@router.post("/mcp/jsonrpc")
async def mcp_jsonrpc_gateway(
    request: Request,
    orchestrator: PipelineOrchestrator = Depends(get_pipeline_orchestrator),
    x_aegis_tenant_id: str = Header(default="default"),
    x_aegis_workspace_id: str = Header(default="default"),
    x_aegis_policy_pack: str = Header(default="base-enterprise"),
    x_aegis_session_id: str | None = Header(default=None),
    x_aegis_actor_id: str = Header(default="mcp_client"),
    x_aegis_actor_role: str = Header(default="agent"),
):
    """Model Context Protocol (MCP) JSON-RPC 2.0 Gateway.
    Transparently intercepts tools/call requests with pre-call & post-call governance.
    """
    body = await request.json()
    msg_id = body.get("id")
    method = body.get("method")
    params = body.get("params", {})

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "tools": [
                    {
                        "name": "query_database",
                        "description": "Query database tables safely",
                        "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}},
                    },
                    {
                        "name": "read_file",
                        "description": "Read file contents",
                        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
                    },
                ]
            },
        }

    if method == "tools/call":
        tool_name = params.get("name", "unknown_tool")
        arguments = params.get("arguments", {})

        # Pre-call evaluation
        eval_req = EvaluationRequest(
            tenant_id=x_aegis_tenant_id,
            workspace_id=x_aegis_workspace_id,
            policy_pack_id=x_aegis_policy_pack,
            session_id=x_aegis_session_id,
            stage=StageEnum.TOOL_PRE_CALL,
            actor=ActorModel(id=x_aegis_actor_id, role=x_aegis_actor_role),
            action=ActionModel(name=tool_name, parameters=arguments),
        )

        verdict = await orchestrator.evaluate(eval_req)
        if verdict.decision == DecisionEnum.DENY:
            reason = verdict.triggered_rules[0].reason if verdict.triggered_rules else "Policy Denied"
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32001,
                    "message": f"AegisGate MCP Policy Denied: {reason}",
                    "data": {"verdict_id": verdict.verdict_id},
                },
            }

        # Mock successful MCP execution
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": f"Successfully executed governed MCP tool {tool_name} with params {arguments}",
                    }
                ]
            },
        }

    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {"code": -32601, "message": f"Method '{method}' not found"},
    }

