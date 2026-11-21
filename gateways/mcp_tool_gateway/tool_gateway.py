import hashlib
import json
from typing import Any

import httpx
from fastapi import APIRouter, Depends, Header, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import db_context
from core.logger import get_logger
from core.models.mcp import McpToolPinRecord, UpstreamMcpServerRecord
from core.pipeline.orchestrator import PipelineOrchestrator, get_pipeline_orchestrator
from core.schemas.common import DecisionEnum, StageEnum
from core.schemas.events import ActionModel, ActorModel, ContentModel, EvaluationRequest
from core.security.ssrf import SSRFProtectionError, validate_outbound_url
from core.telemetry import record_proxy_request

logger = get_logger("gateways.tool_gateway")
router = APIRouter(prefix="/proxy", tags=["Tool & MCP Gateway"])


async def check_anti_rug_pull(
    db: AsyncSession,
    tenant_id: str,
    workspace_id: str,
    tool_name: str,
    input_schema: dict[str, Any] | None = None,
    description: str | None = None,
) -> tuple[bool, str | None]:
    stmt = select(McpToolPinRecord).where(
        McpToolPinRecord.tenant_id == tenant_id,
        McpToolPinRecord.workspace_id == workspace_id,
        McpToolPinRecord.tool_name == tool_name,
    )
    res = await db.execute(stmt)
    pin = res.scalar_one_or_none()
    if not pin:
        return True, None

    if pin.is_quarantined:
        return False, pin.quarantine_reason or "Tool is quarantined by Anti-Rug-Pull policy"

    if input_schema is not None or description is not None:
        canonical_schema = json.dumps(input_schema or {}, sort_keys=True, separators=(",", ":"))
        curr_s_hash = hashlib.sha256(canonical_schema.encode("utf-8")).hexdigest()
        curr_d_hash = hashlib.sha256((description or "").strip().encode("utf-8")).hexdigest()

        if curr_s_hash != pin.schema_hash or curr_d_hash != pin.description_hash:
            reason = f"Drift detected in schema/description (Anti-Rug-Pull). Expected schema {pin.schema_hash[:8]}, got {curr_s_hash[:8]}"
            pin.is_quarantined = True
            pin.quarantine_reason = reason
            await db.commit()
            return False, reason

    return True, None


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
        record_proxy_request("mcp_tool", "denied")
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
            await validate_outbound_url(x_aegis_upstream_url, target_type="tool_gateway")
        except SSRFProtectionError as ssrf_err:
            return Response(
                status_code=400,
                media_type="application/json",
                content=json.dumps({"error": {"message": f"Invalid upstream tool URL: {ssrf_err!s}", "type": "ssrf_violation"}}),
            )

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
        record_proxy_request("mcp_tool", "denied")
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

    record_proxy_request("mcp_tool", "success")
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
    Interprets JSON-RPC requests, enforces Anti-Rug-Pull schema pinning,
    role-based tool filtering, pre-call governance, and upstream proxying.
    """
    body = await request.json()
    msg_id = body.get("id")
    method = body.get("method")
    params = body.get("params", {})

    if method == "tools/list":
        base_tools = [
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

        async with db_context() as db:
            pins_stmt = select(McpToolPinRecord).where(
                McpToolPinRecord.tenant_id == x_aegis_tenant_id,
                McpToolPinRecord.workspace_id == x_aegis_workspace_id,
            )
            res = await db.execute(pins_stmt)
            pins_map = {p.tool_name: p for p in res.scalars().all()}

        active_tools = []
        for t in base_tools:
            t_name = t["name"]
            pin = pins_map.get(t_name)
            if pin:
                if pin.is_quarantined:
                    continue
                # Anti-Rug-Pull check
                canonical_s = json.dumps(t["inputSchema"], sort_keys=True, separators=(",", ":"))
                s_hash = hashlib.sha256(canonical_s.encode("utf-8")).hexdigest()
                d_hash = hashlib.sha256((t.get("description") or "").strip().encode("utf-8")).hexdigest()
                if s_hash != pin.schema_hash or d_hash != pin.description_hash:
                    async with db_context() as db:
                        p_to_update = await db.get(McpToolPinRecord, pin.id)
                        if p_to_update:
                            p_to_update.is_quarantined = True
                            p_to_update.quarantine_reason = "Schema/description drift detected on tools/list"
                    continue
            active_tools.append(t)

        # Role-based tool filtering
        policy_pack = orchestrator.policy_engine.get_policy_pack(x_aegis_policy_pack)
        if policy_pack and policy_pack.budgets and "delegation" in policy_pack.budgets:
            role_perms = policy_pack.budgets["delegation"].get("role_tool_permissions", {}).get(x_aegis_actor_role, [])
            if role_perms and "*" not in role_perms:
                active_tools = [t for t in active_tools if t["name"] in role_perms]

        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {"tools": active_tools},
        }

    if method == "tools/call":
        tool_name = params.get("name", "unknown_tool")
        arguments = params.get("arguments", {})

        # 1. Anti-Rug-Pull Quarantine check
        async with db_context() as db:
            allowed, quarantine_reason = await check_anti_rug_pull(
                db,
                tenant_id=x_aegis_tenant_id,
                workspace_id=x_aegis_workspace_id,
                tool_name=tool_name,
            )
            if not allowed:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32002,
                        "message": f"AegisGate Anti-Rug-Pull: Tool '{tool_name}' is quarantined ({quarantine_reason})",
                    },
                }

        # 2. Tool Pre-Call Evaluation
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

        effective_params = verdict.mutated_parameters or arguments

        # 3. Upstream Forwarding or Governed Execution
        tool_result = None
        upstream_url = None
        async with db_context() as db:
            up_stmt = select(UpstreamMcpServerRecord).where(
                UpstreamMcpServerRecord.tenant_id == x_aegis_tenant_id,
                UpstreamMcpServerRecord.workspace_id == x_aegis_workspace_id,
                UpstreamMcpServerRecord.is_active.is_(True),
            )
            up_res = await db.execute(up_stmt)
            up_server = up_res.scalars().first()
            if up_server:
                upstream_url = up_server.server_url

        if upstream_url:
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.post(
                        upstream_url,
                        json={
                            "jsonrpc": "2.0",
                            "id": msg_id,
                            "method": "tools/call",
                            "params": {"name": tool_name, "arguments": effective_params},
                        },
                    )
                    data = resp.json()
                    tool_result = data.get("result", {}).get("content", [{"type": "text", "text": resp.text}])
            except Exception as e:
                logger.error("Upstream MCP invocation error", error=str(e))
                tool_result = [{"type": "text", "text": f"Upstream MCP error: {e!s}"}]
        else:
            tool_result = [
                {
                    "type": "text",
                    "text": f"Successfully executed governed MCP tool {tool_name} with params {effective_params}",
                }
            ]

        # 4. Tool Post-Call Evaluation
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
            reason = post_verdict.triggered_rules[0].reason if post_verdict.triggered_rules else "Post-Call Denied"
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32001,
                    "message": f"AegisGate MCP Policy Denied on Output: {reason}",
                    "data": {"verdict_id": post_verdict.verdict_id},
                },
            }

        final_content = (
            post_verdict.mutated_content.get("untrusted_data", tool_result)
            if post_verdict.mutated_content
            else tool_result
        )

        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "content": final_content,
            },
        }

    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {"code": -32601, "message": f"Method '{method}' not found"},
    }

