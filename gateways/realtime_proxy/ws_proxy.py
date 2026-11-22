import json
import time
from typing import Any
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from core.governance.budgets import get_budget_manager
from core.governance.kill_switch import get_kill_switch_service
from core.logger import get_logger
from core.pipeline.orchestrator import get_pipeline_orchestrator
from core.schemas.common import DecisionEnum, StageEnum
from core.schemas.events import ActionModel, ActorModel, ContentModel, EvaluationRequest

logger = get_logger("gateways.realtime_proxy.ws_proxy")

router = APIRouter(prefix="/proxy/realtime/v1", tags=["Realtime WebSocket Proxy"])


@router.websocket("/ws")
@router.websocket("")
async def realtime_websocket_proxy(websocket: WebSocket) -> None:
    """Bidirectional WebSocket proxy for OpenAI Realtime & generic voice/event streams.
    Intercepts client transcript/text events (llm_input), assistant deltas (llm_output),
    and function calls (tool_pre_call) with instant kill-switch termination and policy enforcement.
    """
    await websocket.accept()

    # Extract session context from query params or headers
    query_params = dict(websocket.query_params)
    headers = dict(websocket.headers)

    tenant_id = (
        query_params.get("tenant_id")
        or headers.get("x-aegis-tenant-id")
        or "default"
    )
    workspace_id = (
        query_params.get("workspace_id")
        or headers.get("x-aegis-workspace-id")
        or "default"
    )
    session_id = (
        query_params.get("session_id")
        or headers.get("x-aegis-session-id")
        or f"rt-sess-{int(time.time())}"
    )
    policy_pack_id = (
        query_params.get("policy_pack")
        or headers.get("x-aegis-policy-pack")
        or "base-enterprise"
    )

    orchestrator = get_pipeline_orchestrator()
    kill_switch = get_kill_switch_service()
    budget_manager = get_budget_manager()

    try:
        while True:
            # Check kill switch before processing next message
            is_tripped, trip_reason = await kill_switch.is_tripped(
                tenant_id=tenant_id,
                workspace_id=workspace_id,
                session_id=session_id,
            )
            if is_tripped:
                await websocket.send_text(
                    json.dumps({
                        "type": "error",
                        "error": {
                            "type": "kill_switch_engaged",
                            "message": f"Realtime session terminated by emergency kill switch: {trip_reason}",
                        },
                    })
                )
                await websocket.close(code=1008, reason="Kill switch engaged")
                return

            raw_msg = await websocket.receive_text()
            try:
                event = json.loads(raw_msg)
            except json.JSONDecodeError:
                await websocket.send_text(json.dumps({"type": "error", "message": "Invalid JSON frame"}))
                continue

            event_type = event.get("type", "")

            # 1. CLIENT INPUT TRANSCRIPT / TEXT (LLM_INPUT)
            if event_type in ("conversation.item.create", "client_transcript", "user_message"):
                text_content = ""
                item = event.get("item", event)
                content = item.get("content", [])
                if isinstance(content, list):
                    for part in content:
                        if isinstance(part, dict) and "text" in part:
                            text_content += part["text"] + " "
                elif isinstance(content, str):
                    text_content = content
                elif "text" in event:
                    text_content = event["text"]

                eval_req = EvaluationRequest(
                    tenant_id=tenant_id,
                    workspace_id=workspace_id,
                    session_id=session_id,
                    policy_pack_id=policy_pack_id,
                    stage=StageEnum.LLM_INPUT,
                    actor=ActorModel(id="realtime_client", role="user"),
                    action=ActionModel(name="realtime_input"),
                    content=ContentModel(trusted_instructions="", untrusted_data=text_content.strip()),
                )
                verdict = await orchestrator.evaluate(eval_req)

                if verdict.decision == DecisionEnum.DENY:
                    reason = verdict.triggered_rules[0].reason if verdict.triggered_rules else "Realtime input denied by policy"
                    await websocket.send_text(
                        json.dumps({
                            "type": "error",
                            "error": {
                                "type": "policy_denied",
                                "message": f"AegisGate Realtime Input Denied: {reason}",
                                "verdict_id": verdict.verdict_id,
                            },
                        })
                    )
                    continue

            # 2. TOOL / FUNCTION CALLS (TOOL_PRE_CALL)
            elif event_type in ("response.function_call_arguments.done", "function_call", "tool_call"):
                call_name = event.get("name") or event.get("call_id") or "function"
                raw_args = event.get("arguments", "{}")
                parsed_args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args

                eval_req = EvaluationRequest(
                    tenant_id=tenant_id,
                    workspace_id=workspace_id,
                    session_id=session_id,
                    policy_pack_id=policy_pack_id,
                    stage=StageEnum.TOOL_PRE_CALL,
                    actor=ActorModel(id="realtime_agent", role="agent"),
                    action=ActionModel(name=call_name, parameters=parsed_args),
                )
                verdict = await orchestrator.evaluate(eval_req)

                if verdict.decision == DecisionEnum.DENY:
                    reason = verdict.triggered_rules[0].reason if verdict.triggered_rules else "Tool call denied by policy"
                    await websocket.send_text(
                        json.dumps({
                            "type": "error",
                            "error": {
                                "type": "tool_denied",
                                "message": f"AegisGate Realtime Tool Denied: {reason}",
                                "verdict_id": verdict.verdict_id,
                            },
                        })
                    )
                    continue

            # 3. ASSISTANT OUTPUT TRANSCRIPT DELTAS (LLM_OUTPUT)
            elif event_type in ("response.audio_transcript.delta", "response.text.delta", "assistant_delta"):
                delta_text = event.get("delta", "")
                if delta_text:
                    eval_req = EvaluationRequest(
                        tenant_id=tenant_id,
                        workspace_id=workspace_id,
                        session_id=session_id,
                        policy_pack_id=policy_pack_id,
                        stage=StageEnum.LLM_OUTPUT,
                        actor=ActorModel(id="realtime_assistant", role="assistant"),
                        action=ActionModel(name="realtime_output_delta"),
                        content=ContentModel(output_payload=delta_text),
                    )
                    verdict = await orchestrator.evaluate(eval_req)

                    if verdict.decision == DecisionEnum.DENY:
                        # Redact or close connection on output leak
                        await websocket.send_text(
                            json.dumps({
                                "type": "error",
                                "error": {
                                    "type": "output_redacted",
                                    "message": "Realtime output delta blocked by AegisGate output policy",
                                    "verdict_id": verdict.verdict_id,
                                },
                            })
                        )
                        continue

            # Echo/forward permitted frame back in mock/proxy mode
            ack_event = dict(event)
            ack_event["aegis_status"] = "permitted"
            await websocket.send_text(json.dumps(ack_event))

    except WebSocketDisconnect:
        logger.debug("realtime_websocket_disconnected", session_id=session_id)
    except Exception as e:
        logger.error("realtime_websocket_error", error=str(e), session_id=session_id)
        try:
            await websocket.close(code=1011, reason="Internal error")
        except Exception:
            pass

