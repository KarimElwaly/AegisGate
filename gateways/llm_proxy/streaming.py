import json
import re
from collections.abc import AsyncGenerator

from core.audit.ledger import AuditLedger
from core.governance.budgets import get_budget_manager
from core.logger import get_logger
from core.pii_vault.vault import get_pii_vault
from core.telemetry import record_proxy_request
from core.schemas.common import DecisionEnum, StageEnum
from core.schemas.events import ActionModel, ActorModel, ContentModel, EvaluationRequest
from core.schemas.verdicts import EvaluationVerdict, TriggeredRule
from gateways.llm_proxy.translators.base import BaseProtocolTranslator
from gateways.llm_proxy.translators.openai_translator import OpenAIProtocolTranslator

logger = get_logger("gateways.llm_proxy.streaming")


class SSEStreamGuard:
    """Rolling window SSE streaming guardrail.
    Buffers tokens across chunk boundaries to detect secret exfiltration
    or policy violations mid-stream, replaces or aborts gracefully,
    re-hydrates synthetic PII tokens on-the-fly,
    tracks token usage (including OpenAI stream_options usage chunk),
    and reconciles token balances against Redis budgets.
    """

    SECRET_PATTERN = re.compile(
        r"AKIA[0-9A-Z]{16}"
        r"|-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
        r"|sk-proj-[A-Za-z0-9_-]{20,}"
        r"|sk-ant-[A-Za-z0-9_-]{20,}"
        r"|sk-[A-Za-z0-9_-]{20,}"
        r"|ghp_[A-Za-z0-9]{36}"
        r"|xox[baprs]-[A-Za-z0-9-]{10,}"
        r"|eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9._-]{15,}\.[A-Za-z0-9_-]{15,}"
    )

    def __init__(
        self,
        tenant_id: str,
        session_id: str,
        rehydrate_pii: bool = True,
        buffer_window_size: int = 256,
        estimated_prompt_tokens: int = 15,
        actor_id: str = "llm_client",
        actor_role: str = "user",
        model: str = "default-model",
        policy_pack_id: str = "base-enterprise",
        translator: BaseProtocolTranslator | None = None,
    ) -> None:
        self.tenant_id = tenant_id
        self.session_id = session_id
        self.rehydrate_pii = rehydrate_pii
        self.buffer_window_size = buffer_window_size
        self.estimated_prompt_tokens = estimated_prompt_tokens
        self.actor_id = actor_id
        self.actor_role = actor_role
        self.model = model
        self.policy_pack_id = policy_pack_id
        self.translator = translator or OpenAIProtocolTranslator()

        self.rolling_buffer = ""
        self.tail_overlap = ""
        self.partial_pii_tail = ""
        self.streamed_characters = 0
        self.exact_usage: dict[str, int] | None = None
        self._reconciled = False
        self.vault = get_pii_vault()

    async def guard_stream(
        self,
        upstream_generator: AsyncGenerator[bytes, None],
    ) -> AsyncGenerator[bytes, None]:
        try:
            async for raw_chunk in upstream_generator:
                decoded = raw_chunk.decode("utf-8", errors="replace") if isinstance(raw_chunk, bytes) else str(raw_chunk)
                lines = decoded.splitlines(keepends=True)

                for line in lines:
                    if not line.startswith("data: "):
                        yield line.encode("utf-8")
                        continue

                    payload_str = line[6:].strip()
                    if self.translator.is_stream_done(payload_str):
                        # Final chunk: perform token reconciliation
                        await self._reconcile_final_tokens()
                        yield line.encode("utf-8")
                        continue

                    try:
                        chunk_obj = json.loads(payload_str)

                        if self.translator.is_stream_done(payload_str, chunk_obj):
                            await self._reconcile_final_tokens()
                            yield line.encode("utf-8")
                            continue

                        # Capture usage if upstream emitted it
                        usage = self.translator.extract_stream_usage(chunk_obj)
                        if usage:
                            if self.exact_usage is None:
                                self.exact_usage = usage
                            else:
                                self.exact_usage.update(usage)

                        content_piece = self.translator.extract_stream_delta(chunk_obj)
                        if content_piece:
                            self.streamed_characters += len(content_piece)
                            combined_window = self.tail_overlap + content_piece
                            self.rolling_buffer += content_piece

                            # Check for secret exfiltration across split-token chunk boundary
                            if self.SECRET_PATTERN.search(combined_window):
                                logger.critical(
                                    "Mid-stream secret leak detected in SSE stream! Aborting...",
                                    session_id=self.session_id,
                                )
                                # Perform partial token reconciliation & audit recording
                                await self._handle_mid_stream_abort()

                                abort_chunk = self.translator.build_stream_abort_chunk("Sensitive credential leak detected")
                                if self.translator.protocol_name == "anthropic":
                                    yield (
                                        f"event: content_block_delta\ndata: {json.dumps(abort_chunk)}\n\n"
                                        f"event: message_delta\ndata: {json.dumps({'type': 'message_delta', 'delta': {'stop_reason': 'GUARDRAIL_INTERVENTION'}})}\n\n"
                                        f"event: message_stop\ndata: {{\"type\":\"message_stop\"}}\n\n"
                                    ).encode("utf-8")
                                else:
                                    yield f"data: {json.dumps(abort_chunk)}\n\ndata: [DONE]\n\n".encode("utf-8")
                                return

                            # Handle PII rehydration across split chunks
                            piece_to_emit = content_piece
                            if self.rehydrate_pii:
                                rehydrate_target = self.partial_pii_tail + content_piece
                                self.partial_pii_tail = ""

                                if "<AEGIS_" in rehydrate_target:
                                    # If ends with an unclosed tag prefix like '<AEGIS_PII_123', buffer the tail
                                    tag_start = rehydrate_target.rfind("<AEGIS_")
                                    tag_end = rehydrate_target.find(">", tag_start)
                                    if tag_end == -1:
                                        # Tag incomplete, buffer it
                                        self.partial_pii_tail = rehydrate_target[tag_start:]
                                        rehydrate_target = rehydrate_target[:tag_start]

                                    if rehydrate_target:
                                        rehydrate_target = await self.vault.rehydrate(
                                            self.tenant_id, self.session_id, rehydrate_target
                                        )
                                piece_to_emit = rehydrate_target

                            chunk_obj = self.translator.replace_stream_delta(chunk_obj, piece_to_emit)
                            line = f"data: {json.dumps(chunk_obj)}\n\n"

                            # Update sliding overlap tail buffer
                            self.tail_overlap = combined_window[-self.buffer_window_size:]
                            if len(self.rolling_buffer) > self.buffer_window_size:
                                self.rolling_buffer = self.rolling_buffer[-self.buffer_window_size:]

                        yield line.encode("utf-8")
                    except json.JSONDecodeError:
                        yield line.encode("utf-8")
        finally:
            # Guarantee reconciliation if generator terminated without explicit [DONE]
            await self._reconcile_final_tokens()

    async def _handle_mid_stream_abort(self) -> None:
        """Records an audit event and reconciles partial token burn on mid-stream violation."""
        record_proxy_request("streaming", "aborted")
        partial_tokens = (
            self.exact_usage.get("total_tokens")
            if self.exact_usage
            else max(1, self.streamed_characters // 4) + self.estimated_prompt_tokens
        )
        if not self._reconciled and self.session_id and self.session_id != "global":
            self._reconciled = True
            try:
                await get_budget_manager().reconcile_tokens(
                    self.tenant_id,
                    "session",
                    self.session_id,
                    partial_tokens - self.estimated_prompt_tokens,
                )
            except Exception:
                pass

        try:
            ledger = AuditLedger()
            abort_req = EvaluationRequest(
                tenant_id=self.tenant_id,
                session_id=self.session_id,
                policy_pack_id=self.policy_pack_id,
                stage=StageEnum.LLM_OUTPUT,
                actor=ActorModel(id=self.actor_id, role=self.actor_role),
                action=ActionModel(
                    name="chat_completion",
                    target=self.model,
                    estimated_tokens=partial_tokens,
                ),
                content=ContentModel(output_payload=self.rolling_buffer),
            )
            abort_verdict = EvaluationVerdict(
                decision=DecisionEnum.DENY,
                risk_score=1.0,
                triggered_rules=[
                    TriggeredRule(
                        rule_id="sse_stream_credential_leak_guard",
                        policy_pack=self.policy_pack_id,
                        policy_version="1.0.0",
                        severity="CRITICAL",
                        reason="Mid-stream sensitive credential leak detected in SSE stream",
                        compliance_tags=["OWASP-LLM06", "SECRETS-EXFIL"],
                    )
                ],
            )
            await ledger.record_event(
                request=abort_req,
                verdict=abort_verdict,
                policy_pack_id=self.policy_pack_id,
            )
        except Exception as exc:
            logger.warning("failed_to_record_abort_audit", error=str(exc))

    async def _reconcile_final_tokens(self) -> None:
        """Reconciles total token consumption against Redis session budget upon completion."""
        if self._reconciled:
            return
        self._reconciled = True

        if self.exact_usage:
            actual_tokens = self.exact_usage.get(
                "total_tokens",
                self.exact_usage.get("prompt_tokens", self.estimated_prompt_tokens)
                + self.exact_usage.get("completion_tokens", max(1, self.streamed_characters // 4)),
            )
        else:
            actual_tokens = self.estimated_prompt_tokens + max(1, self.streamed_characters // 4)

        if self.session_id and self.session_id != "global":
            try:
                await get_budget_manager().reconcile_tokens(
                    self.tenant_id,
                    "session",
                    self.session_id,
                    actual_tokens - self.estimated_prompt_tokens,
                )
            except Exception:
                pass

        record_proxy_request("streaming", "completed")
