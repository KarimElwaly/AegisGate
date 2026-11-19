import json
import re
from collections.abc import AsyncGenerator

from core.logger import get_logger
from core.pii_vault.vault import get_pii_vault

logger = get_logger("gateways.llm_proxy.streaming")


class SSEStreamGuard:
    """Rolling window SSE streaming guardrail.
    Buffers tokens across chunk boundaries to detect secret exfiltration
    or policy violations mid-stream, replaces or aborts gracefully,
    and re-hydrates synthetic PII tokens on-the-fly.
    """

    SECRET_PATTERN = re.compile(r"AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA )?PRIVATE KEY-----")

    def __init__(
        self,
        tenant_id: str,
        session_id: str,
        rehydrate_pii: bool = True,
        buffer_window_size: int = 64,
    ) -> None:
        self.tenant_id = tenant_id
        self.session_id = session_id
        self.rehydrate_pii = rehydrate_pii
        self.buffer_window_size = buffer_window_size
        self.rolling_buffer = ""
        self.vault = get_pii_vault()

    async def guard_stream(
        self,
        upstream_generator: AsyncGenerator[bytes, None],
    ) -> AsyncGenerator[bytes, None]:
        async for raw_chunk in upstream_generator:
            decoded = raw_chunk.decode("utf-8", errors="replace")
            lines = decoded.splitlines(keepends=True)

            for line in lines:
                if not line.startswith("data: "):
                    yield line.encode("utf-8")
                    continue

                payload_str = line[6:].strip()
                if payload_str == "[DONE]":
                    yield line.encode("utf-8")
                    continue

                try:
                    chunk_obj = json.loads(payload_str)
                    choices = chunk_obj.get("choices", [])
                    if choices:
                        delta = choices[0].get("delta", {})
                        content_piece = delta.get("content", "")

                        if content_piece:
                            self.rolling_buffer += content_piece

                            # Check for secret exfiltration in rolling window
                            if self.SECRET_PATTERN.search(self.rolling_buffer):
                                logger.critical(
                                    "Mid-stream secret leak detected in SSE stream! Aborting...",
                                    session_id=self.session_id,
                                )
                                abort_chunk = {
                                    "choices": [
                                        {
                                            "delta": {
                                                "content": "\n[STREAM ABORTED BY AEGISGATE: Sensitive credential leak detected]"
                                            },
                                            "finish_reason": "content_filter",
                                        }
                                    ]
                                }
                                yield f"data: {json.dumps(abort_chunk)}\n\ndata: [DONE]\n\n".encode()
                                return

                            # Rehydrate PII tokens if present
                            if self.rehydrate_pii and "<AEGIS_" in content_piece:
                                rehydrated = await self.vault.rehydrate(
                                    self.tenant_id, self.session_id, content_piece
                                )
                                delta["content"] = rehydrated
                                line = f"data: {json.dumps(chunk_obj)}\n\n"

                            # Maintain rolling window buffer size
                            if len(self.rolling_buffer) > self.buffer_window_size:
                                self.rolling_buffer = self.rolling_buffer[-self.buffer_window_size :]

                    yield line.encode("utf-8")
                except json.JSONDecodeError:
                    yield line.encode("utf-8")

