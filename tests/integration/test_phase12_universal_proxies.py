import json
import pytest
from httpx import ASGITransport, AsyncClient

from gateways.pdp_api.main import app


@pytest.fixture
async def async_client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


@pytest.mark.asyncio
async def test_anthropic_messages_clean_and_token_reconciliation(async_client):
    payload = {
        "model": "claude-3-5-sonnet-20241022",
        "system": "You are a helpful banking assistant.",
        "messages": [
            {"role": "user", "content": "What is the capital of France?"}
        ],
        "max_tokens": 100,
    }

    headers = {
        "x-api-key": "test-anthropic-key",
        "x-aegis-tenant-id": "default",
        "x-aegis-session-id": "sess-anthropic-clean",
        "x-aegis-actor-id": "operator-1",
        "x-aegis-actor-role": "user",
    }

    resp = await async_client.post("/proxy/anthropic/v1/messages", json=payload, headers=headers)
    assert resp.status_code == 200
    data = resp.json()

    # Anthropic contract assertions
    assert data["type"] == "message"
    assert data["role"] == "assistant"
    assert len(data["content"]) > 0
    assert data["content"][0]["type"] == "text"
    assert "Paris" in data["content"][0]["text"]
    assert "usage" in data
    assert data["usage"]["input_tokens"] > 0
    assert data["usage"]["output_tokens"] > 0

    # AegisGate headers
    assert "X-Aegis-Verdict-Id" in resp.headers
    assert "X-Aegis-Reconciled-Tokens" in resp.headers


@pytest.mark.asyncio
async def test_anthropic_messages_sse_streaming(async_client):
    payload = {
        "model": "claude-3-5-sonnet-20241022",
        "system": "You are a helpful assistant.",
        "messages": [{"role": "user", "content": "Tell me a short greeting."}],
        "stream": True,
    }

    headers = {
        "x-api-key": "test-anthropic-key",
        "x-aegis-session-id": "sess-anthropic-stream",
    }

    resp = await async_client.post("/proxy/anthropic/v1/messages", json=payload, headers=headers)
    assert resp.status_code == 200
    assert "text/event-stream" in resp.headers["content-type"]

    body = resp.text
    assert "event: message_start" in body
    assert "event: content_block_delta" in body
    assert "event: message_delta" in body
    assert "event: message_stop" in body


@pytest.mark.asyncio
async def test_anthropic_messages_policy_denied(async_client):
    # Payload containing hardcoded AWS secret in user prompt
    payload = {
        "model": "claude-3-5-sonnet-20241022",
        "messages": [
            {"role": "user", "content": "Deploy this key: AKIAIOSFODNN7EXAMPLE to prod"}
        ],
    }

    headers = {
        "x-api-key": "test-anthropic-key",
    }

    resp = await async_client.post("/proxy/anthropic/v1/messages", json=payload, headers=headers)
    assert resp.status_code == 403
    data = resp.json()

    # Anthropic error structure
    assert data["type"] == "error"
    assert data["error"]["type"] == "permission_error"
    assert "AegisGate Policy Denied" in data["error"]["message"]
    assert "verdict_id" in data["error"]


@pytest.mark.asyncio
async def test_gemini_generate_content_clean(async_client):
    payload = {
        "systemInstruction": {
            "parts": [{"text": "You are a helpful research agent."}]
        },
        "contents": [
            {
                "role": "user",
                "parts": [{"text": "What is the capital of France?"}],
            }
        ],
    }

    headers = {
        "x-goog-api-key": "test-gemini-key",
        "x-aegis-session-id": "sess-gemini-clean",
    }

    resp = await async_client.post(
        "/proxy/gemini/v1beta/models/gemini-1.5-flash:generateContent",
        json=payload,
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()

    # Gemini contract assertions
    assert "candidates" in data
    assert len(data["candidates"]) > 0
    candidate = data["candidates"][0]
    assert candidate["content"]["role"] == "model"
    assert "Paris" in candidate["content"]["parts"][0]["text"]
    assert "usageMetadata" in data
    assert data["usageMetadata"]["totalTokenCount"] > 0

    assert "X-Aegis-Verdict-Id" in resp.headers
    assert "X-Aegis-Reconciled-Tokens" in resp.headers


@pytest.mark.asyncio
async def test_gemini_stream_generate_content_sse(async_client):
    payload = {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": "Stream a short response."}],
            }
        ],
    }

    headers = {
        "x-goog-api-key": "test-gemini-key",
        "x-aegis-session-id": "sess-gemini-stream",
    }

    resp = await async_client.post(
        "/proxy/gemini/v1beta/models/gemini-1.5-pro:streamGenerateContent",
        json=payload,
        headers=headers,
    )
    assert resp.status_code == 200
    assert "text/event-stream" in resp.headers["content-type"]

    body = resp.text
    assert "data: " in body
    assert "candidates" in body
    assert "usageMetadata" in body


@pytest.mark.asyncio
async def test_gemini_policy_denied(async_client):
    # AWS credential in part
    payload = {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": "Leaking secret AKIAIOSFODNN7EXAMPLE right now"}],
            }
        ],
    }

    headers = {
        "x-goog-api-key": "test-gemini-key",
    }

    resp = await async_client.post(
        "/proxy/gemini/v1beta/models/gemini-1.5-pro:generateContent",
        json=payload,
        headers=headers,
    )
    assert resp.status_code == 403
    data = resp.json()

    # Gemini error contract
    assert "error" in data
    assert data["error"]["code"] == 403
    assert data["error"]["status"] == "PERMISSION_DENIED"
    assert "AegisGate Policy Denied" in data["error"]["message"]

