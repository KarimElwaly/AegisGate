import pytest

from sdks.python.aegisgate.client import AegisClient
from sdks.python.aegisgate.decorators import governed_llm, governed_tool
from sdks.python.aegisgate.exceptions import PolicyViolationError


@pytest.mark.asyncio
async def test_llm_proxy_clean_and_blocked_completions(api_client):
    # 1. Clean completion request through proxy
    clean_body = {
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "What is the capital of France?"},
        ],
    }
    resp_clean = await api_client.post("/proxy/llm/v1/chat/completions", json=clean_body)
    assert resp_clean.status_code == 200
    data = resp_clean.json()
    assert "choices" in data
    assert resp_clean.headers.get("X-Aegis-Verdict-Id") is not None

    # 2. Blocked prompt (contains AWS secret key)
    malicious_body = {
        "model": "gpt-4o",
        "messages": [
            {"role": "user", "content": "Use key AKIAIOSFODNN7EXAMPLE to log in."},
        ],
    }
    resp_blocked = await api_client.post("/proxy/llm/v1/chat/completions", json=malicious_body)
    assert resp_blocked.status_code == 403
    err = resp_blocked.json()
    assert err["error"]["type"] == "aegisgate_policy_violation"
    assert "AKIA" in str(err) or "secret" in str(err).lower()


@pytest.mark.asyncio
async def test_llm_proxy_sse_streaming(api_client):
    body = {
        "model": "gpt-4o",
        "stream": True,
        "messages": [{"role": "user", "content": "Tell me a joke."}],
    }
    resp = await api_client.post("/proxy/llm/v1/chat/completions", json=body)
    assert resp.status_code == 200
    assert "text/event-stream" in resp.headers.get("content-type", "")

    # Models endpoint
    models_resp = await api_client.get("/proxy/llm/v1/models")
    assert models_resp.status_code == 200
    assert len(models_resp.json()["data"]) > 0


@pytest.mark.asyncio
async def test_tool_gateway_pre_call_and_post_call(api_client):
    # 1. Safe tool call
    resp_safe = await api_client.post(
        "/proxy/tools/get_weather",
        json={"parameters": {"city": "Paris"}},
    )
    assert resp_safe.status_code == 200
    assert "status" in resp_safe.json()

    # 2. Blocked tool call (Path traversal parameter)
    resp_traversal = await api_client.post(
        "/proxy/tools/read_file",
        json={"parameters": {"path": "../../../etc/passwd"}},
    )
    assert resp_traversal.status_code == 403
    err = resp_traversal.json()
    assert err["error"]["type"] == "aegisgate_tool_denial"


@pytest.mark.asyncio
async def test_mcp_jsonrpc_gateway(api_client):
    # 1. tools/list
    resp_list = await api_client.post(
        "/proxy/mcp/jsonrpc",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    assert resp_list.status_code == 200
    res_data = resp_list.json()
    assert "result" in res_data
    assert "tools" in res_data["result"]

    # 2. tools/call safe
    resp_call_safe = await api_client.post(
        "/proxy/mcp/jsonrpc",
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "query_database", "arguments": {"query": "SELECT count(*) FROM users"}},
        },
    )
    assert resp_call_safe.status_code == 200
    assert resp_call_safe.json()["result"]["content"][0]["type"] == "text"

    # 3. tools/call blocked (Shell metacharacters injection)
    resp_call_blocked = await api_client.post(
        "/proxy/mcp/jsonrpc",
        json={
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "run_shell", "arguments": {"cmd": "echo 1; rm -rf /"}},
        },
    )
    assert resp_call_blocked.status_code == 200
    err_json = resp_call_blocked.json()
    assert "error" in err_json
    assert err_json["error"]["code"] == -32001
    assert "Policy Denied" in err_json["error"]["message"]


@pytest.mark.asyncio
async def test_python_sdk_and_decorators(api_client):
    # Test SDK client with transport from api_client
    sdk = AegisClient(
        base_url="http://testserver",
        fail_open=False,
        transport=api_client._transport,
    )

    # Wrap async tool with @governed_tool
    @governed_tool(name="read_document", client=sdk)
    async def sample_tool(path: str):
        return f"Content of {path}"

    # Safe call passes
    out = await sample_tool(path="docs/readme.txt")
    assert out == "Content of docs/readme.txt"

    # Dangerous call with path traversal is blocked before function executes!
    with pytest.raises(PolicyViolationError) as exc_info:
        await sample_tool(path="../../secrets.txt")
    assert "blocked by policy" in str(exc_info.value)

    # Test @governed_llm
    @governed_llm(client=sdk)
    async def sample_llm(prompt: str):
        return "Clean LLM response"

    llm_out = await sample_llm("Explain machine learning")
    assert llm_out == "Clean LLM response"

    with pytest.raises(PolicyViolationError):
        await sample_llm("Here is my key: AKIAIOSFODNN7EXAMPLE")
