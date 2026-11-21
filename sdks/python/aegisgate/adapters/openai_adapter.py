from typing import Any


class AegisOpenAIAdapter:
    """Configures and wraps an OpenAI client to route through AegisGate LLM Proxy seamlessly."""

    def __init__(
        self,
        base_url: str = "http://localhost:8088/proxy/llm/v1",
        api_key: str = "ag_live_client_key",
        tenant_id: str = "default",
        workspace_id: str = "default",
        policy_pack_id: str = "base-enterprise",
        session_id: str | None = None,
    ) -> None:
        self.base_url = base_url
        self.api_key = api_key
        self.tenant_id = tenant_id
        self.workspace_id = workspace_id
        self.policy_pack_id = policy_pack_id
        self.session_id = session_id

    def get_client_kwargs(self) -> dict[str, Any]:
        """Returns kwargs to instantiate an openai.OpenAI or AsyncOpenAI client."""
        headers = {
            "X-Aegis-Tenant-Id": self.tenant_id,
            "X-Aegis-Workspace-Id": self.workspace_id,
            "X-Aegis-Policy-Pack": self.policy_pack_id,
            "X-Aegis-Api-Key": self.api_key,
        }
        if self.session_id:
            headers["X-Aegis-Session-Id"] = self.session_id

        return {
            "base_url": self.base_url,
            "api_key": self.api_key,
            "default_headers": headers,
        }

