from typing import Any

from gateways.llm_proxy.translators.openai_translator import OpenAIProtocolTranslator


class AzureOpenAIProtocolTranslator(OpenAIProtocolTranslator):
    """Protocol translator for Azure OpenAI Deployments API (/deployments/{deployment}/chat/completions)."""

    protocol_name: str = "azure_openai"

    def extract_canonical_input(
        self, body: dict[str, Any], path_params: dict[str, str] | None = None
    ) -> tuple[str, str, list[dict[str, Any]], str, bool]:
        trusted, untrusted, attachments, model, stream = super().extract_canonical_input(body, path_params)
        # In Azure OpenAI, deployment name is often in the path
        if path_params and "deployment" in path_params:
            model = path_params["deployment"]
        elif not model or model == "default-model":
            model = body.get("model") or "azure-gpt-4o"
        return trusted, untrusted, attachments, model, stream

