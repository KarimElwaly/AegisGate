from typing import Any

from aegisgate.client import AegisClient
from aegisgate.exceptions import PolicyViolationError
from aegisgate.models import ActionModel, ActorModel, ContentModel, EvaluationRequest, StageEnum


class LlamaIndexGuard:
    """AegisGate Governance Adapter for LlamaIndex RAG Pipelines & Query Engines."""

    def __init__(
        self,
        client: AegisClient | None = None,
        policy_pack_id: str = "rag-copilot-pack",
        actor_id: str = "llamaindex_user",
        actor_role: str = "internal",
        tenant_id: str = "default",
    ) -> None:
        self.client = client or AegisClient()
        self.policy_pack_id = policy_pack_id
        self.actor_id = actor_id
        self.actor_role = actor_role
        self.tenant_id = tenant_id

    async def post_retrieval_filter(
        self,
        nodes: list[Any],
        query_str: str | None = None,
    ) -> list[Any]:
        """Post-retrieval node filter enforcing RAG ACL clearance and chunk sanitization."""
        filtered_nodes = []
        for node in nodes:
            # Extract text and metadata from LlamaIndex NodeWithScore or TextNode
            text = getattr(node, "text", "") or (
                getattr(node.node, "text", "") if hasattr(node, "node") else str(node)
            )
            metadata = getattr(node, "metadata", {}) or (
                getattr(node.node, "metadata", {}) if hasattr(node, "node") else {}
            )

            eval_req = EvaluationRequest(
                tenant_id=self.tenant_id,
                policy_pack_id=self.policy_pack_id,
                stage=StageEnum.RAG_RETRIEVAL,
                actor=ActorModel(id=self.actor_id, role=self.actor_role),
                action=ActionModel(name="retrieve_chunk", parameters=metadata),
                content=ContentModel(
                    trusted_instructions=query_str or "",
                    untrusted_data={"text": text, "metadata": metadata},
                ),
            )

            verdict = await self.client.evaluate(eval_req)
            if verdict.decision != "DENY":
                filtered_nodes.append(node)

        return filtered_nodes

    async def post_response_guard(
        self,
        response_text: str,
        query_str: str | None = None,
    ) -> str:
        """Post-response output guard inspecting synthesized answer for hallucination and leaks."""
        eval_req = EvaluationRequest(
            tenant_id=self.tenant_id,
            policy_pack_id=self.policy_pack_id,
            stage=StageEnum.LLM_OUTPUT,
            actor=ActorModel(id=self.actor_id, role=self.actor_role),
            action=ActionModel(name="synthesize_response"),
            content=ContentModel(
                trusted_instructions=query_str or "",
                output_payload=response_text,
            ),
        )

        verdict = await self.client.evaluate(eval_req)
        if verdict.decision == "DENY":
            reason = verdict.triggered_rules[0].reason if verdict.triggered_rules else "Output blocked"
            raise PolicyViolationError(f"AegisGate LlamaIndex Response Denied: {reason}", verdict)

        return response_text
