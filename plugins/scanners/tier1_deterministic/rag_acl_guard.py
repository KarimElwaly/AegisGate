import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from core.registry.interfaces import BaseScanner, ScannerResult
from core.schemas.events import EvaluationRequest

CLEARANCE_LEVELS: dict[str, int] = {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "secret": 3,
    "top_secret": 4,
}


class RagAclGuardConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    enabled: bool = True
    default_caller_clearance: str = "internal"
    allow_missing_acl: bool = True
    enforce_hierarchical_clearance: bool = True
    enforce_group_acls: bool = True
    action_on_violation: str = "block"  # "block" | "flag"


class RagAclGuardScanner(BaseScanner):
    name = "rag_acl_guard"
    version = "1.0.0"
    tier = 1
    supported_stages = ["rag_retrieval", "llm_input", "tool_post_call"]
    config_schema = RagAclGuardConfig

    async def scan(
        self,
        request: EvaluationRequest,
        context: dict[str, Any],
        config: BaseModel,
    ) -> ScannerResult:
        cfg = config if isinstance(config, RagAclGuardConfig) else RagAclGuardConfig(**config.model_dump())
        if not cfg.enabled:
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        actor_meta = request.actor.metadata or {}
        caller_clearance = str(
            actor_meta.get("clearance") or request.metadata.get("user_clearance") or cfg.default_caller_clearance
        ).lower()
        caller_rank = CLEARANCE_LEVELS.get(caller_clearance, 0)
        caller_groups = set(actor_meta.get("groups") or request.metadata.get("user_groups") or [])
        caller_id = request.actor.id

        # Inspect chunks from request.content.untrusted_data or metadata
        chunks: list[dict[str, Any]] = []
        raw_data = request.content.untrusted_data
        if isinstance(raw_data, list):
            for item in raw_data:
                if isinstance(item, dict):
                    chunks.append(item)
        elif isinstance(raw_data, dict):
            if "chunks" in raw_data and isinstance(raw_data["chunks"], list):
                chunks.extend(raw_data["chunks"])
            elif "documents" in raw_data and isinstance(raw_data["documents"], list):
                chunks.extend(raw_data["documents"])
            else:
                chunks.append(raw_data)

        if not chunks and request.action and request.action.parameters:
            chunks.append({"text": str(raw_data) if raw_data is not None else "", "metadata": request.action.parameters})

        if not chunks and "retrieved_chunks" in request.metadata:
            retrieved = request.metadata["retrieved_chunks"]
            if isinstance(retrieved, list):
                chunks.extend(retrieved)

        if not chunks:
            return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

        violations: list[dict[str, Any]] = []
        for i, chunk in enumerate(chunks):
            chunk_meta = chunk.get("metadata") or chunk.get("acl") or {}
            chunk_id = chunk.get("id") or chunk.get("chunk_id") or f"chunk_{i}"

            chunk_clearance = chunk_meta.get("classification") or chunk_meta.get("clearance")
            if chunk_clearance:
                chunk_clearance_str = str(chunk_clearance).lower()
                chunk_rank = CLEARANCE_LEVELS.get(chunk_clearance_str, 1)
                if cfg.enforce_hierarchical_clearance and chunk_rank > caller_rank:
                    violations.append({
                        "chunk_id": chunk_id,
                        "reason": f"Required clearance '{chunk_clearance_str}' exceeds caller clearance '{caller_clearance}'",
                    })
                    continue

            # Check group ACLs
            allowed_groups = chunk_meta.get("allowed_groups") or chunk_meta.get("groups")
            if cfg.enforce_group_acls and allowed_groups:
                allowed_set = {str(g).lower() for g in allowed_groups}
                caller_lower_groups = {str(g).lower() for g in caller_groups}
                if not allowed_set.intersection(caller_lower_groups):
                    violations.append({
                        "chunk_id": chunk_id,
                        "reason": f"Caller groups {list(caller_groups)} not in allowed groups {list(allowed_set)}",
                    })
                    continue

            # Check user ACLs
            allowed_users = chunk_meta.get("allowed_users") or chunk_meta.get("users")
            if allowed_users:
                allowed_users_set = {str(u).lower() for u in allowed_users}
                if caller_id.lower() not in allowed_users_set:
                    violations.append({
                        "chunk_id": chunk_id,
                        "reason": f"Caller '{caller_id}' not in allowed users list",
                    })
                    continue

        if violations:
            return ScannerResult(
                scanner_name=self.name,
                tier=self.tier,
                status=cfg.action_on_violation,
                score=0.9,
                details={"violations_count": len(violations), "violations": violations},
                message=f"RAG ACL Guard: {len(violations)} retrieved document chunk(s) violate access control policy",
            )

        return ScannerResult(scanner_name=self.name, tier=self.tier, status="pass")

