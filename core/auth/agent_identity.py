import datetime
import time
import uuid
from typing import Any

import jwt

from core.config import get_settings
from core.logger import get_logger

logger = get_logger("core.auth.agent_identity")


class AgentIdentityService:
    """Mints and cryptographically validates short-lived signed Agent JWTs with monotonic attenuation."""

    ALGORITHM = "HS256"

    def __init__(self, secret_key: str | None = None) -> None:
        self.secret_key = secret_key or getattr(get_settings(), "AEGIS_SECRET_KEY", "default-insecure-secret-key-change-me")

    def mint_agent_token(
        self,
        agent_id: str,
        role: str,
        allowed_tools: list[str],
        parent_jti: str | None = None,
        delegation_depth: int = 0,
        ttl_seconds: int = 300,
    ) -> str:
        now = int(time.time())
        jti = str(uuid.uuid4())
        payload = {
            "sub": agent_id,
            "role": role,
            "allowed_tools": list(allowed_tools),
            "jti": jti,
            "parent_jti": parent_jti,
            "delegation_depth": delegation_depth,
            "iat": now,
            "exp": now + ttl_seconds,
        }
        return jwt.encode(payload, self.secret_key, algorithm=self.ALGORITHM)

    def verify_agent_token(self, token: str) -> dict[str, Any]:
        try:
            return jwt.decode(token, self.secret_key, algorithms=[self.ALGORITHM])
        except jwt.PyJWTError as e:
            raise ValueError(f"Invalid or expired agent token: {e!s}")

    def mint_child_token(
        self,
        parent_token: str,
        child_agent_id: str,
        child_role: str,
        allowed_tools: list[str],
        ttl_seconds: int = 300,
    ) -> str:
        parent_claims = self.verify_agent_token(parent_token)
        parent_allowed = set(parent_claims.get("allowed_tools", []))

        # Monotonic attenuation enforcement
        if not set(allowed_tools).issubset(parent_allowed) and "*" not in parent_allowed:
            raise ValueError(
                "Child tool scope violates monotonic attenuation: child cannot possess permissions not granted to parent"
            )

        return self.mint_agent_token(
            agent_id=child_agent_id,
            role=child_role,
            allowed_tools=list(allowed_tools),
            parent_jti=parent_claims.get("jti"),
            delegation_depth=parent_claims.get("delegation_depth", 0) + 1,
            ttl_seconds=ttl_seconds,
        )

    def create_delegated_token(
        self,
        parent_token: str,
        child_agent_id: str,
        child_role: str,
        requested_tools: list[str],
        ttl_seconds: int = 300,
    ) -> str:
        parent_claims = self.verify_agent_token(parent_token)
        parent_allowed = set(parent_claims.get("allowed_tools", []))

        # Monotonic permission attenuation: child tools MUST be a subset of parent tools
        attenuated_tools = list(parent_allowed.intersection(set(requested_tools)))

        return self.mint_agent_token(
            agent_id=child_agent_id,
            role=child_role,
            allowed_tools=attenuated_tools,
            parent_jti=parent_claims.get("jti"),
            delegation_depth=parent_claims.get("delegation_depth", 0) + 1,
            ttl_seconds=ttl_seconds,
        )

    def verify_delegation_chain(
        self, tokens: list[str]
    ) -> tuple[bool, str | None, list[str]]:
        """Verifies full cryptographic signature chain and monotonic tool attenuation.
        Returns: (is_valid, failure_reason, effective_allowed_tools)
        """
        if not tokens:
            return False, "Delegation chain is empty", []

        parsed_claims: list[dict[str, Any]] = []
        for i, token in enumerate(tokens):
            try:
                claims = self.verify_agent_token(token)
                parsed_claims.append(claims)
            except Exception as e:
                return False, f"Invalid token at chain index {i}: {e!s}", []

        # Verify parent-child linkage and monotonic attenuation
        for i in range(1, len(parsed_claims)):
            parent = parsed_claims[i - 1]
            child = parsed_claims[i]

            if child.get("parent_jti") != parent.get("jti"):
                return False, f"Broken delegation chain linkage between index {i-1} and {i}", []

            if child.get("delegation_depth", 0) <= parent.get("delegation_depth", 0):
                return False, f"Non-increasing delegation depth at index {i}", []

            parent_tools = set(parent.get("allowed_tools", []))
            child_tools = set(child.get("allowed_tools", []))
            if not child_tools.issubset(parent_tools):
                diff = child_tools - parent_tools
                return (
                    False,
                    f"Monotonic attenuation violation at index {i}: child escalated tools {list(diff)}",
                    [],
                )

        leaf_tools = parsed_claims[-1].get("allowed_tools", [])
        return True, None, leaf_tools


default_agent_identity_service = AgentIdentityService()


def get_agent_identity_service() -> AgentIdentityService:
    return default_agent_identity_service

