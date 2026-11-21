from pydantic import BaseModel, ConfigDict, Field

from core.auth.agent_identity import get_agent_identity_service
from core.logger import get_logger
from core.schemas.events import ActorModel

logger = get_logger("core.governance.delegation")


class DelegationPolicyConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    enabled: bool = True
    max_delegation_depth: int = 3
    # allowed_role_matrix: {delegator_role: [allowed_delegatee_roles]}
    allowed_role_matrix: dict[str, list[str]] = Field(default_factory=dict)
    # role_tool_permissions: {role: [allowed_tool_names] or "*"}
    role_tool_permissions: dict[str, list[str]] = Field(default_factory=dict)
    # denied_roles: roles that cannot execute actions
    denied_roles: list[str] = Field(default_factory=list)
    # require_signed_delegation: cryptographically verify signed agent tokens with monotonic attenuation
    require_signed_delegation: bool = False


class DelegationValidator:
    """Enforces delegation depth limits, allowed role transition matrices,
    and prevents privilege escalation across multi-agent delegation chains.
    """

    def validate_delegation(
        self,
        actor: ActorModel,
        action_name: str,
        config: DelegationPolicyConfig,
    ) -> tuple[bool, str | None]:
        if not config.enabled:
            return True, None

        chain = actor.delegation_chain or []

        # 1. Denied roles check
        if actor.role in config.denied_roles:
            return False, f"Actor role '{actor.role}' is in denied roles list"

        # 2. Maximum delegation depth check
        depth = len(chain)
        if depth > config.max_delegation_depth:
            return False, f"Delegation depth {depth} exceeds maximum allowed depth {config.max_delegation_depth}"

        # 3. Cryptographic Signed Delegation Chain Verification (Anti-Forging & Monotonic Attenuation)
        if config.require_signed_delegation:
            metadata = getattr(actor, "metadata", None) or {}
            signed_tokens = metadata.get("signed_delegation_tokens")
            if not signed_tokens or not isinstance(signed_tokens, list):
                return False, "Signed delegation required but no signed_delegation_tokens provided"

            identity_svc = get_agent_identity_service()
            is_valid, reason, leaf_tools = identity_svc.verify_delegation_chain(signed_tokens)
            if not is_valid:
                return False, f"Signed delegation failure: {reason}"

            if leaf_tools and "*" not in leaf_tools and action_name not in leaf_tools:
                return (
                    False,
                    f"Action '{action_name}' is not in cryptographically authorized tools: {leaf_tools}",
                )

        # 4. Check role-tool permission for current actor
        if config.role_tool_permissions:
            current_role_perms = config.role_tool_permissions.get(actor.role, [])
            if "*" not in current_role_perms and action_name not in current_role_perms:
                return False, f"Role '{actor.role}' is not authorized to execute tool '{action_name}'"

        # 5. Privilege Escalation Prevention across the delegation chain
        # If actor was delegated by an originator, the originator must ALSO have permission for action_name
        if chain and config.role_tool_permissions:
            for delegator_id in chain:
                if delegator_id in config.role_tool_permissions:
                    allowed_tools = config.role_tool_permissions[delegator_id]
                    if "*" not in allowed_tools and action_name not in allowed_tools:
                        return (
                            False,
                            f"Privilege escalation denied: Delegator '{delegator_id}' lacks permission for tool '{action_name}'",
                        )

        # 6. Role transition matrix check
        if config.allowed_role_matrix and len(chain) > 1:
            for i in range(len(chain) - 1):
                parent_role = chain[i]
                child_role = chain[i + 1]
                allowed_children = config.allowed_role_matrix.get(parent_role, [])
                if child_role not in allowed_children and "*" not in allowed_children:
                    return (
                        False,
                        f"Invalid delegation step: Role '{parent_role}' cannot delegate to '{child_role}'",
                    )

        return True, None


default_delegation_validator = DelegationValidator()


def get_delegation_validator() -> DelegationValidator:
    return default_delegation_validator
