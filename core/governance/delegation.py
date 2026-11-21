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
            signed_tokens = actor.metadata.get("signed_delegation_tokens")
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

            # Anti-privilege escalation check across the delegation chain:
            # No delegated agent can possess more rights than any of its delegators
            for ancestor_role in chain:
                ancestor_perms = config.role_tool_permissions.get(ancestor_role, [])
                if "*" not in ancestor_perms and action_name not in ancestor_perms:
                    return (
                        False,
                        f"Privilege escalation denied: ancestor role '{ancestor_role}' in delegation chain lacks permission for '{action_name}'",
                    )

        # 5. Role transition matrix check
        if config.allowed_role_matrix and len(chain) > 1:
            for i in range(len(chain) - 1):
                delegator_role = chain[i]
                delegatee_role = chain[i + 1]
                allowed = config.allowed_role_matrix.get(delegator_role, [])
                if allowed and delegatee_role not in allowed and "*" not in allowed:
                    return (
                        False,
                        f"Role transition from '{delegator_role}' to '{delegatee_role}' is prohibited by matrix",
                    )

        return True, None


default_delegation_validator = DelegationValidator()


def get_delegation_validator() -> DelegationValidator:
    return default_delegation_validator
