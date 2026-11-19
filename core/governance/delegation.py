from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, ConfigDict, Field
from core.logger import get_logger
from core.schemas.events import ActorModel

logger = get_logger("core.governance.delegation")


class DelegationPolicyConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    enabled: bool = True
    max_delegation_depth: int = 3
    # allowed_role_matrix: {delegator_role: [allowed_delegatee_roles]}
    allowed_role_matrix: Dict[str, List[str]] = Field(default_factory=dict)
    # role_tool_permissions: {role: [allowed_tool_names] or "*"}
    role_tool_permissions: Dict[str, List[str]] = Field(default_factory=dict)
    # denied_roles: roles that cannot execute actions
    denied_roles: List[str] = Field(default_factory=list)


class DelegationValidator:
    """Enforces delegation depth limits, allowed role transition matrices,
    and prevents privilege escalation across multi-agent delegation chains.
    """

    def validate_delegation(
        self,
        actor: ActorModel,
        action_name: str,
        config: DelegationPolicyConfig,
    ) -> Tuple[bool, Optional[str]]:
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

        # 3. Check role-tool permission for current actor
        if config.role_tool_permissions:
            current_role_perms = config.role_tool_permissions.get(actor.role, [])
            if "*" not in current_role_perms and action_name not in current_role_perms:
                return False, f"Role '{actor.role}' is not authorized to execute tool '{action_name}'"

        # 4. Privilege Escalation Prevention across the delegation chain
        # If actor was delegated by an originator, the originator must ALSO have permission for action_name
        if chain and config.role_tool_permissions:
            originator_id = chain[0]
            # If originator has a known role or permissions in config
            for delegator_id in chain:
                # Check if delegator role is mapped in permissions
                # If delegator role is explicitly registered and lacks permission, deny!
                if delegator_id in config.role_tool_permissions:
                    allowed_tools = config.role_tool_permissions[delegator_id]
                    if "*" not in allowed_tools and action_name not in allowed_tools:
                        return (
                            False,
                            f"Privilege escalation denied: Delegator '{delegator_id}' lacks permission for tool '{action_name}'",
                        )

        # 5. Role transition matrix check
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
