import pytest

from core.auth.agent_identity import AgentIdentityService
from core.governance.delegation import DelegationPolicyConfig, DelegationValidator
from core.governance.taint_tracker import TaintTracker
from core.schemas.events import ActorModel


@pytest.mark.asyncio
async def test_taint_tracker_lifecycle():
    tracker = TaintTracker()
    tenant = "test-tenant-taints"
    session_id = "sess-taint-01"

    # Initially empty
    taints = await tracker.get_taints(tenant, session_id)
    assert taints == set()

    # Add taints
    await tracker.add_taints(tenant, session_id, ["confidential_pii", "pci_cardholder"])
    taints = await tracker.get_taints(tenant, session_id)
    assert taints == {"confidential_pii", "pci_cardholder"}

    # has_any_taints
    assert await tracker.has_any_taints(tenant, session_id, ["confidential_pii"]) is True
    assert await tracker.has_any_taints(tenant, session_id, ["unrelated"]) is False
    assert await tracker.has_any_taints(tenant, session_id, ["unrelated", "pci_cardholder"]) is True

    # has_all_taints
    assert await tracker.has_all_taints(tenant, session_id, ["confidential_pii"]) is True
    assert await tracker.has_all_taints(tenant, session_id, ["confidential_pii", "pci_cardholder"]) is True
    assert await tracker.has_all_taints(tenant, session_id, ["confidential_pii", "secret"]) is False

    # Clear taints
    cleared = await tracker.clear_taints(tenant, session_id)
    assert cleared is True
    assert await tracker.get_taints(tenant, session_id) == set()


def test_agent_identity_mint_and_verify():
    svc = AgentIdentityService(secret_key="secret-key-for-test-32bytes-min!!")

    # 1. Mint root agent token
    root_token = svc.mint_agent_token(
        agent_id="agent-coordinator",
        role="orchestrator",
        allowed_tools=["read_file", "search_db", "send_email"],
        ttl_seconds=60,
    )
    payload = svc.verify_agent_token(root_token)
    assert payload["sub"] == "agent-coordinator"
    assert payload["role"] == "orchestrator"
    assert payload["allowed_tools"] == ["read_file", "search_db", "send_email"]
    assert payload["delegation_depth"] == 0

    # 2. Mint attenuated child agent token
    child_token = svc.mint_child_token(
        parent_token=root_token,
        child_agent_id="agent-sub-worker",
        child_role="analyst",
        allowed_tools=["read_file", "search_db"],  # Proper subset
    )
    child_payload = svc.verify_agent_token(child_token)
    assert child_payload["sub"] == "agent-sub-worker"
    assert child_payload["parent_jti"] == payload["jti"]
    assert child_payload["delegation_depth"] == 1
    assert set(child_payload["allowed_tools"]) == {"read_file", "search_db"}

    # 3. Test privilege expansion prevention during delegation
    with pytest.raises(ValueError, match="violates monotonic attenuation"):
        svc.mint_child_token(
            parent_token=root_token,
            child_agent_id="agent-rogue-child",
            child_role="superadmin",
            allowed_tools=["delete_database", "read_file"],  # Escalation!
        )


def test_cryptographic_delegation_chain_validation():
    from core.auth.agent_identity import get_agent_identity_service

    svc = get_agent_identity_service()
    validator = DelegationValidator()

    # Create root token
    token_0 = svc.mint_agent_token(
        agent_id="lead-agent",
        role="lead",
        allowed_tools=["read_doc", "write_doc"],
    )
    # Create child token
    token_1 = svc.mint_child_token(
        parent_token=token_0,
        child_agent_id="worker-agent",
        child_role="worker",
        allowed_tools=["read_doc"],
    )

    config = DelegationPolicyConfig(
        require_signed_delegation=True,
        max_delegation_depth=2,
    )

    # Actor with valid signed chain
    valid_actor = ActorModel(
        id="worker-agent",
        role="worker",
        delegation_chain=["lead-agent"],
        metadata={"signed_delegation_tokens": [token_0, token_1]},
    )

    # 1. Executing allowed tool "read_doc" -> Success
    ok, err = validator.validate_delegation(valid_actor, "read_doc", config)
    assert ok is True
    assert err is None

    # 2. Executing attenuated tool "write_doc" -> Denied by cryptographic monotonic attenuation
    ok, err = validator.validate_delegation(valid_actor, "write_doc", config)
    assert ok is False
    assert "not in cryptographically authorized tools" in err

    # 3. Actor missing signed delegation tokens -> Denied
    invalid_actor = ActorModel(id="worker-agent", role="worker")
    ok, err = validator.validate_delegation(invalid_actor, "read_doc", config)
    assert ok is False
    assert "Signed delegation required" in err
