import pytest
from core.pii_vault.vault import PiiVault


@pytest.mark.asyncio
async def test_pii_vault_tokenization_and_rehydration():
    vault = PiiVault(ttl_seconds=60)
    tenant_id = "test-tenant"
    session_id = "sess-123"

    # Tokenize IP
    ip = "192.168.1.50"
    token1 = await vault.tokenize(tenant_id, session_id, "IPV4", ip)
    assert token1.startswith("<AEGIS_IPV4_")

    # Idempotent tokenization in same session
    token2 = await vault.tokenize(tenant_id, session_id, "IPV4", ip)
    assert token1 == token2

    # Second unique IP gets next index
    ip2 = "10.0.0.1"
    token3 = await vault.tokenize(tenant_id, session_id, "IPV4", ip2)
    assert token3 != token1

    # Re-hydration
    llm_output = f"Connecting to host {token1} and backup {token3} done."
    rehydrated = await vault.rehydrate(tenant_id, session_id, llm_output)
    assert rehydrated == "Connecting to host 192.168.1.50 and backup 10.0.0.1 done."

    # Session mappings
    mappings = await vault.get_session_mappings(tenant_id, session_id)
    assert mappings[token1] == ip
    assert mappings[token3] == ip2
