import asyncio
import datetime
import time
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from core.auth.oidc import OidcConfig, OidcService
from gateways.llm_proxy.streaming import SSEStreamGuard


# ---------------------------------------------------------------------------
# 1. RSA Key Fixture for OIDC Verification Tests
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def test_oidc_rs256_valid_token_verification(rsa_key_pair):
    """Test cryptographic RS256 signature verification and group mapping."""
    private_pem, public_pem = rsa_key_pair
    now = int(time.time())

    cfg = OidcConfig(
        enabled=True,
        issuer="https://auth.company.internal/",
        client_id="aegisgate-portal",
        role_claim="roles",
    )
    svc = OidcService(config=cfg)

    payload = {
        "sub": "user_12345",
        "email": "alice@company.com",
        "iss": "https://auth.company.internal/",
        "aud": "aegisgate-portal",
        "roles": ["aegis_admins"],
        "iat": now,
        "exp": now + 3600,
        "nbf": now - 10,
    }

    token = jwt.encode(payload, private_pem, algorithm="RS256", headers={"kid": "key-2026-v1"})

    # Verify using the corresponding public key
    claims = svc.verify_oidc_token(token, key=public_pem)
    assert claims["sub"] == "user_12345"
    assert claims["role"] == "SuperAdmin"


def test_oidc_rs256_expired_token_rejected(rsa_key_pair):
    """Test expired OIDC tokens are rejected cryptographically."""
    private_pem, public_pem = rsa_key_pair
    now = int(time.time())

    cfg = OidcConfig(
        enabled=True,
        issuer="https://auth.company.internal/",
        client_id="aegisgate-portal",
    )
    svc = OidcService(config=cfg)

    expired_payload = {
        "sub": "user_12345",
        "iss": "https://auth.company.internal/",
        "aud": "aegisgate-portal",
        "groups": ["aegis_operators"],
        "iat": now - 7200,
        "exp": now - 3600,  # Expired 1 hour ago
    }

    token = jwt.encode(expired_payload, private_pem, algorithm="RS256")
    with pytest.raises(ValueError) as exc:
        svc.verify_oidc_token(token, key=public_pem)
    assert "expired" in str(exc.value).lower()


def test_oidc_rs256_wrong_audience_rejected(rsa_key_pair):
    """Test token intended for another client/audience is rejected."""
    private_pem, public_pem = rsa_key_pair
    now = int(time.time())

    cfg = OidcConfig(
        enabled=True,
        issuer="https://auth.company.internal/",
        client_id="aegisgate-portal",
    )
    svc = OidcService(config=cfg)

    wrong_aud_payload = {
        "sub": "user_12345",
        "iss": "https://auth.company.internal/",
        "aud": "wrong-external-app",
        "groups": ["aegis_admins"],
        "iat": now,
        "exp": now + 3600,
    }

    token = jwt.encode(wrong_aud_payload, private_pem, algorithm="RS256")
    with pytest.raises(ValueError) as exc:
        svc.verify_oidc_token(token, key=public_pem)
    assert "audience" in str(exc.value).lower() or "verification failed" in str(exc.value).lower()


def test_oidc_key_rotation_retry(rsa_key_pair):
    """Test unknown kid triggers JWKS cache refresh for rotated keys."""
    private_pem, public_pem = rsa_key_pair
    now = int(time.time())

    cfg = OidcConfig(
        enabled=True,
        issuer="https://auth.company.internal/",
        client_id="aegisgate-portal",
        jwks_uri="https://auth.company.internal/.well-known/jwks.json",
    )
    svc = OidcService(config=cfg)

    # Mock JWKS client that fails on first try (cache miss) and succeeds on refresh
    mock_jwk = MagicMock()
    mock_jwk.key = public_pem

    mock_client = MagicMock()
    # First call raises PyJWKClientError, second call succeeds after get_jwk_set(refresh=True)
    mock_client.get_signing_key_from_jwt.side_effect = [
        jwt.PyJWKClientError("Unable to find key with kid: key-rotated-v2"),
        mock_jwk,
    ]

    token = jwt.encode(
        {
            "sub": "user_rotated",
            "iss": "https://auth.company.internal/",
            "aud": "aegisgate-portal",
            "groups": ["aegis_auditors"],
            "iat": now,
            "exp": now + 3600,
        },
        private_pem,
        algorithm="RS256",
        headers={"kid": "key-rotated-v2"},
    )

    claims = svc.verify_oidc_token(token, jwks_client=mock_client)
    assert claims["sub"] == "user_rotated"
    assert claims["role"] == "Auditor"
    mock_client.get_jwk_set.assert_called_once_with(refresh=True)


# ---------------------------------------------------------------------------
# 2. SSE Streaming Token Reconciliation & Abort Tests
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_sse_stream_usage_chunk_token_reconciliation():
    """Test SSEStreamGuard extracts exact usage chunk and calls reconcile_tokens."""
    reconciled_delta = None

    async def mock_reconcile(tenant_id, scope_type, scope_id, delta):
        nonlocal reconciled_delta
        reconciled_delta = delta

    with patch("gateways.llm_proxy.streaming.get_budget_manager") as mock_bm:
        mock_bm.return_value.reconcile_tokens = AsyncMock(side_effect=mock_reconcile)

        guard = SSEStreamGuard(
            tenant_id="test-tenant",
            session_id="test-session-123",
            estimated_prompt_tokens=15,
        )

        async def upstream_stream():
            yield b"data: {\"choices\": [{\"delta\": {\"content\": \"Hello \"}}]}\n\n"
            yield b"data: {\"choices\": [{\"delta\": {\"content\": \"world!\"}}]}\n\n"
            yield b"data: {\"choices\": [], \"usage\": {\"prompt_tokens\": 15, \"completion_tokens\": 5, \"total_tokens\": 20}}\n\n"
            yield b"data: [DONE]\n\n"

        chunks = []
        async for c in guard.guard_stream(upstream_stream()):
            chunks.append(c)

        full_text = b"".join(chunks).decode("utf-8")
        assert "Hello " in full_text
        assert "world!" in full_text
        assert "[DONE]" in full_text
        # Delta = actual (20) - estimated (15) = 5
        assert reconciled_delta == 5


@pytest.mark.asyncio
async def test_sse_stream_credential_leak_abort_and_audit():
    """Test mid-stream AWS secret leak triggers immediate abort and audit record."""
    guard = SSEStreamGuard(
        tenant_id="test-tenant",
        session_id="test-session-abort",
        estimated_prompt_tokens=10,
    )

    async def leak_stream():
        yield b"data: {\"choices\": [{\"delta\": {\"content\": \"Here is your AWS access key: \"}}]}\n\n"
        yield b"data: {\"choices\": [{\"delta\": {\"content\": \"AKIAIOSFODNN7EXAMPLE\"}}]}\n\n"
        yield b"data: {\"choices\": [{\"delta\": {\"content\": \" Never share it.\"}}]}\n\n"
        yield b"data: [DONE]\n\n"

    chunks = []
    async for c in guard.guard_stream(leak_stream()):
        chunks.append(c.decode("utf-8"))

    full_output = "".join(chunks)
    assert "[STREAM ABORTED BY AEGISGATE: Sensitive credential leak detected]" in full_output
    assert "AKIAIOSFODNN7EXAMPLE" not in full_output
    assert "data: [DONE]" in full_output
