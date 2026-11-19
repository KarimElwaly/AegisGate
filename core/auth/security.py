import datetime
import hashlib
import os
import secrets
from typing import Any, Dict, Optional, Tuple
import jwt
from core.config import get_settings

SETTINGS = get_settings()


def hash_password(password: str) -> str:
    """Hashes a password with PBKDF2-HMAC-SHA256 and a random 16-byte salt."""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return f"{salt.hex()}${dk.hex()}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plaintext password against a stored salt$hash string."""
    try:
        salt_hex, hash_hex = hashed_password.split("$")
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, 100_000)
        return secrets.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


def create_access_token(
    data: Dict[str, Any],
    expires_delta: Optional[datetime.timedelta] = None,
) -> str:
    """Encodes a JWT access token containing subject, tenant_id, role, and expiration."""
    to_encode = data.copy()
    now = datetime.datetime.utcnow()
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + datetime.timedelta(minutes=SETTINGS.AEGIS_JWT_EXPIRY_MINUTES)
    to_encode.update({"iat": now, "exp": expire})
    encoded_jwt = jwt.encode(
        to_encode,
        SETTINGS.AEGIS_SECRET_KEY,
        algorithm=SETTINGS.AEGIS_JWT_ALGORITHM,
    )
    return encoded_jwt


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decodes and cryptographically validates a JWT access token."""
    return jwt.decode(
        token,
        SETTINGS.AEGIS_SECRET_KEY,
        algorithms=[SETTINGS.AEGIS_JWT_ALGORITHM],
    )


def generate_api_key(tenant_id: str, role: str) -> Tuple[str, str, str]:
    """
    Generates a secure scoped API key.
    Returns:
      raw_api_key: presented once to caller (e.g. aegis_live_...)
      key_prefix: first 12 characters for indexing/display
      key_hash: SHA256 hex string stored in DB
    """
    raw_random = secrets.token_hex(24)
    raw_api_key = f"aegis_live_{raw_random}"
    key_prefix = raw_api_key[:12]
    key_hash = hashlib.sha256(raw_api_key.encode("utf-8")).hexdigest()
    return raw_api_key, key_prefix, key_hash
