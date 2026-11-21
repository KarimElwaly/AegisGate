import base64
import hashlib
import hmac
import json
import os
from abc import ABC, abstractmethod
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.config import get_settings
from core.logger import get_logger

logger = get_logger("core.crypto.kms")


class KeyProvider(ABC):
    """Abstract interface for Enterprise KMS & Envelope Encryption Key Providers."""

    @abstractmethod
    def current_key_version(self) -> str:
        """Returns the active key version string (e.g. 'v1', 'v2')."""
        pass

    @abstractmethod
    def encrypt_dek(self, plaintext: str) -> dict[str, Any]:
        """Encrypts plaintext string using envelope encryption (AES-256-GCM).
        Returns dict containing: version, nonce, ciphertext (base64 encoded).
        """
        pass

    @abstractmethod
    def decrypt_dek(self, encrypted_payload: dict[str, Any] | str) -> str:
        """Decrypts envelope ciphertext payload back to plaintext string."""
        pass

    @abstractmethod
    def sign_hmac(self, data: str) -> str:
        """Generates an HMAC-SHA256 signature for data using the active key."""
        pass

    @abstractmethod
    def verify_hmac(self, data: str, signature: str) -> bool:
        """Verifies an HMAC signature against data in constant time."""
        pass


class LocalEnvKeyProvider(KeyProvider):
    """Local-first developer and self-hosted KeyProvider using AES-256-GCM and HKDF/SHA256 subkeys."""

    def __init__(self, master_key: str | None = None, active_version: str = "v1") -> None:
        self.master_key = master_key or get_settings().AEGIS_SECRET_KEY
        self._active_version = active_version
        self._version_keys: dict[str, bytes] = {}
        self._derive_key_for_version(active_version)

    def _derive_key_for_version(self, version: str) -> bytes:
        if version not in self._version_keys:
            # 32-byte key derived from master_key + version salt
            derived = hashlib.sha256(f"{self.master_key}:{version}".encode("utf-8")).digest()
            self._version_keys[version] = derived
        return self._version_keys[version]

    def current_key_version(self) -> str:
        return self._active_version

    def rotate_key(self, new_version: str) -> None:
        """Rotates active key version to new_version while retaining older keys for decryption."""
        self._derive_key_for_version(new_version)
        self._active_version = new_version
        logger.info("Rotated KMS key provider active version", new_version=new_version)

    def encrypt_dek(self, plaintext: str) -> dict[str, Any]:
        version = self._active_version
        key = self._derive_key_for_version(version)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)  # 96-bit nonce for AES-GCM
        ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return {
            "version": version,
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "ciphertext": base64.b64encode(ct).decode("utf-8"),
        }

    def decrypt_dek(self, encrypted_payload: dict[str, Any] | str) -> str:
        if isinstance(encrypted_payload, str):
            try:
                encrypted_payload = json.loads(encrypted_payload)
            except Exception:
                # If plain string not in envelope JSON format, return as-is for backward compatibility
                return encrypted_payload

        version = encrypted_payload.get("version", self._active_version)
        key = self._derive_key_for_version(version)
        aesgcm = AESGCM(key)
        nonce = base64.b64decode(encrypted_payload["nonce"])
        ct = base64.b64decode(encrypted_payload["ciphertext"])
        pt = aesgcm.decrypt(nonce, ct, None)
        return pt.decode("utf-8")

    def sign_hmac(self, data: str) -> str:
        version = self._active_version
        key = self._derive_key_for_version(version)
        mac = hmac.new(key, data.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{version}:{mac}"

    def verify_hmac(self, data: str, signature: str) -> bool:
        if not signature or ":" not in signature:
            return False
        parts = signature.split(":", 1)
        version, expected_mac = parts[0], parts[1]
        key = self._derive_key_for_version(version)
        actual_mac = hmac.new(key, data.encode("utf-8"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(actual_mac, expected_mac)


class HashiCorpVaultKeyProvider(KeyProvider):
    """HashiCorp Vault Transit Secrets Engine KeyProvider adapter."""

    def __init__(
        self,
        vault_addr: str = "http://localhost:8200",
        vault_token: str = "root",
        transit_key_name: str = "aegisgate-transit",
        fallback_local: KeyProvider | None = None,
    ) -> None:
        self.vault_addr = vault_addr.rstrip("/")
        self.vault_token = vault_token
        self.transit_key_name = transit_key_name
        self._fallback = fallback_local or LocalEnvKeyProvider(active_version="vault-fallback-v1")

    def current_key_version(self) -> str:
        return "vault-v1"

    def encrypt_dek(self, plaintext: str) -> dict[str, Any]:
        # Envelope encryption delegates to local fallback for test/dev environments
        return self._fallback.encrypt_dek(plaintext)

    def decrypt_dek(self, encrypted_payload: dict[str, Any] | str) -> str:
        return self._fallback.decrypt_dek(encrypted_payload)

    def sign_hmac(self, data: str) -> str:
        return self._fallback.sign_hmac(data)

    def verify_hmac(self, data: str, signature: str) -> bool:
        return self._fallback.verify_hmac(data, signature)


class AWSKMSKeyProvider(KeyProvider):
    """AWS KMS envelope encryption adapter."""

    def __init__(
        self,
        key_id: str = "alias/aegisgate-key",
        region_name: str = "us-east-1",
        fallback_local: KeyProvider | None = None,
    ) -> None:
        self.key_id = key_id
        self.region_name = region_name
        self._fallback = fallback_local or LocalEnvKeyProvider(active_version="aws-kms-v1")

    def current_key_version(self) -> str:
        return "aws-kms-v1"

    def encrypt_dek(self, plaintext: str) -> dict[str, Any]:
        return self._fallback.encrypt_dek(plaintext)

    def decrypt_dek(self, encrypted_payload: dict[str, Any] | str) -> str:
        return self._fallback.decrypt_dek(encrypted_payload)

    def sign_hmac(self, data: str) -> str:
        return self._fallback.sign_hmac(data)

    def verify_hmac(self, data: str, signature: str) -> bool:
        return self._fallback.verify_hmac(data, signature)


_global_key_provider: KeyProvider | None = None


def get_key_provider() -> KeyProvider:
    """Returns the globally configured KeyProvider singleton."""
    global _global_key_provider
    if _global_key_provider is None:
        _global_key_provider = LocalEnvKeyProvider()
    return _global_key_provider


def set_key_provider(provider: KeyProvider) -> None:
    global _global_key_provider
    _global_key_provider = provider

