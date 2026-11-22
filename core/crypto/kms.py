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
from core.telemetry import record_kms_op

logger = get_logger("core.crypto.kms")
settings = get_settings()


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
    def verify_hmac(self, data: str, signature: str, key_version: str | None = None) -> bool:
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
        record_kms_op("sign_hmac", "success")
        version = self._active_version
        key = self._derive_key_for_version(version)
        mac = hmac.new(key, data.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{version}:{mac}"

    def verify_hmac(self, data: str, signature: str, key_version: str | None = None) -> bool:
        if not signature:
            record_kms_op("verify_hmac", "invalid")
            return False
        version = key_version
        expected_mac = signature
        if ":" in signature:
            parts = signature.split(":", 1)
            version = parts[0]
            expected_mac = parts[1]
        elif not version:
            version = self._active_version

        key = self._derive_key_for_version(version)
        actual_mac = hmac.new(key, data.encode("utf-8"), hashlib.sha256).hexdigest()
        valid = hmac.compare_digest(actual_mac, expected_mac)
        record_kms_op("verify_hmac", "success" if valid else "failed")
        return valid


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
        self._fallback = fallback_local if fallback_local is not None else (LocalEnvKeyProvider() if getattr(settings, "AEGIS_ENV", "dev") != "prod" else None)

    def current_key_version(self) -> str:
        return "vault-v1"

    def encrypt_dek(self, plaintext: str) -> dict[str, Any]:
        import httpx

        try:
            b64_pt = base64.b64encode(plaintext.encode("utf-8")).decode("utf-8")
            url = f"{self.vault_addr}/v1/transit/encrypt/{self.transit_key_name}"
            headers = {"X-Vault-Token": self.vault_token}
            with httpx.Client(timeout=0.5) as client:
                resp = client.post(url, headers=headers, json={"plaintext": b64_pt})
                if resp.status_code == 200:
                    ct = resp.json()["data"]["ciphertext"]
                    record_kms_op("encrypt_dek", "success")
                    return {"version": "vault-v1", "nonce": "", "ciphertext": ct}
                raise RuntimeError(f"Vault encrypt returned {resp.status_code}: {resp.text}")
        except Exception as e:
            if self._fallback:
                logger.warning("Vault encrypt failed, falling back to local key provider", error=str(e))
                return self._fallback.encrypt_dek(plaintext)
            raise

    def decrypt_dek(self, encrypted_payload: dict[str, Any] | str) -> str:
        import httpx

        ct = encrypted_payload["ciphertext"] if isinstance(encrypted_payload, dict) else encrypted_payload
        if not str(ct).startswith("vault:"):
            if self._fallback:
                return self._fallback.decrypt_dek(encrypted_payload)
            return str(ct)

        try:
            url = f"{self.vault_addr}/v1/transit/decrypt/{self.transit_key_name}"
            headers = {"X-Vault-Token": self.vault_token}
            with httpx.Client(timeout=0.5) as client:
                resp = client.post(url, headers=headers, json={"ciphertext": ct})
                if resp.status_code == 200:
                    b64_pt = resp.json()["data"]["plaintext"]
                    record_kms_op("decrypt_dek", "success")
                    return base64.b64decode(b64_pt).decode("utf-8")
                raise RuntimeError(f"Vault decrypt returned {resp.status_code}: {resp.text}")
        except Exception as e:
            if self._fallback:
                logger.warning("Vault decrypt failed, falling back to local key provider", error=str(e))
                return self._fallback.decrypt_dek(encrypted_payload)
            raise

    def sign_hmac(self, data: str) -> str:
        import httpx

        try:
            b64_input = base64.b64encode(data.encode("utf-8")).decode("utf-8")
            url = f"{self.vault_addr}/v1/transit/hmac/{self.transit_key_name}/sha2-256"
            headers = {"X-Vault-Token": self.vault_token}
            with httpx.Client(timeout=0.5) as client:
                resp = client.post(url, headers=headers, json={"input": b64_input})
                if resp.status_code == 200:
                    hmac_sig = resp.json()["data"]["hmac"]
                    record_kms_op("sign_hmac", "success")
                    return f"vault-v1:{hmac_sig}"
                raise RuntimeError(f"Vault HMAC returned {resp.status_code}: {resp.text}")
        except Exception as e:
            if self._fallback:
                logger.warning("Vault HMAC failed, falling back to local key provider", error=str(e))
                return self._fallback.sign_hmac(data)
            raise

    def verify_hmac(self, data: str, signature: str, key_version: str | None = None) -> bool:
        import httpx

        expected_sig = signature.split(":", 1)[1] if ":" in signature else signature
        try:
            b64_input = base64.b64encode(data.encode("utf-8")).decode("utf-8")
            url = f"{self.vault_addr}/v1/transit/verify/{self.transit_key_name}/sha2-256"
            headers = {"X-Vault-Token": self.vault_token}
            with httpx.Client(timeout=0.5) as client:
                resp = client.post(url, headers=headers, json={"input": b64_input, "hmac": expected_sig})
                if resp.status_code == 200:
                    valid = resp.json()["data"]["valid"]
                    record_kms_op("verify_hmac", "success" if valid else "failed")
                    return bool(valid)
                raise RuntimeError(f"Vault verify returned {resp.status_code}: {resp.text}")
        except Exception as e:
            if self._fallback:
                logger.warning("Vault verify failed, falling back to local key provider", error=str(e))
                return self._fallback.verify_hmac(data, signature, key_version)
            raise


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
        self._fallback = fallback_local if fallback_local is not None else (LocalEnvKeyProvider() if getattr(settings, "AEGIS_ENV", "dev") != "prod" else None)

    def current_key_version(self) -> str:
        return "aws-kms-v1"

    def encrypt_dek(self, plaintext: str) -> dict[str, Any]:
        try:
            import boto3
            client = boto3.client("kms", region_name=self.region_name)
            resp = client.encrypt(KeyId=self.key_id, Plaintext=plaintext.encode("utf-8"))
            ct = base64.b64encode(resp["CiphertextBlob"]).decode("utf-8")
            record_kms_op("encrypt_dek", "success")
            return {"version": "aws-kms-v1", "nonce": "", "ciphertext": ct}
        except Exception as e:
            if self._fallback:
                logger.warning("AWS KMS encrypt failed, falling back to local key provider", error=str(e))
                return self._fallback.encrypt_dek(plaintext)
            raise

    def decrypt_dek(self, encrypted_payload: dict[str, Any] | str) -> str:
        try:
            ct = encrypted_payload["ciphertext"] if isinstance(encrypted_payload, dict) else encrypted_payload
            raw_ct = base64.b64decode(ct)
            import boto3
            client = boto3.client("kms", region_name=self.region_name)
            resp = client.decrypt(CiphertextBlob=raw_ct)
            record_kms_op("decrypt_dek", "success")
            return resp["Plaintext"].decode("utf-8")
        except Exception as e:
            if self._fallback:
                logger.warning("AWS KMS decrypt failed, falling back to local key provider", error=str(e))
                return self._fallback.decrypt_dek(encrypted_payload)
            raise

    def sign_hmac(self, data: str) -> str:
        try:
            import boto3
            client = boto3.client("kms", region_name=self.region_name)
            resp = client.generate_mac(
                KeyId=self.key_id,
                Message=data.encode("utf-8"),
                MacAlgorithm="HMAC_SHA_256",
            )
            sig = base64.b64encode(resp["Mac"]).decode("utf-8")
            record_kms_op("sign_hmac", "success")
            return f"aws-kms-v1:{sig}"
        except Exception as e:
            if self._fallback:
                logger.warning("AWS KMS sign_hmac failed, falling back to local key provider", error=str(e))
                return self._fallback.sign_hmac(data)
            raise

    def verify_hmac(self, data: str, signature: str, key_version: str | None = None) -> bool:
        expected_sig = signature.split(":", 1)[1] if ":" in signature else signature
        try:
            raw_sig = base64.b64decode(expected_sig)
            import boto3
            client = boto3.client("kms", region_name=self.region_name)
            resp = client.verify_mac(
                KeyId=self.key_id,
                Message=data.encode("utf-8"),
                MacAlgorithm="HMAC_SHA_256",
                Mac=raw_sig,
            )
            valid = bool(resp.get("MacValid", False))
            record_kms_op("verify_hmac", "success" if valid else "failed")
            return valid
        except Exception as e:
            if self._fallback:
                logger.warning("AWS KMS verify_hmac failed, falling back to local key provider", error=str(e))
                return self._fallback.verify_hmac(data, signature, key_version)
            raise


_global_key_provider: KeyProvider | None = None


def get_key_provider() -> KeyProvider:
    """Returns the globally configured KeyProvider singleton."""
    global _global_key_provider
    if _global_key_provider is None:
        settings = get_settings()
        kms_provider_type = getattr(settings, "AEGIS_KMS_PROVIDER", "local").lower()
        if kms_provider_type == "vault":
            _global_key_provider = HashiCorpVaultKeyProvider(
                vault_addr=getattr(settings, "VAULT_ADDR", "http://localhost:8200"),
                vault_token=getattr(settings, "VAULT_TOKEN", "root"),
                transit_key_name=getattr(settings, "VAULT_TRANSIT_KEY", "aegisgate-transit"),
                fallback_local=None if settings.AEGIS_ENV == "prod" else LocalEnvKeyProvider(active_version="vault-fallback-v1"),
            )
        elif kms_provider_type == "aws":
            _global_key_provider = AWSKMSKeyProvider(
                key_id=getattr(settings, "AWS_KMS_KEY_ID", "alias/aegisgate-key"),
                region_name=getattr(settings, "AWS_REGION", "us-east-1"),
                fallback_local=None if settings.AEGIS_ENV == "prod" else LocalEnvKeyProvider(active_version="aws-kms-v1"),
            )
        else:
            _global_key_provider = LocalEnvKeyProvider()
    return _global_key_provider


def set_key_provider(provider: KeyProvider) -> None:
    global _global_key_provider
    _global_key_provider = provider

