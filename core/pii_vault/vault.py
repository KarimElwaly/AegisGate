import hashlib
import hmac
import json
import re

from core.config import get_settings
from core.crypto.kms import get_key_provider
from core.logger import get_logger
from core.redis_client import get_redis_client

logger = get_logger("core.pii_vault")


class PiiVault:
    """Ephemeral Reversible Tokenization & Re-hydration Vault.
    Stores bidirectional token <-> plaintext mappings in Redis (or memory) with session TTL.
    """

    TOKEN_PATTERN = re.compile(r"<AEGIS_([A-Z0-9_]+)>")

    def __init__(self, ttl_seconds: int | None = None) -> None:
        self.ttl = ttl_seconds or get_settings().PII_VAULT_TTL_SECONDS
        self._local_forward: dict[str, dict[str, str]] = {}
        self._local_reverse: dict[str, dict[str, str]] = {}
        self._local_counts: dict[str, dict[str, int]] = {}

    def _get_session_key(self, tenant_id: str, session_id: str) -> str:
        prefix = get_settings().REDIS_KEY_PREFIX
        return f"{prefix}vault:{tenant_id}:{session_id or 'global'}"

    def _get_forward_digest(self, original_value: str) -> str:
        key = get_settings().AEGIS_SECRET_KEY.encode("utf-8")
        return hmac.new(key, original_value.encode("utf-8"), hashlib.sha256).hexdigest()

    async def tokenize(
        self,
        tenant_id: str,
        session_id: str,
        entity_type: str,
        original_value: str,
    ) -> str:
        """Replace a sensitive value with an ephemeral synthetic token e.g. <AEGIS_IP_1>."""
        if not original_value:
            return original_value

        entity_type = entity_type.upper().replace(" ", "_")
        session_key = self._get_session_key(tenant_id, session_id)
        fwd_digest = self._get_forward_digest(original_value)

        try:
            redis = await get_redis_client()
            forward_key = f"{session_key}:fwd:{fwd_digest}"
            existing_token = await redis.get(forward_key)
            if existing_token:
                return str(existing_token)

            counter_key = f"{session_key}:cnt:{entity_type}"
            count = await redis.incr(counter_key)
            await redis.expire(counter_key, self.ttl)

            token = f"<AEGIS_{entity_type}_{count}>"
            reverse_key = f"{session_key}:rev:{token}"

            # Encrypt original value at rest using KMS KeyProvider
            encrypted_val = json.dumps(get_key_provider().encrypt_dek(original_value))

            pipe = redis.pipeline()
            pipe.setex(forward_key, self.ttl, token)
            pipe.setex(reverse_key, self.ttl, encrypted_val)
            # Store in session token index set
            pipe.sadd(f"{session_key}:tokens", token)
            pipe.expire(f"{session_key}:tokens", self.ttl)
            await pipe.execute()

            return token
        except Exception as e:
            logger.warning("Redis vault error, falling back to local memory", error=str(e))
            sess = f"{tenant_id}:{session_id or 'global'}"
            if sess not in self._local_forward:
                self._local_forward[sess] = {}
                self._local_reverse[sess] = {}
                self._local_counts[sess] = {}

            if fwd_digest in self._local_forward[sess]:
                return self._local_forward[sess][fwd_digest]

            cnt = self._local_counts[sess].get(entity_type, 0) + 1
            self._local_counts[sess][entity_type] = cnt
            token = f"<AEGIS_{entity_type}_{cnt}>"
            self._local_forward[sess][fwd_digest] = token
            # Encrypt in memory as well
            encrypted_val = json.dumps(get_key_provider().encrypt_dek(original_value))
            self._local_reverse[sess][token] = encrypted_val
            return token

    async def rehydrate(
        self,
        tenant_id: str,
        session_id: str,
        text: str,
    ) -> str:
        """Replace synthetic tokens in text back into their original sensitive values."""
        if not text or "<AEGIS_" not in text:
            return text

        tokens_in_text = self.TOKEN_PATTERN.findall(text)
        if not tokens_in_text:
            return text

        session_key = self._get_session_key(tenant_id, session_id)
        result = text

        try:
            redis = await get_redis_client()
            key_provider = get_key_provider()
            for token_type in set(tokens_in_text):
                token = f"<AEGIS_{token_type}>"
                reverse_key = f"{session_key}:rev:{token}"
                orig_encrypted = await redis.get(reverse_key)
                if orig_encrypted:
                    orig = key_provider.decrypt_dek(str(orig_encrypted))
                    result = result.replace(token, str(orig))
            return result
        except Exception as e:
            logger.warning("Redis rehydration error, falling back to memory", error=str(e))
            sess = f"{tenant_id}:{session_id or 'global'}"
            rev_map = self._local_reverse.get(sess, {})
            key_provider = get_key_provider()
            for token, orig_encrypted in rev_map.items():
                orig = key_provider.decrypt_dek(orig_encrypted)
                result = result.replace(token, orig)
            return result

    async def detokenize(
        self,
        tenant_id: str,
        session_id: str,
        token: str,
    ) -> str:
        """Alias for rehydrate to restore original value from token."""
        return await self.rehydrate(tenant_id, session_id, token)

    async def get_session_mappings(
        self,
        tenant_id: str,
        session_id: str,
    ) -> dict[str, str]:
        """Return dict of token -> original_value for the session."""
        session_key = self._get_session_key(tenant_id, session_id)
        key_provider = get_key_provider()
        try:
            redis = await get_redis_client()
            tokens = await redis.smembers(f"{session_key}:tokens")
            mappings = {}
            for token in tokens:
                orig_encrypted = await redis.get(f"{session_key}:rev:{token}")
                if orig_encrypted:
                    mappings[token] = key_provider.decrypt_dek(str(orig_encrypted))
            return mappings
        except Exception:
            sess = f"{tenant_id}:{session_id or 'global'}"
            return {
                tok: key_provider.decrypt_dek(val)
                for tok, val in self._local_reverse.get(sess, {}).items()
            }


default_pii_vault = PiiVault()


def get_pii_vault() -> PiiVault:
    return default_pii_vault

