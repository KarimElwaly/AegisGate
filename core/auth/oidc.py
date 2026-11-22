from typing import Any
import jwt
from pydantic import BaseModel, Field

from core.config import get_settings
from core.logger import get_logger

logger = get_logger("core.auth.oidc")


class OidcConfig(BaseModel):
    enabled: bool = False
    issuer: str = ""
    client_id: str = ""
    jwks_uri: str = ""
    role_claim: str = "groups"
    cache_ttl_seconds: int = 3600
    group_role_mapping: dict[str, str] = Field(
        default_factory=lambda: {
            "aegis_admins": "SuperAdmin",
            "aegis_policy_authors": "PolicyAuthor",
            "aegis_auditors": "Auditor",
            "aegis_operators": "Operator",
        }
    )


class OidcService:
    """OIDC JWKS token verification and Identity Provider group-to-role mapping.
    Cryptographically verifies RS256/ES256 signatures against cached JWKS with
    TTL and automatic rotation retry on unknown kid.
    """

    def __init__(self, config: OidcConfig | None = None) -> None:
        if config is not None:
            self.config = config
        else:
            self.config = self._load_config_from_settings()

        self._jwks_client: Any | None = None
        self._init_jwks_client()

    def _load_config_from_settings(self) -> OidcConfig:
        settings = get_settings()
        return OidcConfig(
            enabled=settings.OIDC_ENABLED,
            issuer=settings.OIDC_ISSUER,
            client_id=settings.OIDC_CLIENT_ID,
            jwks_uri=settings.OIDC_JWKS_URI,
            role_claim=settings.OIDC_ROLE_CLAIM,
        )

    def _init_jwks_client(self) -> None:
        if self.config.enabled and self.config.jwks_uri:
            try:
                self._jwks_client = jwt.PyJWKClient(
                    self.config.jwks_uri,
                    cache_keys=True,
                    max_cached_keys=16,
                    cache_jwk_set=True,
                    lifespan=self.config.cache_ttl_seconds,
                )
            except Exception as e:
                logger.warning("failed_to_initialize_jwks_client", error=str(e))

    def verify_oidc_token(
        self,
        token: str,
        jwks_client: Any | None = None,
        key: Any | None = None,
    ) -> dict[str, Any]:
        """Validates an OIDC token cryptographically (RS256/ES256) and maps user groups to AegisGate roles."""
        if not self.config.enabled:
            raise ValueError("OIDC authentication is not enabled")

        try:
            client = jwks_client or self._jwks_client

            if key:
                signing_key_val = key
            elif client:
                try:
                    signing_key = client.get_signing_key_from_jwt(token)
                    signing_key_val = signing_key.key
                except Exception as jwk_err:
                    # Key rotation retry: force refresh JWKS cache on unknown kid
                    logger.info("JWKS key miss, refreshing cache for rotated key", error=str(jwk_err))
                    try:
                        client.get_jwk_set(refresh=True)
                        signing_key = client.get_signing_key_from_jwt(token)
                        signing_key_val = signing_key.key
                    except Exception as retry_err:
                        raise ValueError(f"OIDC signing key not found after refresh: {retry_err}")
            else:
                raise ValueError("OIDC JWKS verification is not configured")

            decode_kwargs: dict[str, Any] = {
                "algorithms": ["RS256", "ES256"],
                "options": {
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                },
            }
            if self.config.issuer:
                decode_kwargs["issuer"] = self.config.issuer
            if self.config.client_id:
                decode_kwargs["audience"] = self.config.client_id

            claims = jwt.decode(token, signing_key_val, **decode_kwargs)
            return self._attach_mapped_role(claims)
        except Exception as e:
            logger.warning("oidc_verification_failed", error=str(e))
            raise ValueError(f"OIDC token verification failed: {e!s}")

    def _attach_mapped_role(self, claims: dict[str, Any]) -> dict[str, Any]:
        role_claim_val = claims.get(self.config.role_claim, [])
        if isinstance(role_claim_val, str):
            groups = [role_claim_val]
        elif isinstance(role_claim_val, list):
            groups = [str(g) for g in role_claim_val]
        else:
            groups = []

        mapped_role = self.map_groups_to_role(groups)
        claims["role"] = mapped_role
        return claims

    def map_groups_to_role(self, groups: list[str]) -> str:
        """Resolves highest privilege AegisGate role from user IdP group memberships."""
        role_precedence = ["SuperAdmin", "TenantAdmin", "PolicyAuthor", "Operator", "Auditor", "Viewer"]
        matched_roles = []

        for grp in groups:
            if grp in self.config.group_role_mapping:
                matched_roles.append(self.config.group_role_mapping[grp])

        for r in role_precedence:
            if r in matched_roles:
                return r

        return "Viewer"


default_oidc_service = OidcService()


def get_oidc_service() -> OidcService:
    return default_oidc_service
