from typing import Any
import jwt
from pydantic import BaseModel, Field

from core.logger import get_logger

logger = get_logger("core.auth.oidc")


class OidcConfig(BaseModel):
    enabled: bool = False
    issuer: str = ""
    client_id: str = ""
    jwks_uri: str = ""
    group_role_mapping: dict[str, str] = Field(
        default_factory=lambda: {
            "aegis_admins": "SuperAdmin",
            "aegis_policy_authors": "PolicyAuthor",
            "aegis_auditors": "Auditor",
            "aegis_operators": "Operator",
        }
    )


class OidcService:
    """OIDC JWKS token verification and Identity Provider group-to-role mapping."""

    def __init__(self, config: OidcConfig | None = None) -> None:
        self.config = config or OidcConfig()

    def verify_oidc_token(self, token: str, jwks_client: Any | None = None) -> dict[str, Any]:
        """Validates an OIDC token and maps user groups to AegisGate roles."""
        if not self.config.enabled:
            raise ValueError("OIDC authentication is not enabled")

        try:
            # If jwks_client provided, decode using signing key
            if jwks_client:
                signing_key = jwks_client.get_signing_key_from_jwt(token)
                claims = jwt.decode(
                    token,
                    signing_key.key,
                    algorithms=["RS256"],
                    issuer=self.config.issuer,
                    audience=self.config.client_id,
                )
            else:
                # Unverified claims extraction for testing / simulation
                claims = jwt.decode(token, options={"verify_signature": False})

            return claims
        except Exception as e:
            logger.warning("oidc_verification_failed", error=str(e))
            raise ValueError(f"OIDC token verification failed: {e!s}")

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

