import hashlib
from collections.abc import Callable

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from core.auth.security import decode_access_token
from core.database import db_context
from core.models.user import ApiKeyRecord

bearer_scheme = HTTPBearer(auto_error=False)


class AuthenticatedActor(BaseModel):
    model_config = ConfigDict(extra="ignore")

    actor_id: str
    username: str
    tenant_id: str
    role: str  # SuperAdmin | TenantAdmin | PolicyAuthor | Approver | Auditor
    auth_type: str = "jwt"  # jwt | api_key


async def get_current_actor(
    auth_header: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    x_api_key: str | None = Header(default=None, alias="X-Aegis-Api-Key"),
) -> AuthenticatedActor:
    """
    Extracts and authenticates caller identity via JWT Bearer token or scoped API key.
    """
    # 1. Check API Key
    if x_api_key:
        key_hash = hashlib.sha256(x_api_key.encode("utf-8")).hexdigest()
        async with db_context() as session:
            stmt = select(ApiKeyRecord).where(ApiKeyRecord.key_hash == key_hash)
            res = await session.execute(stmt)
            key_rec = res.scalar_one_or_none()
            if key_rec:
                return AuthenticatedActor(
                    actor_id=key_rec.id,
                    username=key_rec.name,
                    tenant_id=key_rec.tenant_id,
                    role=key_rec.role,
                    auth_type="api_key",
                )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API Key",
        )

    # 2. Check Bearer Token
    if auth_header and auth_header.credentials:
        token = auth_header.credentials
        try:
            payload = decode_access_token(token)
            user_id = payload.get("sub")
            tenant_id = payload.get("tenant_id", "default")
            role = payload.get("role", "Auditor")
            username = payload.get("username", "user")

            if not user_id:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

            return AuthenticatedActor(
                actor_id=user_id,
                username=username,
                tenant_id=tenant_id,
                role=role,
                auth_type="jwt",
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Could not validate credentials: {e!s}",
            )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Provide Bearer token or X-Aegis-Api-Key header.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_role(*allowed_roles: str) -> Callable:
    """Dependency factory checking that the authenticated caller has one of allowed_roles or SuperAdmin."""
    async def _checker(actor: AuthenticatedActor = Depends(get_current_actor)) -> AuthenticatedActor:
        if actor.role == "SuperAdmin":
            return actor
        if actor.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{actor.role}' is not authorized. Required: {list(allowed_roles)}",
            )
        return actor
    return _checker

