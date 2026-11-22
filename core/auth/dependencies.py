import hashlib
from collections.abc import Callable

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from core.auth.oidc import get_oidc_service
from core.auth.security import decode_access_token
from core.config import get_settings
from core.database import db_context
from core.models.user import ApiKeyRecord
from core.tenancy.context import (
    current_tenant_id,
    current_virtual_key_id,
    current_workspace_id,
)
from core.tenancy.service import get_tenancy_service

bearer_scheme = HTTPBearer(auto_error=False)


class AuthenticatedActor(BaseModel):
    model_config = ConfigDict(extra="ignore")

    actor_id: str
    username: str
    tenant_id: str
    workspace_id: str = "default"
    role: str  # SuperAdmin | TenantAdmin | PolicyAuthor | Approver | Auditor
    auth_type: str = "jwt"  # jwt | api_key | virtual_key
    virtual_key_id: str | None = None
    default_policy_pack_id: str | None = None


async def get_current_actor(
    auth_header: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    x_api_key: str | None = Header(default=None, alias="X-Aegis-Api-Key"),
    x_tenant_id: str | None = Header(default=None, alias="X-Aegis-Tenant-Id"),
    x_workspace_id: str | None = Header(default=None, alias="X-Aegis-Workspace-Id"),
) -> AuthenticatedActor:
    """Extracts and authenticates caller identity via Virtual Key, legacy API Key, or JWT Bearer."""
    raw_key = x_api_key
    if not raw_key and auth_header and auth_header.credentials:
        cred = auth_header.credentials
        if cred.startswith("ag_live_") or cred.startswith("aegis_live_"):
            raw_key = cred

    # 1. Virtual API Key (ag_live_...)
    if raw_key and raw_key.startswith("ag_live_"):
        tenancy_svc = get_tenancy_service()
        async with db_context() as session:
            vkey = await tenancy_svc.validate_virtual_key(session, raw_key)
            if vkey:
                current_tenant_id.set(vkey.tenant_id)
                current_workspace_id.set(vkey.workspace_id)
                current_virtual_key_id.set(vkey.id)
                return AuthenticatedActor(
                    actor_id=vkey.id,
                    username=vkey.name,
                    tenant_id=vkey.tenant_id,
                    workspace_id=vkey.workspace_id,
                    role=vkey.role,
                    auth_type="virtual_key",
                    virtual_key_id=vkey.id,
                    default_policy_pack_id=vkey.default_policy_pack_id,
                )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked Virtual API Key",
        )

    # 2. Legacy API Key (aegis_live_...)
    if raw_key:
        key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        async with db_context() as session:
            stmt = select(ApiKeyRecord).where(ApiKeyRecord.key_hash == key_hash)
            res = await session.execute(stmt)
            key_rec = res.scalar_one_or_none()
            if key_rec:
                tid = key_rec.tenant_id or x_tenant_id or "default"
                wid = x_workspace_id or "default"
                current_tenant_id.set(tid)
                current_workspace_id.set(wid)
                return AuthenticatedActor(
                    actor_id=key_rec.id,
                    username=key_rec.name,
                    tenant_id=tid,
                    workspace_id=wid,
                    role=key_rec.role,
                    auth_type="api_key",
                )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API Key",
        )

    # 3. Bearer Token (JWT)
    if auth_header and auth_header.credentials:
        token = auth_header.credentials
        try:
            payload = decode_access_token(token)
            user_id = payload.get("sub")
            role = payload.get("role", "Auditor")
            claim_tid = payload.get("tenant_id")
            if role == "SuperAdmin" and x_tenant_id:
                tid = x_tenant_id
            else:
                tid = claim_tid or "default"
            wid = payload.get("workspace_id") or x_workspace_id or "default"
            username = payload.get("username", "user")

            if not user_id:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

            current_tenant_id.set(tid)
            current_workspace_id.set(wid)
            return AuthenticatedActor(
                actor_id=user_id,
                username=username,
                tenant_id=tid,
                workspace_id=wid,
                role=role,
                auth_type="jwt",
            )
        except Exception as local_err:
            oidc_svc = get_oidc_service()
            if oidc_svc.config.enabled:
                try:
                    claims = oidc_svc.verify_oidc_token(token)
                    user_id = claims.get("sub") or claims.get("email") or "oidc_user"
                    username = claims.get("preferred_username") or claims.get("email") or claims.get("name") or "oidc_user"
                    role = claims.get("role", "Auditor")
                    claim_tid = claims.get("tenant_id")
                    if role == "SuperAdmin" and x_tenant_id:
                        tid = x_tenant_id
                    else:
                        tid = claim_tid or "default"
                    wid = x_workspace_id or "default"

                    current_tenant_id.set(tid)
                    current_workspace_id.set(wid)
                    return AuthenticatedActor(
                        actor_id=user_id,
                        username=username,
                        tenant_id=tid,
                        workspace_id=wid,
                        role=role,
                        auth_type="oidc",
                    )
                except Exception as oidc_err:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail=f"OIDC validation failed: {oidc_err!s}",
                    )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Could not validate credentials: {local_err!s}",
            )

    # 4. Optional header fallback in dev/test if no credentials provided
    if x_tenant_id:
        current_tenant_id.set(x_tenant_id)
        current_workspace_id.set(x_workspace_id or "default")

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Provide Bearer token or X-Aegis-Api-Key header.",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_pdp_actor(
    auth_header: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    x_api_key: str | None = Header(default=None, alias="X-Aegis-Api-Key"),
    x_tenant_id: str | None = Header(default=None, alias="X-Aegis-Tenant-Id"),
    x_workspace_id: str | None = Header(default=None, alias="X-Aegis-Workspace-Id"),
) -> AuthenticatedActor:
    """PDP actor dependency: validates credentials strictly when provided, allows anonymous fallback for open PDP endpoints."""
    raw_key = x_api_key
    if not raw_key and auth_header and auth_header.credentials:
        cred = auth_header.credentials
        if cred.startswith("ag_live_") or cred.startswith("aegis_live_"):
            raw_key = cred

    # 1. Virtual API Key
    if raw_key and raw_key.startswith("ag_live_"):
        tenancy_svc = get_tenancy_service()
        async with db_context() as session:
            vkey = await tenancy_svc.validate_virtual_key(session, raw_key)
            if vkey:
                current_tenant_id.set(vkey.tenant_id)
                current_workspace_id.set(vkey.workspace_id)
                current_virtual_key_id.set(vkey.id)
                return AuthenticatedActor(
                    actor_id=vkey.id,
                    username=vkey.name,
                    tenant_id=vkey.tenant_id,
                    workspace_id=vkey.workspace_id,
                    role=vkey.role,
                    auth_type="virtual_key",
                    virtual_key_id=vkey.id,
                    default_policy_pack_id=vkey.default_policy_pack_id,
                )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked Virtual API Key",
        )

    # 2. Legacy API Key
    if raw_key:
        key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        async with db_context() as session:
            stmt = select(ApiKeyRecord).where(ApiKeyRecord.key_hash == key_hash)
            res = await session.execute(stmt)
            key_rec = res.scalar_one_or_none()
            if key_rec:
                tid = key_rec.tenant_id or x_tenant_id or "default"
                wid = x_workspace_id or "default"
                current_tenant_id.set(tid)
                current_workspace_id.set(wid)
                return AuthenticatedActor(
                    actor_id=key_rec.id,
                    username=key_rec.name,
                    tenant_id=tid,
                    workspace_id=wid,
                    role=key_rec.role,
                    auth_type="api_key",
                )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API Key",
        )

    # 3. Bearer Token
    if auth_header and auth_header.credentials:
        token = auth_header.credentials
        try:
            payload = decode_access_token(token)
            user_id = payload.get("sub")
            role = payload.get("role", "Auditor")
            claim_tid = payload.get("tenant_id")
            if role == "SuperAdmin" and x_tenant_id:
                tid = x_tenant_id
            else:
                tid = claim_tid or "default"
            wid = payload.get("workspace_id") or x_workspace_id or "default"
            username = payload.get("username", "user")

            if not user_id:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

            current_tenant_id.set(tid)
            current_workspace_id.set(wid)
            return AuthenticatedActor(
                actor_id=user_id,
                username=username,
                tenant_id=tid,
                workspace_id=wid,
                role=role,
                auth_type="jwt",
            )
        except Exception as local_err:
            oidc_svc = get_oidc_service()
            if oidc_svc.config.enabled:
                try:
                    claims = oidc_svc.verify_oidc_token(token)
                    user_id = claims.get("sub") or claims.get("email") or "oidc_user"
                    username = claims.get("preferred_username") or claims.get("email") or claims.get("name") or "oidc_user"
                    role = claims.get("role", "Auditor")
                    claim_tid = claims.get("tenant_id")
                    if role == "SuperAdmin" and x_tenant_id:
                        tid = x_tenant_id
                    else:
                        tid = claim_tid or "default"
                    wid = x_workspace_id or "default"

                    current_tenant_id.set(tid)
                    current_workspace_id.set(wid)
                    return AuthenticatedActor(
                        actor_id=user_id,
                        username=username,
                        tenant_id=tid,
                        workspace_id=wid,
                        role=role,
                        auth_type="oidc",
                    )
                except Exception as oidc_err:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail=f"OIDC validation failed: {oidc_err!s}",
                    )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Could not validate credentials: {local_err!s}",
            )

    # 4. Anonymous fallback for backward compatibility
    tid = x_tenant_id or "default"
    wid = x_workspace_id or "default"
    current_tenant_id.set(tid)
    current_workspace_id.set(wid)
    settings = get_settings()
    default_role = "SuperAdmin" if settings.AEGIS_ENV == "test" else "Anonymous"
    return AuthenticatedActor(
        actor_id="anonymous",
        username="anonymous",
        tenant_id=tid,
        workspace_id=wid,
        role=default_role,
        auth_type="anonymous",
    )


async def authenticate_credentials(
    raw_key_or_token: str | None,
    x_tenant_id: str | None = None,
    x_workspace_id: str | None = None,
) -> AuthenticatedActor:
    """Helper to authenticate credentials extracted from non-standard channels (e.g. WebSocket query params/headers)."""
    auth_header = None
    x_api_key = None
    if raw_key_or_token:
        token_str = raw_key_or_token.strip()
        if token_str.startswith("Bearer "):
            auth_header = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token_str[7:].strip())
        elif token_str.startswith("ag_live_") or token_str.startswith("aegis_live_"):
            x_api_key = token_str
        else:
            auth_header = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token_str)
    return await get_pdp_actor(
        auth_header=auth_header,
        x_api_key=x_api_key,
        x_tenant_id=x_tenant_id,
        x_workspace_id=x_workspace_id,
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
