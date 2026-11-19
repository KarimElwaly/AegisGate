import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from core.auth.dependencies import AuthenticatedActor, get_current_actor, require_role
from core.auth.security import create_access_token, generate_api_key, hash_password, verify_password
from core.database import db_context
from core.models.user import ApiKeyRecord, UserRecord

router = APIRouter(prefix="/v1/auth", tags=["Operator Authentication & RBAC"])


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    username: str
    password: str
    tenant_id: str = "default"


class RegisterUserRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    username: str
    password: str
    email: str
    tenant_id: str = "default"
    role: str = "Auditor"  # SuperAdmin | TenantAdmin | PolicyAuthor | Approver | Auditor


class CreateApiKeyRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str = Field(..., description="Friendly label for the API key")
    tenant_id: str = "default"
    role: str = "PolicyAuthor"


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict[str, Any]


class ApiKeyCreatedResponse(BaseModel):
    key_id: str
    name: str
    tenant_id: str
    role: str
    raw_api_key: str = Field(..., description="Scoped API key (shown once)")
    key_prefix: str


@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest) -> TokenResponse:
    """Authenticates operator credentials and returns a signed JWT access token."""
    async with db_context() as session:
        stmt = (
            select(UserRecord)
            .where(UserRecord.username == req.username)
            .where(UserRecord.tenant_id == req.tenant_id)
        )
        res = await session.execute(stmt)
        user = res.scalar_one_or_none()

        if not user or not verify_password(req.password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password for this tenant",
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is deactivated",
            )

        token = create_access_token(
            data={
                "sub": user.id,
                "username": user.username,
                "email": user.email,
                "tenant_id": user.tenant_id,
                "role": user.role,
            }
        )

        return TokenResponse(
            access_token=token,
            user={
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "tenant_id": user.tenant_id,
                "role": user.role,
            },
        )


@router.get("/me", response_model=AuthenticatedActor)
async def get_me(current_actor: AuthenticatedActor = Depends(get_current_actor)) -> AuthenticatedActor:
    """Returns the authenticated operator identity and RBAC role."""
    return current_actor


@router.post("/register")
async def register_user(req: RegisterUserRequest) -> dict[str, Any]:
    """Registers a new user in a tenant."""
    async with db_context() as session:
        # Check duplicate
        stmt = (
            select(UserRecord)
            .where(UserRecord.username == req.username)
            .where(UserRecord.tenant_id == req.tenant_id)
        )
        res = await session.execute(stmt)
        if res.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Username '{req.username}' already exists in tenant '{req.tenant_id}'",
            )

        user_id = str(uuid.uuid4())
        hashed_pwd = hash_password(req.password)
        new_user = UserRecord(
            id=user_id,
            tenant_id=req.tenant_id,
            username=req.username,
            email=req.email,
            hashed_password=hashed_pwd,
            role=req.role,
            is_active=True,
        )
        session.add(new_user)
        await session.commit()

        return {
            "id": user_id,
            "username": new_user.username,
            "tenant_id": new_user.tenant_id,
            "role": new_user.role,
            "email": new_user.email,
        }


@router.post("/api-keys", response_model=ApiKeyCreatedResponse)
async def create_api_key(
    req: CreateApiKeyRequest,
    actor: AuthenticatedActor = Depends(require_role("SuperAdmin", "TenantAdmin")),
) -> ApiKeyCreatedResponse:
    """Generates a scoped API key for agent or gateway authentication."""
    raw_key, prefix, key_hash = generate_api_key(tenant_id=req.tenant_id, role=req.role)
    key_id = str(uuid.uuid4())

    async with db_context() as session:
        key_record = ApiKeyRecord(
            id=key_id,
            tenant_id=req.tenant_id,
            name=req.name,
            key_prefix=prefix,
            key_hash=key_hash,
            role=req.role,
        )
        session.add(key_record)
        await session.commit()

    return ApiKeyCreatedResponse(
        key_id=key_id,
        name=req.name,
        tenant_id=req.tenant_id,
        role=req.role,
        raw_api_key=raw_key,
        key_prefix=prefix,
    )


@router.get("/api-keys")
async def list_api_keys(
    tenant_id: str = "default",
    actor: AuthenticatedActor = Depends(get_current_actor),
) -> list[dict[str, Any]]:
    """Lists API keys for a tenant (without exposing secrets)."""
    async with db_context() as session:
        stmt = select(ApiKeyRecord).where(ApiKeyRecord.tenant_id == tenant_id)
        res = await session.execute(stmt)
        keys = res.scalars().all()
        return [
            {
                "id": k.id,
                "name": k.name,
                "tenant_id": k.tenant_id,
                "role": k.role,
                "key_prefix": k.key_prefix,
                "created_at": k.created_at.isoformat() if k.created_at else "",
            }
            for k in keys
        ]
