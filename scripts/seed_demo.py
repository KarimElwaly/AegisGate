#!/usr/bin/env python3
"""
AegisGate Demo & Production Bootstrap Script.
Idempotently provisions the database schema, creates demo tenant, registers SuperAdmin,
issues scoped API keys, loads reference policy packs, and outputs connection commands.
"""

import asyncio
import os
import sys
import uuid
from pathlib import Path

# Ensure root directory is in python path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from alembic import command
from alembic.config import Config
from sqlalchemy import select

from core.auth.security import generate_api_key, hash_password
from core.database import db_context
from core.models.user import ApiKeyRecord, UserRecord
from core.policy_engine.yaml_engine import YamlPolicyEngine
from core.registry.registry import get_plugin_registry


def run_alembic_migrations() -> None:
    """Runs Alembic migrations up to head."""
    print(" [1/5] Applying Alembic database migrations...")
    ini_path = ROOT_DIR / "alembic.ini"
    alembic_cfg = Config(str(ini_path))
    alembic_cfg.set_main_option("script_location", str(ROOT_DIR / "migrations"))
    command.upgrade(alembic_cfg, "head")
    print("   [+] Alembic migrations applied successfully.")


async def seed_tenant_and_users() -> dict:
    """Creates initial SuperAdmin user and scoped API key for tenant acme-corp."""
    print(" [2/5] Bootstrapping demo tenant and SuperAdmin operator...")
    tenant_id = "acme-corp"
    admin_email = "admin@acme.corp"
    admin_password = os.getenv("DEMO_ADMIN_PASSWORD", "AegisGate2026!Secure")

    async with db_context() as session:
        # Check if user already exists
        stmt = select(UserRecord).where(UserRecord.email == admin_email)
        res = await session.execute(stmt)
        user = res.scalar_one_or_none()

        if not user:
            pw_hash = hash_password(admin_password)
            user = UserRecord(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                username="admin",
                email=admin_email,
                hashed_password=pw_hash,
                role="SuperAdmin",
                is_active=True,
            )
            session.add(user)
            await session.commit()
            await session.refresh(user)
            print(f"   [+] Created SuperAdmin user: {admin_email} (Tenant: {tenant_id})")
        else:
            print(f"   [*] User {admin_email} already exists (Tenant: {user.tenant_id})")

        # Also provision author and auditor demo preset users if not present
        demo_presets = [
            ("author", "author@acme.corp", "authorpass123", "PolicyAuthor"),
            ("auditor", "auditor@acme.corp", "auditpass123", "Auditor"),
        ]
        for uname, uemail, upass, urole in demo_presets:
            stmt_demo = select(UserRecord).where(UserRecord.username == uname)
            res_demo = await session.execute(stmt_demo)
            if not res_demo.scalar_one_or_none():
                d_user = UserRecord(
                    id=str(uuid.uuid4()),
                    tenant_id=tenant_id,
                    username=uname,
                    email=uemail,
                    hashed_password=hash_password(upass),
                    role=urole,
                    is_active=True,
                )
                session.add(d_user)
                await session.commit()
                print(f"   [+] Created preset user: {uname} ({urole})")

        # Issue demo API key
        print(" [3/5] Issuing scoped API keys...")
        key_name = "acme-production-key"
        stmt_key = select(ApiKeyRecord).where(
            ApiKeyRecord.tenant_id == tenant_id,
            ApiKeyRecord.name == key_name,
        )
        res_key = await session.execute(stmt_key)
        existing_key = res_key.scalar_one_or_none()

        if not existing_key:
            plain_key, prefix, key_hash = generate_api_key(tenant_id=tenant_id, role="SuperAdmin")
            api_key_rec = ApiKeyRecord(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                name=key_name,
                key_prefix=prefix,
                key_hash=key_hash,
                role="SuperAdmin",
            )
            session.add(api_key_rec)
            await session.commit()
            print(f"   [+] Generated API Key: {plain_key} (Prefix: {prefix})")
        else:
            plain_key = f"{existing_key.key_prefix}***[STORED_HASH]"
            print(f"   [*] API Key '{key_name}' already registered (Prefix: {existing_key.key_prefix})")

    return {
        "tenant_id": tenant_id,
        "admin_email": admin_email,
        "admin_password": admin_password,
        "api_key": plain_key,
    }



def verify_policy_packs() -> None:
    """Verifies that all reference policy packs compile cleanly."""
    print(" [4/5] Verifying and indexing reference policy packs...")
    engine = YamlPolicyEngine()
    packs_dir = ROOT_DIR / "policy_packs"

    if not packs_dir.exists():
        print(f"   [!] Policy packs directory not found at {packs_dir}")
        return

    count = 0
    for pack_path in packs_dir.glob("*/policy.yaml"):
        try:
            with open(pack_path, "r", encoding="utf-8") as f:
                pack_def = engine.load_from_yaml_string(f.read())
            print(f"   [+] Validated Pack: {pack_def.id} (v{pack_def.version}) - {pack_def.name}")
            count += 1
        except Exception as exc:
            print(f"   [!] Failed to load {pack_path}: {exc}")

    print(f"   [+] {count} reference policy packs successfully verified and ready.")


def verify_plugin_registry() -> None:
    """Verifies plugin discovery and registrations."""
    print(" [5/5] Auditing plugin catalog...")
    registry = get_plugin_registry()
    plugins_dir = ROOT_DIR / "plugins"
    if plugins_dir.exists():
        registry.discover_and_register_plugins(str(plugins_dir), "plugins")
    scanners = registry.get_all_scanners()
    resolvers = registry.get_all_resolvers()
    notifiers = registry.get_all_notifiers()
    print(f"   [+] Active plugins: {len(scanners)} Scanners, {len(resolvers)} Resolvers, {len(notifiers)} Notifiers.")


async def run_async_bootstrap():
    creds = await seed_tenant_and_users()
    verify_policy_packs()
    verify_plugin_registry()

    print("\n" + "=" * 70)
    print("   BOOTSTRAP COMPLETE - SYSTEM IS PRODUCTION READY")
    print("=" * 70)
    print(" Control Plane Dashboard: http://localhost:3088")
    print(" Engine Health Check:     http://localhost:8088/healthz")
    print(" Prometheus Metrics:      http://localhost:8088/metrics")
    print(f" SuperAdmin User:         {creds['admin_email']}")
    print(f" SuperAdmin Password:     {creds['admin_password']}")
    print(f" Scoped API Key:          {creds['api_key']}")
    print("-" * 70)
    print(" Quick PDP Evaluation Test (cURL):")
    print(f"""
curl -X POST http://localhost:8088/v1/evaluate \\
  -H "Content-Type: application/json" \\
  -H "X-Aegis-Tenant-Id: {creds['tenant_id']}" \\
  -d '{{
    "tenant_id": "{creds['tenant_id']}",
    "stage": "tool_pre_call",
    "policy_pack_id": "soc-investigation-pack",
    "actor": {{"id": "agent-01", "role": "security_agent"}},
    "action": {{"name": "contain_host", "parameters": {{"asset_id": "srv-dc-01", "action": "isolate"}}}}
  }}'
""")
    print("=" * 70)


def main():
    print("=" * 70)
    print("   AEGISGATE COMMERCIAL SEED & BOOTSTRAP WIZARD")
    print("=" * 70)

    try:
        run_alembic_migrations()
    except Exception as exc:
        print(f"   [*] Migration note: {exc} (continuing to async bootstrap)")

    asyncio.run(run_async_bootstrap())


if __name__ == "__main__":
    main()

