from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.bootstrap import bootstrap_system
from core.config import get_settings
from core.database import close_database
from core.logger import configure_logging, get_logger
from core.redis_client import close_redis_client
from gateways.llm_proxy import llm_proxy_router
from gateways.mcp_tool_gateway import tool_gateway_router
from gateways.pdp_api.routes import (
    approvals_router,
    audit_router,
    auth_router,
    evaluate_router,
    health_router,
    kill_switch_router,
    plugins_router,
    policies_router,
    simulate_router,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    configure_logging()
    logger = get_logger("aegisgate.startup")
    logger.info("Bootstrapping AegisGate Engine & Gateways...")
    bootstrap_system()
    yield
    # Shutdown
    logger.info("Shutting down AegisGate Engine & Gateways...")
    await close_redis_client()
    await close_database()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="AegisGate Platform",
        version="0.1.0",
        description="Sub-15ms AI Guardrails & Governance Policy Decision Point & Proxies",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Core PDP & Governance APIs
    app.include_router(health_router)
    app.include_router(auth_router)
    app.include_router(evaluate_router)
    app.include_router(policies_router)
    app.include_router(plugins_router)
    app.include_router(kill_switch_router)
    app.include_router(approvals_router)
    app.include_router(audit_router)
    app.include_router(simulate_router)

    # Integration Gateways
    app.include_router(llm_proxy_router)
    app.include_router(tool_gateway_router)

    return app


app = create_app()
