from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from core.bootstrap import bootstrap_system
from core.config import get_settings
from core.database import close_database
from core.logger import configure_logging, get_logger
from core.redis_client import close_redis_client
from gateways.pdp_api.routes import (
    evaluate_router,
    health_router,
    kill_switch_router,
    plugins_router,
    policies_router,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    configure_logging()
    logger = get_logger("aegisgate.startup")
    logger.info("Bootstrapping AegisGate PDP API...")
    bootstrap_system()
    yield
    # Shutdown
    logger.info("Shutting down AegisGate PDP API...")
    await close_redis_client()
    await close_database()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="AegisGate PDP API",
        version="0.1.0",
        description="Sub-15ms AI Guardrails & Governance Policy Decision Point",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health_router)
    app.include_router(evaluate_router)
    app.include_router(policies_router)
    app.include_router(plugins_router)
    app.include_router(kill_switch_router)

    return app


app = create_app()
