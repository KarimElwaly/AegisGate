from gateways.pdp_api.routes.evaluate import router as evaluate_router
from gateways.pdp_api.routes.health import router as health_router
from gateways.pdp_api.routes.plugins import router as plugins_router
from gateways.pdp_api.routes.policies import router as policies_router

__all__ = [
    "evaluate_router",
    "health_router",
    "plugins_router",
    "policies_router",
]
