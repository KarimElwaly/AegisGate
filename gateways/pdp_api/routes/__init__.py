from gateways.pdp_api.routes.approvals import router as approvals_router
from gateways.pdp_api.routes.audit import router as audit_router
from gateways.pdp_api.routes.auth import router as auth_router
from gateways.pdp_api.routes.evaluate import router as evaluate_router
from gateways.pdp_api.routes.health import router as health_router
from gateways.pdp_api.routes.kill_switch import router as kill_switch_router
from gateways.pdp_api.routes.plugins import router as plugins_router
from gateways.pdp_api.routes.policies import router as policies_router
from gateways.pdp_api.routes.simulate import router as simulate_router

__all__ = [
    "approvals_router",
    "audit_router",
    "auth_router",
    "evaluate_router",
    "health_router",
    "kill_switch_router",
    "plugins_router",
    "policies_router",
    "simulate_router",
]
