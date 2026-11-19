from fastapi import APIRouter, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

router = APIRouter(tags=["Health & Monitoring"])


@router.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok", "service": "aegisgate-pdp"}


@router.get("/readyz")
async def readyz() -> dict:
    return {"status": "ready", "service": "aegisgate-pdp"}


@router.get("/metrics")
async def metrics() -> Response:
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
