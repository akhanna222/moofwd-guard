import time
from typing import Annotated
from uuid import uuid4

import structlog
from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel, EmailStr, Field, IPvAnyAddress
from redis.asyncio import Redis

from api.core.dependencies import get_aggregator, get_redis
from api.models.request import TransactionRequest
from api.services.aggregator import IdentityAggregator

logger = structlog.get_logger()

router = APIRouter(prefix="/v1", tags=["signals"])


class SignalsRequest(BaseModel):
    transaction_id: str
    ip_address: IPvAnyAddress
    email: EmailStr
    bin: str = Field(pattern=r"^[0-9]{6}$")
    billing_country: str
    device_fingerprint: str
    checkout_duration_seconds: float
    user_agent: str
    browser_language: str = "en"
    screen_resolution: str = "unknown"
    timezone_offset: int = 0
    webgl_hash: str | None = None
    mouse_movement_present: bool = True
    copy_paste_detected: bool = False
    page_focus_lost_count: int = 0
    scroll_event_count: int = 0
    amount_usd: float = 0.0


class SignalsResponse(BaseModel):
    identity_id: str
    cache_key: str
    latency_ms: float


@router.post("/signals", response_model=SignalsResponse)
async def create_signals(
    body: SignalsRequest,
    aggregator: Annotated[IdentityAggregator, Depends(get_aggregator)],
    response: Response,
) -> SignalsResponse:
    request_id = str(uuid4())
    response.headers["X-MoofwdGuard-Request-ID"] = request_id

    start = time.perf_counter()

    txn_request = TransactionRequest(
        transaction_id=body.transaction_id,
        ip_address=str(body.ip_address),
        email=body.email,
        bin=body.bin,
        billing_country=body.billing_country,
        device_fingerprint=body.device_fingerprint,
        checkout_duration_seconds=body.checkout_duration_seconds,
        user_agent=body.user_agent,
        browser_language=body.browser_language,
        screen_resolution=body.screen_resolution,
        timezone_offset=body.timezone_offset,
        webgl_hash=body.webgl_hash,
        mouse_movement_present=body.mouse_movement_present,
        copy_paste_detected=body.copy_paste_detected,
        page_focus_lost_count=body.page_focus_lost_count,
        scroll_event_count=body.scroll_event_count,
        amount_usd=body.amount_usd,
    )

    ctx = await aggregator.aggregate(txn_request)

    latency_ms = (time.perf_counter() - start) * 1000
    cache_key = ctx.to_cache_key(body.email)

    logger.info(
        "signals_processed",
        transaction_id=body.transaction_id,
        identity_id=ctx.identity_id,
        latency_ms=round(latency_ms, 2),
    )

    return SignalsResponse(
        identity_id=ctx.identity_id,
        cache_key=cache_key,
        latency_ms=round(latency_ms, 2),
    )


@router.get("/signals/{cache_key}")
async def get_signal_details(
    cache_key: str,
    redis: Annotated[Redis, Depends(get_redis)],
) -> dict:
    """Retrieve full identity context from cache"""
    data = await redis.get(f"identity:{cache_key}")
    if not data:
        return {"error": "Identity not found", "cache_key": cache_key}
    
    import json
    return json.loads(data)
