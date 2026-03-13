from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from redis.asyncio import Redis

from api.core.redis_client import get_redis
from api.services.suspicious import (
    RiskLevel,
    SuspiciousFlag,
    SuspiciousTransaction,
    get_suspicious_stats,
    get_suspicious_transactions,
)

router = APIRouter(prefix="/v1/dashboard", tags=["dashboard"])


class SuspiciousListResponse(BaseModel):
    count: int
    transactions: list[SuspiciousTransaction]


class StatsResponse(BaseModel):
    total: int
    by_level: dict[str, int]
    by_flag: dict[str, int]


@router.get("/suspicious", response_model=SuspiciousListResponse)
async def list_suspicious(
    redis: Annotated[Redis, Depends(get_redis)],
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
) -> SuspiciousListResponse:
    """List recent suspicious transactions, newest first."""
    txns = await get_suspicious_transactions(redis, limit=limit, offset=offset)
    return SuspiciousListResponse(count=len(txns), transactions=txns)


@router.get("/stats", response_model=StatsResponse)
async def dashboard_stats(
    redis: Annotated[Redis, Depends(get_redis)],
) -> StatsResponse:
    """Get aggregated suspicious transaction stats."""
    stats = await get_suspicious_stats(redis)
    return StatsResponse(**stats)
