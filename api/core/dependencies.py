from typing import Annotated

import httpx
from fastapi import Depends, Request
from redis.asyncio import Redis

from api.adapters.bin_lookup import BINLookupClient
from api.adapters.ipqs import IPQSClient
from api.core.config import Settings, get_settings
from api.core.redis_client import get_redis
from api.services.aggregator import IdentityAggregator


async def get_http_client() -> httpx.AsyncClient:
    async with httpx.AsyncClient() as client:
        yield client  # type: ignore[misc]


def get_ipqs_client(
    http_client: Annotated[httpx.AsyncClient, Depends(get_http_client)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> IPQSClient:
    return IPQSClient(http_client, settings)


def get_bin_lookup_client(
    http_client: Annotated[httpx.AsyncClient, Depends(get_http_client)],
) -> BINLookupClient:
    return BINLookupClient(http_client)


def get_aggregator(
    ipqs: Annotated[IPQSClient, Depends(get_ipqs_client)],
    bin_lookup: Annotated[BINLookupClient, Depends(get_bin_lookup_client)],
    redis: Annotated[Redis, Depends(get_redis)],
) -> IdentityAggregator:
    return IdentityAggregator(ipqs, bin_lookup, redis)
