from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated

import redis.asyncio as aioredis
from fastapi import Depends, Request


_redis_pool: aioredis.Redis | None = None


async def init_redis(url: str) -> aioredis.Redis:
    global _redis_pool
    _redis_pool = aioredis.from_url(url, decode_responses=True)
    return _redis_pool


async def close_redis() -> None:
    global _redis_pool
    if _redis_pool is not None:
        await _redis_pool.aclose()
        _redis_pool = None


async def get_redis(request: Request) -> aioredis.Redis:
    redis: aioredis.Redis = request.app.state.redis
    return redis
