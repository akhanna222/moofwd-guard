from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated
from uuid import uuid4

import structlog
from fastapi import Depends, FastAPI, Request, Response
from redis.asyncio import Redis

from api.core.config import Settings, get_settings
from api.core.redis_client import init_redis, close_redis, get_redis

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    app.state.redis = await init_redis(settings.REDIS_URL)
    logger.info("redis_connected", url=settings.REDIS_URL)
    yield
    await close_redis()
    logger.info("redis_disconnected")


app = FastAPI(title="MoofwdGuard", version="0.1.0", lifespan=lifespan)


@app.get("/health")
async def health(redis: Annotated[Redis, Depends(get_redis)]) -> dict:
    await redis.ping()
    return {"status": "ok", "redis": "connected"}


# Import and mount routers
from api.routers.signals import router as signals_router  # noqa: E402
from api.routers.dashboard import router as dashboard_router  # noqa: E402

app.include_router(signals_router)
app.include_router(dashboard_router)
