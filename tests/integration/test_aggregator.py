import httpx
import pytest
import respx
from unittest.mock import AsyncMock, patch

import fakeredis.aioredis

from api.adapters.bin_lookup import BINLookupClient
from api.adapters.ipqs import IPQSClient
from api.core.config import Settings
from api.models.identity import IdentityContext
from api.models.request import TransactionRequest
from api.services.aggregator import IdentityAggregator


def _make_settings() -> Settings:
    return Settings(
        IPQS_API_KEY="test_key",
        MPGS_BASE_URL="",
        MPGS_MERCHANT_ID="",
        MPGS_API_KEY="",
        ANTHROPIC_API_KEY="",
        DATABASE_URL="postgresql+asyncpg://x:x@localhost/x",
    )


def _make_request(**overrides) -> TransactionRequest:
    defaults = {
        "transaction_id": "txn_001",
        "ip_address": "1.2.3.4",
        "email": "buyer@example.com",
        "bin": "411111",
        "billing_country": "US",
        "device_fingerprint": "fp_abc123",
        "checkout_duration_seconds": 38.0,
        "user_agent": "Mozilla/5.0",
        "amount_usd": 49.99,
    }
    defaults.update(overrides)
    return TransactionRequest(**defaults)


@pytest.fixture
async def fake_redis():
    r = fakeredis.aioredis.FakeRedis(decode_responses=True)
    yield r
    await r.aclose()


@respx.mock
@pytest.mark.asyncio
async def test_full_aggregate(fake_redis):
    respx.get("https://ipqualityscore.com/api/json/ip/test_key/1.2.3.4").mock(
        return_value=httpx.Response(
            200,
            json={
                "fraud_score": 15.0,
                "vpn": False,
                "tor": False,
                "proxy": False,
                "country_code": "US",
            },
        )
    )
    respx.get("https://lookup.binlist.net/411111").mock(
        return_value=httpx.Response(
            200,
            json={
                "type": "credit",
                "scheme": "Visa",
                "country": {"alpha2": "US"},
            },
        )
    )

    redis = await anext(fake_redis.__aiter__()) if hasattr(fake_redis, '__aiter__') else fake_redis
    settings = _make_settings()

    async with httpx.AsyncClient() as client:
        ipqs = IPQSClient(client, settings)
        bin_lookup = BINLookupClient(client)
        aggregator = IdentityAggregator(ipqs, bin_lookup, redis)

        ctx = await aggregator.aggregate(_make_request())

    assert isinstance(ctx, IdentityContext)
    assert ctx.device.ip_fraud_score == 15.0
    assert ctx.payment.card_type == "credit"
    assert ctx.payment.is_country_mismatch is False
    assert ctx.velocity.same_email_txn_1h == 1

    # Verify stored in Redis
    cache_key = ctx.to_cache_key("buyer@example.com")
    stored = await redis.get(f"identity:{cache_key}")
    assert stored is not None
    restored = IdentityContext.model_validate_json(stored)
    assert restored.identity_id == ctx.identity_id


@respx.mock
@pytest.mark.asyncio
async def test_ipqs_timeout_fallback(fake_redis):
    respx.get("https://ipqualityscore.com/api/json/ip/test_key/1.2.3.4").mock(
        side_effect=httpx.ReadTimeout("timeout")
    )
    respx.get("https://lookup.binlist.net/411111").mock(
        return_value=httpx.Response(
            200,
            json={
                "type": "credit",
                "scheme": "Visa",
                "country": {"alpha2": "US"},
            },
        )
    )

    redis = await anext(fake_redis.__aiter__()) if hasattr(fake_redis, '__aiter__') else fake_redis
    settings = _make_settings()

    async with httpx.AsyncClient() as client:
        ipqs = IPQSClient(client, settings)
        bin_lookup = BINLookupClient(client)
        aggregator = IdentityAggregator(ipqs, bin_lookup, redis)

        ctx = await aggregator.aggregate(_make_request())

    assert ctx.device.ip_fraud_score == 50.0
    assert ctx.device.is_vpn is False


@respx.mock
@pytest.mark.asyncio
async def test_velocity_increments(fake_redis):
    respx.get("https://ipqualityscore.com/api/json/ip/test_key/1.2.3.4").mock(
        return_value=httpx.Response(
            200,
            json={
                "fraud_score": 10.0,
                "vpn": False,
                "tor": False,
                "proxy": False,
                "country_code": "US",
            },
        )
    )
    respx.get("https://lookup.binlist.net/411111").mock(
        return_value=httpx.Response(
            200,
            json={
                "type": "credit",
                "scheme": "Visa",
                "country": {"alpha2": "US"},
            },
        )
    )

    redis = await anext(fake_redis.__aiter__()) if hasattr(fake_redis, '__aiter__') else fake_redis
    settings = _make_settings()

    async with httpx.AsyncClient() as client:
        ipqs = IPQSClient(client, settings)
        bin_lookup = BINLookupClient(client)
        aggregator = IdentityAggregator(ipqs, bin_lookup, redis)

        req = _make_request()
        ctx1 = await aggregator.aggregate(req)
        ctx2 = await aggregator.aggregate(req)
        ctx3 = await aggregator.aggregate(req)
        ctx4 = await aggregator.aggregate(req)

    assert ctx4.velocity.same_email_txn_1h == 4
    assert ctx1.velocity.is_first_seen_device is True
    assert ctx2.velocity.is_first_seen_device is False
