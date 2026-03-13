import httpx
import pytest
import respx
from unittest.mock import AsyncMock

from api.adapters.ipqs import IPQSClient, IPQSResponse
from api.adapters.bin_lookup import BINLookupClient, BINInfo
from api.core.config import Settings


@pytest.fixture
def settings() -> Settings:
    return Settings(
        IPQS_API_KEY="test_key",
        MPGS_BASE_URL="",
        MPGS_MERCHANT_ID="",
        MPGS_API_KEY="",
        ANTHROPIC_API_KEY="",
        DATABASE_URL="postgresql+asyncpg://x:x@localhost/x",
    )


@pytest.fixture
def http_client() -> httpx.AsyncClient:
    return httpx.AsyncClient()


class TestIPQSClient:
    @respx.mock
    @pytest.mark.asyncio
    async def test_normal_response(self, settings: Settings):
        respx.get("https://ipqualityscore.com/api/json/ip/test_key/1.2.3.4").mock(
            return_value=httpx.Response(
                200,
                json={
                    "fraud_score": 25.5,
                    "vpn": True,
                    "tor": False,
                    "proxy": False,
                    "country_code": "US",
                },
            )
        )
        async with httpx.AsyncClient() as client:
            ipqs = IPQSClient(client, settings)
            result = await ipqs.get_ip_signals("1.2.3.4")

        assert result.fraud_score == 25.5
        assert result.is_vpn is True
        assert result.is_tor is False
        assert result.country_code == "US"

    @respx.mock
    @pytest.mark.asyncio
    async def test_429_retry_then_success(self, settings: Settings):
        route = respx.get("https://ipqualityscore.com/api/json/ip/test_key/1.2.3.4")
        route.side_effect = [
            httpx.Response(429),
            httpx.Response(
                200,
                json={
                    "fraud_score": 10.0,
                    "vpn": False,
                    "tor": False,
                    "proxy": False,
                    "country_code": "GB",
                },
            ),
        ]
        async with httpx.AsyncClient() as client:
            ipqs = IPQSClient(client, settings)
            result = await ipqs.get_ip_signals("1.2.3.4")

        assert result.fraud_score == 10.0
        assert result.country_code == "GB"

    @respx.mock
    @pytest.mark.asyncio
    async def test_timeout_returns_fallback(self, settings: Settings):
        respx.get("https://ipqualityscore.com/api/json/ip/test_key/1.2.3.4").mock(
            side_effect=httpx.ReadTimeout("timeout")
        )
        async with httpx.AsyncClient() as client:
            ipqs = IPQSClient(client, settings)
            result = await ipqs.get_ip_signals("1.2.3.4")

        assert result.fraud_score == 50.0
        assert result.is_vpn is False
        assert result.country_code is None


class TestBINLookupClient:
    @respx.mock
    @pytest.mark.asyncio
    async def test_cache_miss_fetches_and_caches(self):
        redis_mock = AsyncMock()
        redis_mock.get.return_value = None

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

        async with httpx.AsyncClient() as client:
            bin_client = BINLookupClient(client)
            result = await bin_client.get_bin_info("411111", redis_mock)

        assert result.card_type == "credit"
        assert result.card_brand == "visa"
        assert result.issuing_country == "US"
        redis_mock.set.assert_called_once()

    @pytest.mark.asyncio
    async def test_cache_hit_skips_http(self):
        cached_info = BINInfo(card_type="debit", card_brand="mastercard", issuing_country="GB")
        redis_mock = AsyncMock()
        redis_mock.get.return_value = cached_info.model_dump_json()

        async with httpx.AsyncClient() as client:
            bin_client = BINLookupClient(client)
            result = await bin_client.get_bin_info("511111", redis_mock)

        assert result.card_type == "debit"
        assert result.card_brand == "mastercard"
        assert result.issuing_country == "GB"

    @respx.mock
    @pytest.mark.asyncio
    async def test_http_error_returns_unknown(self):
        redis_mock = AsyncMock()
        redis_mock.get.return_value = None

        respx.get("https://lookup.binlist.net/000000").mock(
            return_value=httpx.Response(404)
        )

        async with httpx.AsyncClient() as client:
            bin_client = BINLookupClient(client)
            result = await bin_client.get_bin_info("000000", redis_mock)

        assert result.card_type == "unknown"
        assert result.card_brand == "unknown"
        assert result.issuing_country is None
