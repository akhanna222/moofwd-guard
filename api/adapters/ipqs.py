import asyncio

import httpx
import structlog
from pydantic import BaseModel

from api.core.config import Settings

logger = structlog.get_logger()

_FALLBACK = None  # defined below after model


class IPQSResponse(BaseModel):
    fraud_score: float
    is_vpn: bool
    is_tor: bool
    is_proxy: bool
    country_code: str | None = None


_FALLBACK = IPQSResponse(
    fraud_score=50.0,
    is_vpn=False,
    is_tor=False,
    is_proxy=False,
    country_code=None,
)


class IPQSClient:
    BASE_URL = "https://ipqualityscore.com/api/json/ip"

    def __init__(self, http_client: httpx.AsyncClient, settings: Settings) -> None:
        self._http = http_client
        self._api_key = settings.IPQS_API_KEY

    async def get_ip_signals(self, ip: str) -> IPQSResponse:
        url = f"{self.BASE_URL}/{self._api_key}/{ip}"
        params = {"strictness": 1, "allow_public_access_points": "true"}

        backoff_times = [0.5, 1.0]
        last_exc: BaseException | None = None

        logger.info("ipqs_request_start", ip=ip, url=url[:50])

        for attempt in range(3):
            try:
                resp = await self._http.get(url, params=params, timeout=10.0)
                logger.info("ipqs_response", ip=ip, status=resp.status_code, attempt=attempt + 1)
                
                if resp.status_code == 429:
                    if attempt < 2:
                        await asyncio.sleep(backoff_times[attempt])
                        continue
                    logger.warning("ipqs_rate_limited", ip=ip, attempts=attempt + 1)
                    return _FALLBACK
                resp.raise_for_status()
                data = resp.json()
                logger.info("ipqs_success", ip=ip, fraud_score=data.get("fraud_score"))
                return IPQSResponse(
                    fraud_score=data.get("fraud_score", 50.0),
                    is_vpn=data.get("vpn", False),
                    is_tor=data.get("tor", False),
                    is_proxy=data.get("proxy", False),
                    country_code=data.get("country_code"),
                )
            except httpx.TimeoutException as exc:
                last_exc = exc
                logger.warning("ipqs_timeout", ip=ip, attempt=attempt + 1)
                if attempt < 2:
                    await asyncio.sleep(backoff_times[attempt])
                    continue
                return _FALLBACK
            except Exception as exc:
                last_exc = exc
                logger.warning("ipqs_error", ip=ip, error=str(exc), attempt=attempt + 1)
                return _FALLBACK

        return _FALLBACK
