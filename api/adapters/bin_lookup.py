import httpx
import structlog
from pydantic import BaseModel
from redis.asyncio import Redis
from typing import Literal

logger = structlog.get_logger()


class BINInfo(BaseModel):
    card_type: Literal["credit", "debit", "prepaid", "unknown"]
    card_brand: str
    issuing_country: str | None = None


_FALLBACK = BINInfo(card_type="unknown", card_brand="unknown", issuing_country=None)


class BINLookupClient:
    BASE_URL = "https://lookup.binlist.net"

    def __init__(self, http_client: httpx.AsyncClient) -> None:
        self._http = http_client

    async def get_bin_info(self, bin: str, redis: Redis) -> BINInfo:
        cache_key = f"bin:{bin}"
        try:
            cached = await redis.get(cache_key)
            if cached is not None:
                return BINInfo.model_validate_json(cached)
        except Exception as exc:
            logger.warning("bin_cache_read_error", error=str(exc))

        try:
            resp = await self._http.get(
                f"{self.BASE_URL}/{bin}",
                headers={"Accept-Version": "3"},
                timeout=1.0,
            )
            resp.raise_for_status()
            data = resp.json()

            raw_type = (data.get("type") or "").lower()
            card_type: Literal["credit", "debit", "prepaid", "unknown"]
            match raw_type:
                case "credit" | "debit" | "prepaid":
                    card_type = raw_type  # type: ignore[assignment]
                case _:
                    card_type = "unknown"

            info = BINInfo(
                card_type=card_type,
                card_brand=(data.get("scheme") or "unknown").lower(),
                issuing_country=(data.get("country", {}) or {}).get("alpha2"),
            )

            await redis.set(cache_key, info.model_dump_json(), ex=86400)
            return info

        except Exception as exc:
            logger.warning("bin_lookup_error", bin=bin, error=str(exc))
            return _FALLBACK
