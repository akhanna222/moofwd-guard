import asyncio
import hashlib

import structlog
from redis.asyncio import Redis

from api.adapters.bin_lookup import BINLookupClient
from api.adapters.ipqs import IPQSClient
from api.models.identity import (
    BehavioralSignals,
    DeviceSignals,
    IdentityContext,
    PaymentSignals,
    VelocitySignals,
)
from api.models.request import TransactionRequest

logger = structlog.get_logger()


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class IdentityAggregator:
    def __init__(
        self,
        ipqs: IPQSClient,
        bin_lookup: BINLookupClient,
        redis: Redis,
    ) -> None:
        self._ipqs = ipqs
        self._bin_lookup = bin_lookup
        self._redis = redis

    async def aggregate(self, request: TransactionRequest) -> IdentityContext:
        ipqs_result, bin_info, velocity_values = await asyncio.gather(
            self._ipqs.get_ip_signals(request.ip_address),
            self._bin_lookup.get_bin_info(request.bin, self._redis),
            self._compute_velocity(request),
        )

        device = DeviceSignals(
            fingerprint_id=request.device_fingerprint,
            user_agent=request.user_agent,
            browser_language=request.browser_language,
            screen_resolution=request.screen_resolution,
            timezone_offset=request.timezone_offset,
            webgl_hash=request.webgl_hash,
            is_headless=False,
            is_tor=ipqs_result.is_tor,
            is_vpn=ipqs_result.is_vpn,
            ip_fraud_score=ipqs_result.fraud_score,
            ip_country=ipqs_result.country_code,
        )

        behavioral = BehavioralSignals(
            checkout_duration_seconds=request.checkout_duration_seconds,
            mouse_movement_present=request.mouse_movement_present,
            copy_paste_detected=request.copy_paste_detected,
            page_focus_lost_count=request.page_focus_lost_count,
            scroll_event_count=request.scroll_event_count,
        )

        is_country_mismatch = (
            bin_info.issuing_country is not None
            and request.billing_country is not None
            and bin_info.issuing_country != request.billing_country
        )

        payment = PaymentSignals(
            bin=request.bin,
            card_type=bin_info.card_type,
            card_brand=bin_info.card_brand,
            issuing_country=bin_info.issuing_country,
            billing_country=request.billing_country,
            is_country_mismatch=is_country_mismatch,
            is_prepaid=bin_info.card_type == "prepaid",
            amount_usd=request.amount_usd,
        )

        same_email, same_ip, same_device, same_bin, declined = velocity_values

        velocity = VelocitySignals(
            same_email_txn_1h=same_email,
            same_ip_txn_1h=same_ip,
            same_device_txn_24h=same_device,
            same_bin_txn_1h=same_bin,
            declined_count_24h=declined,
            is_first_seen_device=same_device == 1,
        )

        ctx = IdentityContext(
            device=device,
            behavioral=behavioral,
            velocity=velocity,
            payment=payment,
        )

        cache_key = ctx.to_cache_key(request.email)
        await self._redis.set(
            f"identity:{cache_key}",
            ctx.model_dump_json(),
            ex=86400,
        )

        logger.info(
            "identity_aggregated",
            identity_id=ctx.identity_id,
            transaction_id=request.transaction_id,
        )

        return ctx

    async def _compute_velocity(
        self, request: TransactionRequest
    ) -> tuple[int, int, int, int, int]:
        email_hash = _sha256(request.email)
        keys_ttls = [
            (f"vel:email:{email_hash}:1h", 3600),
            (f"vel:ip:{request.ip_address}:1h", 3600),
            (f"vel:device:{request.device_fingerprint}:24h", 86400),
            (f"vel:bin:{request.bin}:1h", 3600),
            (f"vel:declined:{email_hash}:24h", 86400),
        ]

        pipe = self._redis.pipeline()
        for key, ttl in keys_ttls:
            pipe.incr(key)
            pipe.expire(key, ttl)

        results = await pipe.execute()
        # Results alternate: [incr_val, expire_bool, incr_val, expire_bool, ...]
        values = tuple(results[i] for i in range(0, len(results), 2))
        return values  # type: ignore[return-value]
