import json
from datetime import datetime, timezone
from enum import Enum

import structlog
from pydantic import BaseModel
from redis.asyncio import Redis

from api.models.identity import IdentityContext

logger = structlog.get_logger()


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SuspiciousFlag(BaseModel):
    code: str
    message: str
    severity: RiskLevel


class SuspiciousTransaction(BaseModel):
    transaction_id: str
    identity_id: str
    email: str
    ip_address: str
    amount_usd: float
    risk_level: RiskLevel
    flags: list[SuspiciousFlag]
    identity_cache_key: str
    timestamp: datetime


REDIS_KEY_SUSPICIOUS = "suspicious:transactions"
REDIS_KEY_STATS = "suspicious:stats"


def evaluate_suspicion(
    ctx: IdentityContext,
    transaction_id: str,
    email: str,
    ip_address: str,
) -> SuspiciousTransaction | None:
    """Evaluate an IdentityContext and return a SuspiciousTransaction if flags are found."""
    flags: list[SuspiciousFlag] = []

    # --- Bot detection ---
    if ctx.behavioral.is_bot_suspected:
        if ctx.behavioral.checkout_duration_seconds < 5:
            flags.append(SuspiciousFlag(
                code="BOT_SPEED",
                message=f"Checkout completed in {ctx.behavioral.checkout_duration_seconds}s (under 5s threshold)",
                severity=RiskLevel.HIGH,
            ))
        if not ctx.behavioral.mouse_movement_present and ctx.behavioral.copy_paste_detected:
            flags.append(SuspiciousFlag(
                code="BOT_PATTERN",
                message="No mouse movement with card number pasted — automated behavior",
                severity=RiskLevel.HIGH,
            ))

    # --- Suspicious user agent ---
    ua = ctx.device.user_agent.lower()
    for marker in ["headlesschrome", "python-requests", "curl/", "scrapy", "phantomjs", "selenium"]:
        if marker in ua:
            flags.append(SuspiciousFlag(
                code="SUSPICIOUS_UA",
                message=f"Non-browser user agent detected: {marker}",
                severity=RiskLevel.CRITICAL,
            ))
            break

    # --- IP fraud score ---
    if ctx.device.ip_fraud_score >= 80:
        flags.append(SuspiciousFlag(
            code="HIGH_IP_FRAUD_SCORE",
            message=f"IP fraud score: {ctx.device.ip_fraud_score}/100",
            severity=RiskLevel.HIGH,
        ))
    elif ctx.device.ip_fraud_score >= 50:
        flags.append(SuspiciousFlag(
            code="ELEVATED_IP_FRAUD_SCORE",
            message=f"IP fraud score: {ctx.device.ip_fraud_score}/100",
            severity=RiskLevel.MEDIUM,
        ))

    # --- VPN / Tor ---
    if ctx.device.is_tor:
        flags.append(SuspiciousFlag(
            code="TOR_DETECTED",
            message="Connection via Tor network",
            severity=RiskLevel.HIGH,
        ))
    if ctx.device.is_vpn:
        flags.append(SuspiciousFlag(
            code="VPN_DETECTED",
            message="VPN connection detected",
            severity=RiskLevel.MEDIUM,
        ))

    # --- Country mismatch ---
    if ctx.payment.is_country_mismatch:
        flags.append(SuspiciousFlag(
            code="COUNTRY_MISMATCH",
            message=f"Card issued in {ctx.payment.issuing_country}, billing set to {ctx.payment.billing_country}",
            severity=RiskLevel.HIGH,
        ))

    # --- Prepaid card ---
    if ctx.payment.is_prepaid:
        flags.append(SuspiciousFlag(
            code="PREPAID_CARD",
            message="Prepaid card used",
            severity=RiskLevel.MEDIUM,
        ))

    # --- Velocity ---
    if ctx.velocity.same_email_txn_1h >= 5:
        flags.append(SuspiciousFlag(
            code="VELOCITY_EMAIL",
            message=f"{ctx.velocity.same_email_txn_1h} transactions from same email in 1 hour",
            severity=RiskLevel.HIGH,
        ))
    elif ctx.velocity.same_email_txn_1h >= 3:
        flags.append(SuspiciousFlag(
            code="VELOCITY_EMAIL",
            message=f"{ctx.velocity.same_email_txn_1h} transactions from same email in 1 hour",
            severity=RiskLevel.MEDIUM,
        ))

    if ctx.velocity.same_ip_txn_1h >= 10:
        flags.append(SuspiciousFlag(
            code="VELOCITY_IP",
            message=f"{ctx.velocity.same_ip_txn_1h} transactions from same IP in 1 hour",
            severity=RiskLevel.HIGH,
        ))

    if ctx.velocity.same_device_txn_24h >= 10:
        flags.append(SuspiciousFlag(
            code="VELOCITY_DEVICE",
            message=f"{ctx.velocity.same_device_txn_24h} transactions from same device in 24 hours",
            severity=RiskLevel.HIGH,
        ))

    if ctx.velocity.declined_count_24h >= 3:
        flags.append(SuspiciousFlag(
            code="REPEATED_DECLINES",
            message=f"{ctx.velocity.declined_count_24h} declined transactions in 24 hours",
            severity=RiskLevel.HIGH,
        ))

    # --- Card testing pattern ---
    if ctx.payment.amount_usd <= 2.0 and ctx.behavioral.is_bot_suspected:
        flags.append(SuspiciousFlag(
            code="CARD_TESTING",
            message=f"Micro-charge (${ctx.payment.amount_usd:.2f}) with bot-like behavior — card testing pattern",
            severity=RiskLevel.CRITICAL,
        ))
    elif ctx.payment.amount_usd <= 2.0:
        flags.append(SuspiciousFlag(
            code="MICRO_CHARGE",
            message=f"Micro-charge: ${ctx.payment.amount_usd:.2f} — possible card testing",
            severity=RiskLevel.MEDIUM,
        ))

    # --- High value ---
    if ctx.payment.amount_usd >= 3000:
        flags.append(SuspiciousFlag(
            code="VERY_HIGH_VALUE",
            message=f"Very high transaction: ${ctx.payment.amount_usd:,.2f}",
            severity=RiskLevel.MEDIUM,
        ))

    # --- Focus switching (possible comparison shopping or hesitation) ---
    if ctx.behavioral.page_focus_lost_count >= 5:
        flags.append(SuspiciousFlag(
            code="EXCESSIVE_TAB_SWITCHING",
            message=f"Page focus lost {ctx.behavioral.page_focus_lost_count} times during checkout",
            severity=RiskLevel.MEDIUM,
        ))

    if not flags:
        return None

    # Determine overall risk level
    severities = [f.severity for f in flags]
    if RiskLevel.CRITICAL in severities:
        risk_level = RiskLevel.CRITICAL
    elif RiskLevel.HIGH in severities:
        risk_level = RiskLevel.HIGH
    elif RiskLevel.MEDIUM in severities:
        risk_level = RiskLevel.MEDIUM
    else:
        risk_level = RiskLevel.LOW

    return SuspiciousTransaction(
        transaction_id=transaction_id,
        identity_id=ctx.identity_id,
        email=email,
        ip_address=ip_address,
        amount_usd=ctx.payment.amount_usd,
        risk_level=risk_level,
        flags=flags,
        identity_cache_key=ctx.to_cache_key(email),
        timestamp=datetime.now(timezone.utc),
    )


async def store_suspicious(redis: Redis, txn: SuspiciousTransaction) -> None:
    """Store suspicious transaction in Redis for dashboard access."""
    pipe = redis.pipeline()

    # Add to sorted set (score = timestamp for ordering)
    pipe.zadd(
        REDIS_KEY_SUSPICIOUS,
        {txn.model_dump_json(): txn.timestamp.timestamp()},
    )

    # Trim to last 1000 entries
    pipe.zremrangebyrank(REDIS_KEY_SUSPICIOUS, 0, -1001)

    # Update stats counters
    pipe.hincrby(REDIS_KEY_STATS, "total", 1)
    pipe.hincrby(REDIS_KEY_STATS, f"level:{txn.risk_level.value}", 1)
    for flag in txn.flags:
        pipe.hincrby(REDIS_KEY_STATS, f"flag:{flag.code}", 1)

    await pipe.execute()

    logger.warning(
        "suspicious_transaction",
        transaction_id=txn.transaction_id,
        risk_level=txn.risk_level.value,
        flags=[f.code for f in txn.flags],
        amount=txn.amount_usd,
        email=txn.email,
    )


async def get_suspicious_transactions(
    redis: Redis,
    limit: int = 50,
    offset: int = 0,
) -> list[SuspiciousTransaction]:
    """Retrieve recent suspicious transactions, newest first."""
    raw = await redis.zrevrange(REDIS_KEY_SUSPICIOUS, offset, offset + limit - 1)
    return [SuspiciousTransaction.model_validate_json(r) for r in raw]


async def get_suspicious_stats(redis: Redis) -> dict:
    """Get aggregated stats on suspicious transactions."""
    raw = await redis.hgetall(REDIS_KEY_STATS)
    if not raw:
        return {"total": 0, "by_level": {}, "by_flag": {}}

    by_level = {}
    by_flag = {}
    total = 0

    for key, val in raw.items():
        if key == "total":
            total = int(val)
        elif key.startswith("level:"):
            by_level[key.replace("level:", "")] = int(val)
        elif key.startswith("flag:"):
            by_flag[key.replace("flag:", "")] = int(val)

    return {"total": total, "by_level": by_level, "by_flag": by_flag}
