import hashlib
from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator


class DeviceSignals(BaseModel):
    model_config = ConfigDict(frozen=True)

    fingerprint_id: str
    user_agent: str
    browser_language: str
    screen_resolution: str
    timezone_offset: int
    webgl_hash: str | None = None
    is_headless: bool = False
    is_tor: bool = False
    is_vpn: bool = False
    ip_fraud_score: float = 0.0
    ip_country: str | None = None


class BehavioralSignals(BaseModel):
    model_config = ConfigDict(frozen=True)

    checkout_duration_seconds: float
    form_fill_speed_ms: float | None = None
    mouse_movement_present: bool = True
    copy_paste_detected: bool = False
    page_focus_lost_count: int = 0
    scroll_event_count: int = 0
    is_bot_suspected: bool = False

    @model_validator(mode="after")
    def compute_bot_suspected(self) -> "BehavioralSignals":
        bot = (
            self.checkout_duration_seconds < 5
            or (not self.mouse_movement_present and self.copy_paste_detected)
        )
        object.__setattr__(self, "is_bot_suspected", bot)
        return self


class VelocitySignals(BaseModel):
    model_config = ConfigDict(frozen=True)

    same_email_txn_1h: int = 0
    same_ip_txn_1h: int = 0
    same_device_txn_24h: int = 0
    same_bin_txn_1h: int = 0
    declined_count_24h: int = 0
    is_first_seen_device: bool = True


class PaymentSignals(BaseModel):
    model_config = ConfigDict(frozen=True)

    bin: str
    card_type: Literal["credit", "debit", "prepaid", "unknown"]
    card_brand: str
    issuing_country: str | None = None
    billing_country: str | None = None
    is_country_mismatch: bool = False
    is_prepaid: bool = False
    amount_usd: float
    amount_vs_avg_ratio: float = 1.0


class IdentityContext(BaseModel):
    model_config = ConfigDict(frozen=True)

    identity_id: str = Field(default_factory=lambda: str(uuid4()))
    device: DeviceSignals
    behavioral: BehavioralSignals
    velocity: VelocitySignals
    payment: PaymentSignals
    computed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    risk_score: float = 0.0

    def to_cache_key(self, email: str) -> str:
        raw = email + self.device.fingerprint_id
        return hashlib.sha256(raw.encode()).hexdigest()
