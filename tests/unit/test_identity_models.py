import pytest
from pydantic import ValidationError

from api.models.identity import (
    BehavioralSignals,
    DeviceSignals,
    IdentityContext,
    PaymentSignals,
    VelocitySignals,
)


def _make_device() -> DeviceSignals:
    return DeviceSignals(
        fingerprint_id="fp_abc123",
        user_agent="Mozilla/5.0",
        browser_language="en",
        screen_resolution="1440x900",
        timezone_offset=-300,
    )


def _make_behavioral(**overrides) -> BehavioralSignals:
    defaults = {
        "checkout_duration_seconds": 38.0,
        "mouse_movement_present": True,
        "copy_paste_detected": False,
    }
    defaults.update(overrides)
    return BehavioralSignals(**defaults)


def _make_velocity() -> VelocitySignals:
    return VelocitySignals()


def _make_payment() -> PaymentSignals:
    return PaymentSignals(
        bin="411111",
        card_type="credit",
        card_brand="visa",
        amount_usd=49.99,
    )


class TestBehavioralSignals:
    def test_fast_checkout_is_bot(self):
        sig = _make_behavioral(checkout_duration_seconds=3.0)
        assert sig.is_bot_suspected is True

    def test_no_mouse_with_paste_is_bot(self):
        sig = _make_behavioral(
            mouse_movement_present=False,
            copy_paste_detected=True,
        )
        assert sig.is_bot_suspected is True

    def test_normal_checkout_not_bot(self):
        sig = _make_behavioral(
            checkout_duration_seconds=38.0,
            mouse_movement_present=True,
            copy_paste_detected=False,
        )
        assert sig.is_bot_suspected is False

    def test_caller_cannot_override_bot_flag(self):
        sig = BehavioralSignals(
            checkout_duration_seconds=3.0,
            is_bot_suspected=False,
        )
        assert sig.is_bot_suspected is True


class TestIdentityContext:
    def test_cache_key_consistent(self):
        ctx = IdentityContext(
            device=_make_device(),
            behavioral=_make_behavioral(),
            velocity=_make_velocity(),
            payment=_make_payment(),
        )
        key1 = ctx.to_cache_key("test@example.com")
        key2 = ctx.to_cache_key("test@example.com")
        assert key1 == key2
        assert len(key1) == 64  # sha256 hex

    def test_different_email_different_key(self):
        ctx = IdentityContext(
            device=_make_device(),
            behavioral=_make_behavioral(),
            velocity=_make_velocity(),
            payment=_make_payment(),
        )
        assert ctx.to_cache_key("a@b.com") != ctx.to_cache_key("c@d.com")

    def test_immutable(self):
        ctx = IdentityContext(
            device=_make_device(),
            behavioral=_make_behavioral(),
            velocity=_make_velocity(),
            payment=_make_payment(),
        )
        with pytest.raises(ValidationError):
            ctx.risk_score = 99.0

    def test_identity_id_auto_generated(self):
        ctx = IdentityContext(
            device=_make_device(),
            behavioral=_make_behavioral(),
            velocity=_make_velocity(),
            payment=_make_payment(),
        )
        assert ctx.identity_id is not None
        assert len(ctx.identity_id) > 0
