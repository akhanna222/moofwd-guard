from pydantic import BaseModel, EmailStr, Field, IPvAnyAddress
import re


class TransactionRequest(BaseModel):
    transaction_id: str
    ip_address: str
    email: EmailStr
    bin: str = Field(pattern=r"^[0-9]{6}$")
    billing_country: str
    device_fingerprint: str
    checkout_duration_seconds: float
    user_agent: str
    browser_language: str = "en"
    screen_resolution: str = "unknown"
    timezone_offset: int = 0
    webgl_hash: str | None = None
    mouse_movement_present: bool = True
    copy_paste_detected: bool = False
    page_focus_lost_count: int = 0
    scroll_event_count: int = 0
    amount_usd: float = 0.0
