#!/usr/bin/env python3
"""
MoofwdGuard — Sample Transaction Generator & Runner

Generates realistic transaction data across different risk profiles
and fires them against the API. Shows a live dashboard of results.

Usage:
    python scripts/sample_transactions.py                  # run all 20 samples
    python scripts/sample_transactions.py --profile legit  # only legit transactions
    python scripts/sample_transactions.py --profile fraud  # only fraud patterns
    python scripts/sample_transactions.py --profile mixed  # realistic mix
    python scripts/sample_transactions.py --count 50       # generate 50 random transactions
    python scripts/sample_transactions.py --interactive     # step through one by one
    python scripts/sample_transactions.py --base-url http://your-server:8000
"""

import argparse
import json
import random
import string
import sys
import time
from dataclasses import dataclass

import httpx

# ANSI
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"
BG_RED = "\033[41m"
BG_GREEN = "\033[42m"
BG_YELLOW = "\033[43m"

API_BASE = "http://localhost:8000"

# ─── Realistic Data Pools ────────────────────────────────────────────

LEGIT_EMAILS = [
    "sarah.johnson@gmail.com",
    "mike.chen@outlook.com",
    "emma.williams@yahoo.com",
    "david.kumar@gmail.com",
    "lisa.park@icloud.com",
    "james.taylor@hotmail.com",
    "anna.mueller@gmail.com",
    "carlos.garcia@gmail.com",
    "yuki.tanaka@outlook.jp",
    "rachel.green@gmail.com",
]

FRAUD_EMAILS = [
    "xdr4432@protonmail.com",
    "buy.now.99@tempmail.org",
    "a@a.com",
    "test123@guerrillamail.com",
    "noname@throwaway.email",
    "asdf@yopmail.com",
    "random8832@sharklasers.com",
    "x@x.com",
]

USER_AGENTS = {
    "legit": [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    ],
    "fraud": [
        "Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/120.0.0.0",
        "python-requests/2.31.0",
        "Mozilla/5.0 (compatible; Googlebot/2.1)",
        "curl/8.4.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    ],
}

SCREENS = {
    "desktop": ["1920x1080", "2560x1440", "1440x900", "1366x768", "3840x2160"],
    "mobile": ["390x844", "412x915", "360x800", "414x896", "393x873"],
}

# BIN → (card_brand, typical_country)
BINS = {
    "legit": [
        ("411111", "visa", "US"),
        ("430000", "visa", "US"),
        ("510000", "mastercard", "US"),
        ("540000", "mastercard", "US"),
        ("370000", "amex", "US"),
        ("421345", "visa", "GB"),
        ("520000", "mastercard", "CA"),
        ("401288", "visa", "AU"),
    ],
    "fraud": [
        ("539923", "mastercard", "NG"),
        ("531421", "mastercard", "RU"),
        ("411111", "visa", "US"),  # stolen US card
        ("476173", "visa", "BR"),
        ("450000", "visa", "PK"),
    ],
}

LEGIT_IPS = [
    ("73.162.45.100", "US"),
    ("68.45.128.77", "US"),
    ("99.234.55.12", "US"),
    ("82.132.45.88", "GB"),
    ("70.71.232.14", "CA"),
    ("1.128.45.67", "AU"),
    ("85.214.132.77", "DE"),
    ("210.140.55.33", "JP"),
]

FRAUD_IPS = [
    ("185.220.101.42", "TOR"),
    ("45.153.160.130", "RU"),
    ("41.58.152.8", "NG"),
    ("103.216.220.5", "VN"),
    ("91.232.105.44", "UA"),
    ("185.56.80.11", "NL"),  # VPN
    ("198.51.100.77", "PROXY"),
]


@dataclass
class TransactionResult:
    name: str
    profile: str
    payload: dict
    response: dict | None
    latency_ms: float
    flags: list[str]
    error: str | None = None


# ─── Transaction Generators ─────────────────────────────────────────


def gen_legit_transaction(idx: int) -> tuple[str, dict]:
    """Generate a realistic legitimate transaction."""
    email = random.choice(LEGIT_EMAILS)
    ip, ip_country = random.choice(LEGIT_IPS)
    bin_num, brand, card_country = random.choice(BINS["legit"])
    ua = random.choice(USER_AGENTS["legit"])
    is_mobile = "iPhone" in ua or "Android" in ua
    screen = random.choice(SCREENS["mobile"] if is_mobile else SCREENS["desktop"])

    # Legit users: 20-90s checkout, mouse movement, rarely paste
    checkout = round(random.uniform(20.0, 90.0), 1)
    amount = round(random.choice([9.99, 19.99, 29.99, 49.99, 79.99, 99.99, 149.99, 199.99]), 2)

    name = f"Legit #{idx}: {email.split('@')[0]} — ${amount}"
    return name, {
        "transaction_id": f"txn_legit_{idx:04d}",
        "ip_address": ip,
        "email": email,
        "bin": bin_num,
        "billing_country": card_country,
        "device_fingerprint": f"fp_legit_{random.randbytes(4).hex()}",
        "checkout_duration_seconds": checkout,
        "user_agent": ua,
        "browser_language": "en-US",
        "screen_resolution": screen,
        "timezone_offset": random.choice([-300, -360, -420, -480, 0, 60]),
        "mouse_movement_present": True,
        "copy_paste_detected": False,
        "page_focus_lost_count": random.randint(0, 1),
        "scroll_event_count": random.randint(2, 8),
        "amount_usd": amount,
    }


def gen_bot_transaction(idx: int) -> tuple[str, dict]:
    """Generate a bot/automated transaction."""
    email = random.choice(FRAUD_EMAILS)
    ip, _ = random.choice(FRAUD_IPS)
    bin_num, brand, card_country = random.choice(BINS["fraud"])
    ua = random.choice(USER_AGENTS["fraud"])

    checkout = round(random.uniform(0.5, 4.5), 1)
    amount = round(random.uniform(200.0, 2000.0), 2)

    name = f"Bot #{idx}: {checkout}s checkout — ${amount}"
    return name, {
        "transaction_id": f"txn_bot_{idx:04d}",
        "ip_address": ip,
        "email": email,
        "bin": bin_num,
        "billing_country": "US",
        "device_fingerprint": f"fp_bot_{random.randbytes(4).hex()}",
        "checkout_duration_seconds": checkout,
        "user_agent": ua,
        "browser_language": "en",
        "screen_resolution": "1920x1080",
        "timezone_offset": 0,
        "mouse_movement_present": False,
        "copy_paste_detected": True,
        "page_focus_lost_count": 0,
        "scroll_event_count": 0,
        "amount_usd": amount,
    }


def gen_card_tester(idx: int) -> tuple[str, dict]:
    """Card testing pattern — rapid small amounts, same device."""
    email = f"tester{random.randint(1,99)}@tempmail.org"
    ip, _ = random.choice(FRAUD_IPS)
    bin_num = random.choice(["411111", "510000", "430000"])

    amount = round(random.choice([0.50, 1.00, 1.50, 2.00, 5.00]), 2)

    name = f"Card Test #{idx}: ${amount} micro-charge"
    return name, {
        "transaction_id": f"txn_cardtest_{idx:04d}",
        "ip_address": ip,
        "email": email,
        "bin": bin_num,
        "billing_country": "US",
        "device_fingerprint": "fp_card_tester_same_device",
        "checkout_duration_seconds": round(random.uniform(3.0, 8.0), 1),
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "browser_language": "en",
        "screen_resolution": "1920x1080",
        "timezone_offset": 0,
        "mouse_movement_present": random.choice([True, False]),
        "copy_paste_detected": True,
        "page_focus_lost_count": 0,
        "scroll_event_count": 0,
        "amount_usd": amount,
    }


def gen_country_mismatch(idx: int) -> tuple[str, dict]:
    """Card issued in one country, billing in another."""
    email = random.choice(FRAUD_EMAILS + LEGIT_EMAILS[:3])
    ip, ip_loc = random.choice(FRAUD_IPS[:4])
    bin_num, brand, card_country = random.choice(BINS["fraud"][:3])

    billing = random.choice(["US", "GB", "CA"])
    amount = round(random.uniform(100.0, 800.0), 2)

    name = f"Mismatch #{idx}: card={card_country} billing={billing} — ${amount}"
    return name, {
        "transaction_id": f"txn_mismatch_{idx:04d}",
        "ip_address": ip,
        "email": email,
        "bin": bin_num,
        "billing_country": billing,
        "device_fingerprint": f"fp_mismatch_{random.randbytes(4).hex()}",
        "checkout_duration_seconds": round(random.uniform(15.0, 45.0), 1),
        "user_agent": random.choice(USER_AGENTS["legit"]),
        "browser_language": random.choice(["en-NG", "ru-RU", "pt-BR", "en"]),
        "screen_resolution": random.choice(SCREENS["mobile"]),
        "timezone_offset": random.choice([-60, -180, -180, 60]),
        "mouse_movement_present": True,
        "copy_paste_detected": random.choice([True, False]),
        "page_focus_lost_count": random.randint(0, 3),
        "scroll_event_count": random.randint(0, 4),
        "amount_usd": amount,
    }


def gen_friendly_fraud(idx: int) -> tuple[str, dict]:
    """Looks legit but has subtle red flags — high value, focus switching."""
    email = random.choice(LEGIT_EMAILS)
    ip, ip_country = random.choice(LEGIT_IPS[:3])
    bin_num, brand, card_country = random.choice(BINS["legit"][:3])

    amount = round(random.uniform(500.0, 5000.0), 2)

    name = f"Friendly Fraud #{idx}: {email.split('@')[0]} — ${amount}"
    return name, {
        "transaction_id": f"txn_friendly_{idx:04d}",
        "ip_address": ip,
        "email": email,
        "bin": bin_num,
        "billing_country": card_country,
        "device_fingerprint": f"fp_friendly_{random.randbytes(4).hex()}",
        "checkout_duration_seconds": round(random.uniform(10.0, 25.0), 1),
        "user_agent": random.choice(USER_AGENTS["legit"]),
        "browser_language": "en-US",
        "screen_resolution": random.choice(SCREENS["desktop"]),
        "timezone_offset": -300,
        "mouse_movement_present": True,
        "copy_paste_detected": True,
        "page_focus_lost_count": random.randint(3, 8),
        "scroll_event_count": random.randint(0, 2),
        "amount_usd": amount,
    }


# ─── Curated Sample Set ─────────────────────────────────────────────

CURATED_SAMPLES = [
    # --- Legit ---
    ("Legit: Regular US shopper",
     {"transaction_id": "txn_sample_001", "ip_address": "73.162.45.100", "email": "sarah.johnson@gmail.com",
      "bin": "411111", "billing_country": "US", "device_fingerprint": "fp_sarah_macbook",
      "checkout_duration_seconds": 45.2, "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
      "browser_language": "en-US", "screen_resolution": "1440x900", "timezone_offset": -300,
      "mouse_movement_present": True, "copy_paste_detected": False,
      "page_focus_lost_count": 0, "scroll_event_count": 5, "amount_usd": 34.99}),

    ("Legit: Mobile UK shopper",
     {"transaction_id": "txn_sample_002", "ip_address": "82.132.45.88", "email": "emma.williams@yahoo.com",
      "bin": "421345", "billing_country": "GB", "device_fingerprint": "fp_emma_iphone",
      "checkout_duration_seconds": 62.0, "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X)",
      "browser_language": "en-GB", "screen_resolution": "390x844", "timezone_offset": 0,
      "mouse_movement_present": False, "copy_paste_detected": False,
      "page_focus_lost_count": 1, "scroll_event_count": 3, "amount_usd": 19.99}),

    ("Legit: Canadian returning customer",
     {"transaction_id": "txn_sample_003", "ip_address": "70.71.232.14", "email": "mike.chen@outlook.com",
      "bin": "520000", "billing_country": "CA", "device_fingerprint": "fp_mike_desktop",
      "checkout_duration_seconds": 28.5, "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      "browser_language": "en-CA", "screen_resolution": "2560x1440", "timezone_offset": -300,
      "mouse_movement_present": True, "copy_paste_detected": False,
      "page_focus_lost_count": 0, "scroll_event_count": 6, "amount_usd": 149.99}),

    ("Legit: Slow elderly shopper",
     {"transaction_id": "txn_sample_004", "ip_address": "99.234.55.12", "email": "rachel.green@gmail.com",
      "bin": "370000", "billing_country": "US", "device_fingerprint": "fp_rachel_ipad",
      "checkout_duration_seconds": 180.0, "user_agent": "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X)",
      "browser_language": "en-US", "screen_resolution": "1024x1366", "timezone_offset": -480,
      "mouse_movement_present": True, "copy_paste_detected": False,
      "page_focus_lost_count": 3, "scroll_event_count": 12, "amount_usd": 59.99}),

    # --- Bots ---
    ("Bot: Headless Chrome speed run",
     {"transaction_id": "txn_sample_005", "ip_address": "185.220.101.42", "email": "xdr4432@protonmail.com",
      "bin": "531421", "billing_country": "US", "device_fingerprint": "fp_headless_001",
      "checkout_duration_seconds": 1.2, "user_agent": "Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/120.0.0.0",
      "browser_language": "en", "screen_resolution": "1920x1080", "timezone_offset": 0,
      "mouse_movement_present": False, "copy_paste_detected": True,
      "page_focus_lost_count": 0, "scroll_event_count": 0, "amount_usd": 1299.99}),

    ("Bot: Python script attack",
     {"transaction_id": "txn_sample_006", "ip_address": "45.153.160.130", "email": "a@a.com",
      "bin": "411111", "billing_country": "US", "device_fingerprint": "fp_python_bot",
      "checkout_duration_seconds": 0.3, "user_agent": "python-requests/2.31.0",
      "browser_language": "en", "screen_resolution": "1920x1080", "timezone_offset": 0,
      "mouse_movement_present": False, "copy_paste_detected": True,
      "page_focus_lost_count": 0, "scroll_event_count": 0, "amount_usd": 499.99}),

    ("Bot: Curl probe",
     {"transaction_id": "txn_sample_007", "ip_address": "91.232.105.44", "email": "test123@guerrillamail.com",
      "bin": "510000", "billing_country": "US", "device_fingerprint": "fp_curl_probe",
      "checkout_duration_seconds": 0.1, "user_agent": "curl/8.4.0",
      "browser_language": "en", "screen_resolution": "unknown", "timezone_offset": 0,
      "mouse_movement_present": False, "copy_paste_detected": False,
      "page_focus_lost_count": 0, "scroll_event_count": 0, "amount_usd": 1.00}),

    # --- Card Testing ---
    ("Card Testing: $1 micro-charge #1",
     {"transaction_id": "txn_sample_008", "ip_address": "103.216.220.5", "email": "tester77@tempmail.org",
      "bin": "411111", "billing_country": "US", "device_fingerprint": "fp_card_tester_A",
      "checkout_duration_seconds": 4.5, "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
      "browser_language": "en", "screen_resolution": "1920x1080", "timezone_offset": 0,
      "mouse_movement_present": False, "copy_paste_detected": True,
      "page_focus_lost_count": 0, "scroll_event_count": 0, "amount_usd": 1.00}),

    ("Card Testing: $0.50 micro-charge #2",
     {"transaction_id": "txn_sample_009", "ip_address": "103.216.220.5", "email": "tester77@tempmail.org",
      "bin": "510000", "billing_country": "US", "device_fingerprint": "fp_card_tester_A",
      "checkout_duration_seconds": 3.8, "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
      "browser_language": "en", "screen_resolution": "1920x1080", "timezone_offset": 0,
      "mouse_movement_present": False, "copy_paste_detected": True,
      "page_focus_lost_count": 0, "scroll_event_count": 0, "amount_usd": 0.50}),

    ("Card Testing: $2 micro-charge #3",
     {"transaction_id": "txn_sample_010", "ip_address": "103.216.220.5", "email": "tester77@tempmail.org",
      "bin": "430000", "billing_country": "US", "device_fingerprint": "fp_card_tester_A",
      "checkout_duration_seconds": 4.1, "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
      "browser_language": "en", "screen_resolution": "1920x1080", "timezone_offset": 0,
      "mouse_movement_present": False, "copy_paste_detected": True,
      "page_focus_lost_count": 0, "scroll_event_count": 0, "amount_usd": 2.00}),

    # --- Country Mismatch ---
    ("Mismatch: Nigerian card → US billing",
     {"transaction_id": "txn_sample_011", "ip_address": "41.58.152.8", "email": "buy.now.99@tempmail.org",
      "bin": "539923", "billing_country": "US", "device_fingerprint": "fp_mismatch_ng",
      "checkout_duration_seconds": 25.0, "user_agent": "Mozilla/5.0 (Linux; Android 13)",
      "browser_language": "en-NG", "screen_resolution": "412x915", "timezone_offset": -60,
      "mouse_movement_present": True, "copy_paste_detected": False,
      "page_focus_lost_count": 1, "scroll_event_count": 2, "amount_usd": 599.99}),

    ("Mismatch: Russian card → GB billing",
     {"transaction_id": "txn_sample_012", "ip_address": "45.153.160.130", "email": "noname@throwaway.email",
      "bin": "531421", "billing_country": "GB", "device_fingerprint": "fp_mismatch_ru",
      "checkout_duration_seconds": 18.0, "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
      "browser_language": "ru-RU", "screen_resolution": "1366x768", "timezone_offset": -180,
      "mouse_movement_present": True, "copy_paste_detected": True,
      "page_focus_lost_count": 2, "scroll_event_count": 1, "amount_usd": 799.99}),

    # --- Friendly Fraud ---
    ("Friendly Fraud: High value + tab switching",
     {"transaction_id": "txn_sample_013", "ip_address": "73.162.45.100", "email": "david.kumar@gmail.com",
      "bin": "411111", "billing_country": "US", "device_fingerprint": "fp_david_chrome",
      "checkout_duration_seconds": 15.0, "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
      "browser_language": "en-US", "screen_resolution": "1440x900", "timezone_offset": -300,
      "mouse_movement_present": True, "copy_paste_detected": True,
      "page_focus_lost_count": 6, "scroll_event_count": 1, "amount_usd": 2499.99}),

    ("Friendly Fraud: Legit-looking but huge amount",
     {"transaction_id": "txn_sample_014", "ip_address": "68.45.128.77", "email": "lisa.park@icloud.com",
      "bin": "540000", "billing_country": "US", "device_fingerprint": "fp_lisa_mac",
      "checkout_duration_seconds": 22.0, "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
      "browser_language": "en-US", "screen_resolution": "2560x1440", "timezone_offset": -480,
      "mouse_movement_present": True, "copy_paste_detected": False,
      "page_focus_lost_count": 4, "scroll_event_count": 2, "amount_usd": 4999.00}),

    # --- Edge Cases ---
    ("Edge: Mobile — no mouse is normal",
     {"transaction_id": "txn_sample_015", "ip_address": "68.45.128.77", "email": "carlos.garcia@gmail.com",
      "bin": "411111", "billing_country": "US", "device_fingerprint": "fp_carlos_android",
      "checkout_duration_seconds": 55.0, "user_agent": "Mozilla/5.0 (Linux; Android 13; Pixel 7)",
      "browser_language": "es-US", "screen_resolution": "412x915", "timezone_offset": -360,
      "mouse_movement_present": False, "copy_paste_detected": False,
      "page_focus_lost_count": 2, "scroll_event_count": 4, "amount_usd": 24.99}),

    ("Edge: Gift purchase — different billing",
     {"transaction_id": "txn_sample_016", "ip_address": "85.214.132.77", "email": "anna.mueller@gmail.com",
      "bin": "421345", "billing_country": "DE", "device_fingerprint": "fp_anna_firefox",
      "checkout_duration_seconds": 40.0, "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
      "browser_language": "de-DE", "screen_resolution": "1920x1080", "timezone_offset": -60,
      "mouse_movement_present": True, "copy_paste_detected": False,
      "page_focus_lost_count": 1, "scroll_event_count": 7, "amount_usd": 89.99}),

    # --- Velocity Burst ---
    ("Velocity: Rapid purchase #1 of 4",
     {"transaction_id": "txn_sample_017", "ip_address": "185.56.80.11", "email": "asdf@yopmail.com",
      "bin": "411111", "billing_country": "US", "device_fingerprint": "fp_velocity_burst",
      "checkout_duration_seconds": 8.0, "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
      "browser_language": "en", "screen_resolution": "1920x1080", "timezone_offset": 0,
      "mouse_movement_present": True, "copy_paste_detected": True,
      "page_focus_lost_count": 0, "scroll_event_count": 0, "amount_usd": 149.99}),

    ("Velocity: Rapid purchase #2 of 4",
     {"transaction_id": "txn_sample_018", "ip_address": "185.56.80.11", "email": "asdf@yopmail.com",
      "bin": "510000", "billing_country": "US", "device_fingerprint": "fp_velocity_burst",
      "checkout_duration_seconds": 6.0, "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
      "browser_language": "en", "screen_resolution": "1920x1080", "timezone_offset": 0,
      "mouse_movement_present": True, "copy_paste_detected": True,
      "page_focus_lost_count": 0, "scroll_event_count": 0, "amount_usd": 199.99}),

    ("Velocity: Rapid purchase #3 of 4",
     {"transaction_id": "txn_sample_019", "ip_address": "185.56.80.11", "email": "asdf@yopmail.com",
      "bin": "430000", "billing_country": "US", "device_fingerprint": "fp_velocity_burst",
      "checkout_duration_seconds": 5.5, "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
      "browser_language": "en", "screen_resolution": "1920x1080", "timezone_offset": 0,
      "mouse_movement_present": True, "copy_paste_detected": True,
      "page_focus_lost_count": 0, "scroll_event_count": 0, "amount_usd": 249.99}),

    ("Velocity: Rapid purchase #4 of 4",
     {"transaction_id": "txn_sample_020", "ip_address": "185.56.80.11", "email": "asdf@yopmail.com",
      "bin": "540000", "billing_country": "US", "device_fingerprint": "fp_velocity_burst",
      "checkout_duration_seconds": 7.0, "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
      "browser_language": "en", "screen_resolution": "1920x1080", "timezone_offset": 0,
      "mouse_movement_present": True, "copy_paste_detected": True,
      "page_focus_lost_count": 0, "scroll_event_count": 0, "amount_usd": 179.99}),
]


# ─── Analysis ────────────────────────────────────────────────────────

def analyze(payload: dict) -> list[tuple[str, str]]:
    flags = []

    # Bot
    if payload["checkout_duration_seconds"] < 5:
        flags.append(("DANGER", f"Speed checkout: {payload['checkout_duration_seconds']}s"))
    if not payload["mouse_movement_present"] and payload.get("copy_paste_detected"):
        flags.append(("DANGER", "No mouse + paste → bot pattern"))
    elif not payload["mouse_movement_present"]:
        ua = payload.get("user_agent", "")
        if "iPhone" in ua or "Android" in ua or "iPad" in ua:
            flags.append(("OK", "Mobile device — no mouse expected"))
        else:
            flags.append(("WARN", "No mouse movement (desktop)"))
    if payload.get("copy_paste_detected"):
        flags.append(("WARN", "Card number pasted"))

    # Suspicious UA
    ua = payload.get("user_agent", "")
    for bad in ["HeadlessChrome", "python-requests", "curl/", "Googlebot"]:
        if bad in ua:
            flags.append(("DANGER", f"Suspicious user agent: {bad}"))
            break

    # Behavioral
    focus = payload.get("page_focus_lost_count", 0)
    if focus > 4:
        flags.append(("WARN", f"Tab switched {focus}x"))
    elif focus > 2:
        flags.append(("INFO", f"Tab switched {focus}x"))

    # Amount
    amt = payload["amount_usd"]
    if amt > 2000:
        flags.append(("WARN", f"Very high value: ${amt:,.2f}"))
    elif amt > 500:
        flags.append(("INFO", f"High value: ${amt:,.2f}"))
    if amt < 3:
        flags.append(("WARN", f"Micro-charge: ${amt:.2f} — possible card testing"))

    # Language mismatch
    lang = payload.get("browser_language", "en")
    billing = payload["billing_country"]
    mismatches = {
        "ru": ["RU"], "de": ["DE", "AT", "CH"], "ja": ["JP"],
        "pt": ["BR", "PT"], "es": ["ES", "MX", "AR"],
    }
    lang_prefix = lang.split("-")[0]
    if lang_prefix in mismatches and billing not in mismatches[lang_prefix]:
        flags.append(("WARN", f"Language '{lang}' vs billing '{billing}'"))

    if not flags:
        flags.append(("OK", "Clean — no flags"))

    return flags


# ─── Display ─────────────────────────────────────────────────────────

def print_result(idx: int, total: int, name: str, payload: dict, resp: dict, latency: float, flags: list):
    danger_count = sum(1 for l, _ in flags if l == "DANGER")
    warn_count = sum(1 for l, _ in flags if l == "WARN")

    if danger_count > 0:
        risk_label = f"{BG_RED} HIGH RISK {RESET}"
    elif warn_count > 0:
        risk_label = f"{BG_YELLOW}\033[30m MEDIUM {RESET}"
    else:
        risk_label = f"{BG_GREEN}\033[30m LOW RISK {RESET}"

    print(f"\n{DIM}[{idx}/{total}]{RESET} {BOLD}{name}{RESET}  {risk_label}")
    print(f"  {DIM}identity: {resp.get('identity_id', 'n/a')[:16]}...  latency: {resp.get('latency_ms', 0):.0f}ms  total: {latency:.0f}ms{RESET}")

    for level, msg in flags:
        match level:
            case "DANGER":
                print(f"  {RED}  ✗ {msg}{RESET}")
            case "WARN":
                print(f"  {YELLOW}  ⚠ {msg}{RESET}")
            case "INFO":
                print(f"  {CYAN}  ○ {msg}{RESET}")
            case "OK":
                print(f"  {GREEN}  ✓ {msg}{RESET}")


# ─── Main ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="MoofwdGuard Sample Transaction Runner")
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--profile", choices=["all", "legit", "fraud", "mixed"], default="all",
                        help="Transaction profile to run")
    parser.add_argument("--count", type=int, default=0,
                        help="Generate N random transactions instead of curated set")
    parser.add_argument("--interactive", action="store_true",
                        help="Pause between transactions")
    args = parser.parse_args()

    global API_BASE
    API_BASE = args.base_url

    # Build transaction list
    if args.count > 0:
        generators = {
            "legit": [gen_legit_transaction],
            "fraud": [gen_bot_transaction, gen_card_tester, gen_country_mismatch],
            "mixed": [gen_legit_transaction, gen_legit_transaction, gen_bot_transaction,
                      gen_card_tester, gen_country_mismatch, gen_friendly_fraud],
            "all": [gen_legit_transaction, gen_legit_transaction, gen_bot_transaction,
                    gen_card_tester, gen_country_mismatch, gen_friendly_fraud],
        }
        gens = generators[args.profile]
        samples = []
        for i in range(args.count):
            gen = random.choice(gens)
            name, payload = gen(i + 1)
            samples.append((name, payload))
    else:
        samples = list(CURATED_SAMPLES)
        if args.profile == "legit":
            samples = [(n, p) for n, p in samples if n.startswith("Legit") or n.startswith("Edge")]
        elif args.profile == "fraud":
            samples = [(n, p) for n, p in samples
                       if any(n.startswith(x) for x in ["Bot", "Card Testing", "Mismatch", "Velocity"])]

    # Header
    print(f"\n{BOLD}{'═'*70}{RESET}")
    print(f"{BOLD}{CYAN}  MoofwdGuard — Sample Transaction Runner{RESET}")
    print(f"  {DIM}{len(samples)} transactions · profile: {args.profile} · {API_BASE}{RESET}")
    print(f"{BOLD}{'═'*70}{RESET}")

    # Health check
    with httpx.Client(timeout=5.0) as client:
        try:
            h = client.get(f"{API_BASE}/health").json()
            print(f"\n  {GREEN}✓ API healthy — redis: {h.get('redis')}{RESET}")
        except httpx.ConnectError:
            print(f"\n  {RED}✗ Cannot connect to {API_BASE}{RESET}")
            print(f"  {DIM}docker-compose up -d redis && uvicorn api.main:app --reload{RESET}\n")
            sys.exit(1)

        stats = {"high": 0, "medium": 0, "low": 0, "total_latency": 0.0}

        for i, (name, payload) in enumerate(samples, 1):
            if args.interactive:
                input(f"\n  {DIM}Press Enter for next transaction...{RESET}")

            t0 = time.perf_counter()
            try:
                resp = client.post(f"{API_BASE}/v1/signals", json=payload)
                latency = (time.perf_counter() - t0) * 1000
                data = resp.json()
            except Exception as e:
                print(f"\n  {RED}ERROR on {name}: {e}{RESET}")
                continue

            flags = analyze(payload)
            print_result(i, len(samples), name, payload, data, latency, flags)

            danger_count = sum(1 for l, _ in flags if l == "DANGER")
            warn_count = sum(1 for l, _ in flags if l == "WARN")
            if danger_count:
                stats["high"] += 1
            elif warn_count:
                stats["medium"] += 1
            else:
                stats["low"] += 1
            stats["total_latency"] += latency

        # Summary
        total = len(samples)
        avg_latency = stats["total_latency"] / total if total else 0

        print(f"\n{BOLD}{'═'*70}{RESET}")
        print(f"{BOLD}{CYAN}  Summary{RESET}")
        print(f"  ┌─────────────────────────────────────────┐")
        print(f"  │  Total transactions:  {total:>4}              │")
        print(f"  │  {RED}High risk:          {stats['high']:>4}{RESET}              │")
        print(f"  │  {YELLOW}Medium risk:        {stats['medium']:>4}{RESET}              │")
        print(f"  │  {GREEN}Low risk:           {stats['low']:>4}{RESET}              │")
        print(f"  │  Avg latency:        {avg_latency:>5.0f}ms           │")
        print(f"  └─────────────────────────────────────────┘")
        print(f"\n  {DIM}Redis keys: redis-cli KEYS 'vel:*' | wc -l{RESET}")
        print(f"  {DIM}Identities: redis-cli KEYS 'identity:*' | wc -l{RESET}")
        print(f"{BOLD}{'═'*70}{RESET}\n")


if __name__ == "__main__":
    main()
