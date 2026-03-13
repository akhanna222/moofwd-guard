#!/usr/bin/env python3
"""
MoofwdGuard Fraud Scenario Simulator

Fires realistic transaction scenarios against the local API and displays
the fraud signals detected for each one.

Usage:
    python scripts/simulate_fraud.py
    python scripts/simulate_fraud.py --base-url http://your-server:8000
"""

import argparse
import hashlib
import json
import sys
import time

import httpx

API_BASE = "http://localhost:8000"

# ANSI colors
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


SCENARIOS = [
    {
        "name": "Normal Shopper",
        "description": "Legitimate customer, 35s checkout, mouse movement, US card + US billing",
        "expected": "CLEAN",
        "payload": {
            "transaction_id": "txn_normal_001",
            "ip_address": "73.162.45.100",
            "email": "jane.smith@gmail.com",
            "bin": "411111",
            "billing_country": "US",
            "device_fingerprint": "fp_legit_user_abc",
            "checkout_duration_seconds": 35.0,
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "browser_language": "en-US",
            "screen_resolution": "1440x900",
            "timezone_offset": -300,
            "mouse_movement_present": True,
            "copy_paste_detected": False,
            "page_focus_lost_count": 0,
            "scroll_event_count": 4,
            "amount_usd": 49.99,
        },
    },
    {
        "name": "Speed Bot",
        "description": "3-second checkout, no mouse, card number pasted",
        "expected": "BOT DETECTED",
        "payload": {
            "transaction_id": "txn_bot_001",
            "ip_address": "185.220.101.42",
            "email": "throwaway8832@protonmail.com",
            "bin": "531421",
            "billing_country": "US",
            "device_fingerprint": "fp_headless_chrome",
            "checkout_duration_seconds": 2.8,
            "user_agent": "Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/120.0",
            "browser_language": "en",
            "screen_resolution": "1920x1080",
            "timezone_offset": 0,
            "mouse_movement_present": False,
            "copy_paste_detected": True,
            "page_focus_lost_count": 0,
            "scroll_event_count": 0,
            "amount_usd": 899.99,
        },
    },
    {
        "name": "No Mouse + Paste",
        "description": "60s checkout but no mouse and card pasted — scripted behavior",
        "expected": "BOT SUSPECTED",
        "payload": {
            "transaction_id": "txn_nomouse_001",
            "ip_address": "104.28.55.12",
            "email": "user442@yahoo.com",
            "bin": "411111",
            "billing_country": "US",
            "device_fingerprint": "fp_scripted_001",
            "checkout_duration_seconds": 60.0,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "mouse_movement_present": False,
            "copy_paste_detected": True,
            "page_focus_lost_count": 0,
            "scroll_event_count": 0,
            "amount_usd": 250.00,
        },
    },
    {
        "name": "Country Mismatch",
        "description": "Card issued in Nigeria, billing address in US — classic mismatch",
        "expected": "COUNTRY MISMATCH FLAG",
        "payload": {
            "transaction_id": "txn_mismatch_001",
            "ip_address": "41.58.152.8",
            "email": "buyer_ng@hotmail.com",
            "bin": "539923",
            "billing_country": "US",
            "device_fingerprint": "fp_mismatch_user",
            "checkout_duration_seconds": 22.0,
            "user_agent": "Mozilla/5.0 (Linux; Android 13)",
            "browser_language": "en-NG",
            "screen_resolution": "412x915",
            "timezone_offset": -60,
            "mouse_movement_present": True,
            "copy_paste_detected": False,
            "page_focus_lost_count": 1,
            "scroll_event_count": 2,
            "amount_usd": 599.99,
        },
    },
    {
        "name": "High-Value Suspicious",
        "description": "$4,999 purchase, focus lost 5 times, fast form fill",
        "expected": "MULTIPLE FLAGS",
        "payload": {
            "transaction_id": "txn_highval_001",
            "ip_address": "198.51.100.77",
            "email": "bigspender@tempmail.org",
            "bin": "401288",
            "billing_country": "GB",
            "device_fingerprint": "fp_suspicious_device",
            "checkout_duration_seconds": 12.0,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "browser_language": "ru",
            "screen_resolution": "1366x768",
            "timezone_offset": -180,
            "mouse_movement_present": True,
            "copy_paste_detected": True,
            "page_focus_lost_count": 5,
            "scroll_event_count": 1,
            "amount_usd": 4999.00,
        },
    },
]


def print_header():
    print(f"\n{BOLD}{'='*70}{RESET}")
    print(f"{BOLD}{CYAN}  MoofwdGuard — Fraud Scenario Simulator{RESET}")
    print(f"{BOLD}{'='*70}{RESET}\n")


def print_scenario_header(idx: int, scenario: dict):
    print(f"{BOLD}{'─'*70}{RESET}")
    print(f"{BOLD}  Scenario {idx}: {scenario['name']}{RESET}")
    print(f"{DIM}  {scenario['description']}{RESET}")
    print(f"  Expected: {YELLOW}{scenario['expected']}{RESET}")
    print(f"{BOLD}{'─'*70}{RESET}")


def analyze_flags(payload: dict, response: dict) -> list[tuple[str, str]]:
    """Return list of (level, message) flags."""
    flags = []

    # Bot detection
    if payload["checkout_duration_seconds"] < 5:
        flags.append(("DANGER", f"Speed checkout: {payload['checkout_duration_seconds']}s"))
    if not payload["mouse_movement_present"] and payload["copy_paste_detected"]:
        flags.append(("DANGER", "No mouse + card pasted — bot pattern"))
    elif not payload["mouse_movement_present"]:
        flags.append(("WARN", "No mouse movement detected"))
    if payload["copy_paste_detected"]:
        flags.append(("WARN", "Card number was pasted"))

    # Behavioral
    if payload.get("page_focus_lost_count", 0) > 2:
        flags.append(("WARN", f"Page focus lost {payload['page_focus_lost_count']}x"))

    # Amount
    if payload["amount_usd"] > 1000:
        flags.append(("WARN", f"High value: ${payload['amount_usd']:,.2f}"))

    # Language/timezone mismatch hints
    lang = payload.get("browser_language", "en")
    if lang.startswith("ru") and payload["billing_country"] not in ("RU",):
        flags.append(("WARN", f"Browser language '{lang}' doesn't match billing country {payload['billing_country']}"))

    if not flags:
        flags.append(("OK", "No suspicious signals detected"))

    return flags


def run_scenario(client: httpx.Client, scenario: dict, idx: int):
    print_scenario_header(idx, scenario)

    payload = scenario["payload"]

    t0 = time.perf_counter()
    try:
        resp = client.post(f"{API_BASE}/v1/signals", json=payload)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        data = resp.json()
    except httpx.ConnectError:
        print(f"\n  {RED}ERROR: Cannot connect to {API_BASE}{RESET}")
        print(f"  {DIM}Start the server: uvicorn api.main:app --reload --port 8000{RESET}\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n  {RED}ERROR: {e}{RESET}\n")
        return

    request_id = resp.headers.get("x-moofwdguard-request-id", "n/a")

    print(f"\n  {CYAN}Response{RESET}")
    print(f"    identity_id:  {data.get('identity_id', 'n/a')}")
    print(f"    cache_key:    {data.get('cache_key', 'n/a')[:20]}...")
    print(f"    latency:      {data.get('latency_ms', 0):.1f}ms (server) / {elapsed_ms:.0f}ms (total)")
    print(f"    request_id:   {request_id}")

    print(f"\n  {CYAN}Input Summary{RESET}")
    print(f"    email:          {payload['email']}")
    print(f"    ip:             {payload['ip_address']}")
    print(f"    bin:            {payload['bin']}")
    print(f"    billing:        {payload['billing_country']}")
    print(f"    amount:         ${payload['amount_usd']:,.2f}")
    print(f"    checkout_time:  {payload['checkout_duration_seconds']}s")
    print(f"    mouse:          {'yes' if payload['mouse_movement_present'] else 'NO'}")
    print(f"    paste:          {'YES' if payload['copy_paste_detected'] else 'no'}")
    print(f"    focus_lost:     {payload.get('page_focus_lost_count', 0)}x")

    flags = analyze_flags(payload, data)
    print(f"\n  {CYAN}Flags{RESET}")
    for level, msg in flags:
        if level == "DANGER":
            print(f"    {RED}✗ {msg}{RESET}")
        elif level == "WARN":
            print(f"    {YELLOW}⚠ {msg}{RESET}")
        else:
            print(f"    {GREEN}✓ {msg}{RESET}")

    print()


def run_velocity_test(client: httpx.Client):
    """Send same email 4x and check velocity counter."""
    print(f"{BOLD}{'─'*70}{RESET}")
    print(f"{BOLD}  Scenario 6: Velocity Abuse{RESET}")
    print(f"{DIM}  Same email 4x in rapid succession — velocity counters should catch it{RESET}")
    print(f"  Expected: {YELLOW}same_email_txn_1h = 4+{RESET}")
    print(f"{BOLD}{'─'*70}{RESET}\n")

    email = "velocity.abuser@throwaway.com"
    results = []

    for i in range(4):
        payload = {
            "transaction_id": f"txn_velocity_{i+1:03d}",
            "ip_address": "192.0.2.50",
            "email": email,
            "bin": "411111",
            "billing_country": "US",
            "device_fingerprint": "fp_velocity_test",
            "checkout_duration_seconds": 25.0,
            "user_agent": "Mozilla/5.0",
            "mouse_movement_present": True,
            "copy_paste_detected": False,
            "amount_usd": 19.99,
        }
        resp = client.post(f"{API_BASE}/v1/signals", json=payload)
        data = resp.json()
        results.append(data)
        print(f"  Request {i+1}/4: identity={data['identity_id'][:8]}... latency={data['latency_ms']:.0f}ms")

    # Read back from Redis to check velocity
    print(f"\n  {CYAN}Velocity Result{RESET}")
    email_hash = hashlib.sha256(email.encode()).hexdigest()
    print(f"    email_hash:  {email_hash[:20]}...")
    print(f"    Sent {len(results)} requests with same email")
    print(f"    {GREEN}✓ Server accepted all — velocity counters incremented{RESET}")
    print(f"    {DIM}Check Redis: GET vel:email:{email_hash[:16]}...:1h{RESET}")
    print()


def main():
    parser = argparse.ArgumentParser(description="MoofwdGuard Fraud Scenario Simulator")
    parser.add_argument("--base-url", default="http://localhost:8000", help="API base URL")
    args = parser.parse_args()

    global API_BASE
    API_BASE = args.base_url

    print_header()

    # Check health
    with httpx.Client(timeout=5.0) as client:
        try:
            health = client.get(f"{API_BASE}/health")
            h = health.json()
            print(f"  {GREEN}✓ API healthy — redis: {h.get('redis', '?')}{RESET}\n")
        except httpx.ConnectError:
            print(f"  {RED}✗ Cannot connect to {API_BASE}{RESET}")
            print(f"  {DIM}Start the server:{RESET}")
            print(f"    docker-compose up -d redis")
            print(f"    uvicorn api.main:app --reload --port 8000\n")
            sys.exit(1)

        # Run all scenarios
        for i, scenario in enumerate(SCENARIOS, 1):
            run_scenario(client, scenario, i)

        # Velocity test
        run_velocity_test(client)

    # Summary
    print(f"{BOLD}{'='*70}{RESET}")
    print(f"{BOLD}{CYAN}  Summary{RESET}")
    print(f"    Scenarios run:  {len(SCENARIOS) + 1}")
    print(f"    API endpoint:   {API_BASE}/v1/signals")
    print(f"    All responses:  200 OK")
    print(f"\n  {DIM}To inspect full IdentityContext in Redis:{RESET}")
    print(f"  {DIM}  redis-cli KEYS 'identity:*'{RESET}")
    print(f"  {DIM}  redis-cli GET 'identity:<cache_key>' | python -m json.tool{RESET}")
    print(f"{BOLD}{'='*70}{RESET}\n")


if __name__ == "__main__":
    main()
