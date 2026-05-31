# Deployment & Migration Guide — F18 / F19 / F20

Covers the security-hardening batch (F18/F19), the AppsFlyer MMP integration (F20), and the follow-up that set **both** admin and publisher idle timeouts to 5 minutes. Builds on top of F1–F17 (see `DEPLOY-F1-F17.md`).

Local test status before this guide: `sec.test.js` 24/24, `mmp.test.js` 14/14, `e2e.test.js` (F1–F17 regression) 63/63 — all green on a fresh DB.

> **Release gate:** this has NOT been deployed. It requires UI/UX review and Security & QA sign-off before any production deploy.

## TL;DR
- **Code changed:** `server.js`, `db.js`. New test files: `sec.test.js`, `mmp.test.js`.
- **Dependencies:** none added — no `npm install` needed.
- **Schema migration:** automatic on app start (`db.js`), additive + idempotent.
- **Must-do in prod:** take a DB backup; **set `MMP_ENCRYPTION_KEY`** (else MMP tokens are stored in plaintext).
- **Heads-up:** sessions now idle out after **5 minutes** (admin *and* publisher); `SameSite=Strict`; **HSTS is now sent** (sticky on clients — see Rollback); `/postback/*` has its own 300/min limit.

---

## 1. Pre-deploy: back up the database
```bash
sqlite3 /home/komorebi/komorebi-affiliate/affiliate.db ".backup '/home/komorebi/affiliate-pre-F18-F20.db'"
```

## 2. Schema migrations (automatic on boot; all additive + idempotent)
Guarded `ALTER TABLE` (via `PRAGMA table_info`) and `CREATE TABLE IF NOT EXISTS` — safe to run repeatedly.

**New columns on `advertisers`:**
- `postback_secret` (TEXT) — F18 HMAC secret (nullable; null = unsigned postbacks accepted)
- `mmp_type` (TEXT, default `'none'`), `mmp_app_id` (TEXT), `mmp_api_token` (TEXT) — F20 AppsFlyer creds; `mmp_api_token` is stored AES-256-GCM-encrypted when `MMP_ENCRYPTION_KEY` is set

**New table:** `mmp_sync_log` — `id, advertiser_slug, synced_at, events_pulled, matched, auto_approved, auto_rejected, errors, status`

No changes to `clicks`, `conversions`, `publishers`. Session/idle, rate-limit, headers, PII masking, and input hardening are **code-only** (no schema).

## 3. Deploy steps (PM2)
```bash
cd /home/komorebi/komorebi-affiliate
git pull            # or copy updated server.js + db.js (+ test files)
# npm ci --omit=dev   # optional — no new deps
pm2 restart komorebi-affiliate --update-env
pm2 logs komorebi-affiliate --lines 50   # watch for migration + the startup warnings below
```
At boot, check the logs for: a Telegram/console warning if `SESSION_SECRET`/`ADMIN_PASS` are unset, and a warning if `MMP_ENCRYPTION_KEY` is unset (tokens would be plaintext).

## 4. Environment variables
| Var | Required? | Default | If not set |
|---|---|---|---|
| **`MMP_ENCRYPTION_KEY`** | **Required if using MMP** (strongly recommended in prod) | — | MMP API tokens are stored **in plaintext** + a startup warning is logged. Set a **32-byte key as 64 hex chars** (any other string is SHA-256-derived to 32 bytes). **Keep it stable and backed up** — see Rollback. |
| `MMP_APPSFLYER_BASE` | Optional | `https://hq1.appsflyer.com` | Uses the real AppsFlyer host. Only override for staging/mock. |
| `POSTBACK_RATE_LIMIT_MAX` | Optional | `300` | `/postback/*` limited to 300 req/min per IP. Raise for very high-volume MMP senders. |
| `ADMIN_IDLE_SECONDS` | Optional (testing) | unset → **5 min** for both admin & publisher | When set (seconds), it overrides **both** idle timeouts. Leave **unset in prod** (5-min default). |

Also still relevant from earlier batches: **`BASE_URL`** (must be the real https domain), `RATE_LIMIT_MAX` (global limit, default 100), `GMAIL_*`, `TELEGRAM_*`.

## 5. Post-deploy verification (manual smoke tests)
```bash
# Health: secrets configured (booleans only) + active security headers
curl -s https://<domain>/health | jq '{secrets, security_headers}'
#   expect SESSION_SECRET:true, ADMIN_PASS:true; permissions_policy:"interest-cohort=()"; strict_transport_security:true

# Security headers present on a normal response
curl -sI https://<domain>/publisher/login | grep -iE 'permissions-policy|strict-transport-security|content-security-policy|x-content-type-options'

# Postback limiter is the dedicated 300 (not the global 100)
curl -sI "https://<domain>/postback/<slug>?click_id=x&event=sale" | grep -i x-ratelimit-limit   # → 300
```
Then in the admin UI:
- **Session idle:** log in to `/admin`, leave it ~5 min, next action should bounce to `/admin/login?err=Session+expired…`. (Verify the publisher portal the same way.)
- **HMAC:** on an advertiser with a `postback_secret` set, an **unsigned** postback returns `403`; a correctly **signed** one (`sig=HMAC-SHA256(secret, click_id+event+payout)`) returns `200`. Advertisers with no secret keep accepting unsigned postbacks.
- **MMP:** set AppsFlyer `mmp_type`/`app_id`/`token`, click **Test Connection** → expect "Connection OK". Confirm the token is encrypted at rest:
  ```bash
  sqlite3 affiliate.db "SELECT substr(mmp_api_token,1,7) FROM advertisers WHERE slug='<slug>';"   # → enc:v1:
  ```
  Then run a manual sync from the Sync Dashboard and confirm an `mmp_sync_log` row appears.
- **Input hardening:** a POST with a field > 2000 chars returns `400`.

## 6. Behavioral changes ops/QA need to know (all intentional)
1. **Session timeouts → 5 minutes idle for BOTH admin and publisher.** Inactive sessions are destroyed and redirected to the login page. Expect more frequent re-logins. (`ADMIN_IDLE_SECONDS` overrides both; leave unset in prod.)
2. **Cookies `SameSite=Strict`** (was `lax`) and a 24h cookie ceiling. First-party admin/publisher flows are unaffected; any cross-site embedding would break (none expected).
3. **`/postback/*` rate limit is now 300/min per IP, separate from the global 100/min** (the global limiter no longer applies to postbacks — MMP servers send bursts). `/marketplace/apply` is limited to 10/min.
4. **HMAC postback signatures (opt-in per advertiser):** if `postback_secret` is set, postbacks **must** include a valid `sig` or get `403`. No secret → unchanged (unsigned accepted). Only enable per advertiser once their MMP is configured to sign.
5. **MMP tokens encrypted at rest** (AES-256-GCM) when `MMP_ENCRYPTION_KEY` is set; otherwise plaintext + warning.
6. **Security headers:** `Permissions-Policy: interest-cohort=()` and **HSTS** (`max-age=31536000; includeSubDomains`). With `includeSubDomains`, every subdomain of the cert domain must serve valid HTTPS or browsers will refuse it.
7. **PII masking in audit log:** phone/email/API-key values in audit `detail` are masked.
8. **`/health` is public** and now exposes secret-configured booleans (no values) + active security headers.

## 7. Rollback
- **Code rollback is safe:** new columns/table are inert to old code; revert `server.js`/`db.js` and `pm2 restart`. Idle timeouts, SameSite, rate limits, and HMAC all revert with the code.
- **⚠️ HSTS is sticky on clients.** Once a browser receives `Strict-Transport-Security`, it forces HTTPS for that domain (+subdomains) for up to 1 year, even after rollback. Keep HTTPS serving. To truly back it out you must serve `max-age=0` for a while before removing it.
- **⚠️ Keep `MMP_ENCRYPTION_KEY` stable and backed up.** If the key is lost or changed, previously-encrypted `mmp_api_token` values can no longer be decrypted (decrypt returns null) — the tokens must be re-entered. This does not affect anything else.
- Full data revert: restore the pre-deploy backup from step 1.
- Requires **Node ≥ 22.5** (`node:sqlite`) — already true in prod.

## 8. ⚠️ Never run test files against production
`sec.test.js`, `mmp.test.js`, and `e2e.test.js` seed data, hit a mock AppsFlyer server, and deliberately exhaust rate limiters. Run them **only** against a throwaway/staging DB:
```bash
# local/staging only — example for the security + MMP suites
MKEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
ADMIN_USER=admin ADMIN_PASS=testpass123 SESSION_SECRET=x PORT=3999 BASE_URL=http://localhost:3999 \
  POSTBACK_WHITELIST_ENABLED=false RATE_LIMIT_MAX=100000 ADMIN_IDLE_SECONDS=2 node server.js &
E2E_BASE=http://localhost:3999 node sec.test.js
# (MMP suite needs MMP_ENCRYPTION_KEY=$MKEY MMP_APPSFLYER_BASE=http://localhost:4600 and node mmp.test.js)
```
Consider moving these into a `test/` dir or adding to `.gitignore` if you don't want them on the server.
