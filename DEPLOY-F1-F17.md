# Deployment & Migration Guide — F1–F17

One consolidated end-to-end run passed **63/63 green** on a fresh DB before this guide was written.

## TL;DR
- **Code changed:** `server.js`, `db.js` (modified); `e2e.test.js` (new test harness).
- **Dependencies:** none added — no `npm install` needed.
- **Schema migration:** automatic on app start (`db.js`), fully additive + idempotent.
- **Required action in prod:** **set `BASE_URL`** to the real domain; **take a DB backup first**.
- **Biggest behavioral change:** postbacks are now **assignment-gated** (F3) — existing pairs are auto-backfilled so live traffic is safe, but *new* publisher↔advertiser combos must be assigned first.

---

## 1. Pre-deploy: back up the database
Migrations are additive, but always snapshot first:
```bash
sqlite3 /home/komorebi/komorebi-affiliate/affiliate.db ".backup '/home/komorebi/affiliate-pre-F1-F17.db'"
```
(or run the existing `backup.sh`).

## 2. What the migration does (runs automatically when `server.js` boots)
`db.js` creates new tables `IF NOT EXISTS` and adds columns via guarded `ALTER TABLE` (checked with `PRAGMA table_info`). Safe to run repeatedly.

**New tables:** `goals`, `publisher_advertisers`, `password_resets`, `smart_link_rules`, `marketplace_applications`.

**New columns:**
- `advertisers`: `payout_type`, `click_lookback_window`, `monthly_conversion_cap`, `cap_reset_month`, `cap_reset_at`, `cap_alert_month`, `cap_alerted_80`, `cap_alerted_100`, `is_public`, `category`, `description`, `countries_allowed`
- `conversions`: `loan_amount`, `revenue`, `transaction_id`, `user_id`
- `clicks` (21, tracking pipeline): `sub1–sub5`, `subpub`, `gclid`, `fbclid`, `referrer`, `af_siteid`, `af_campaign`, `af_adset`, `af_ad`, `adjust_network`, `adjust_campaign`, `adjust_adgroup`, `adjust_creative`, `campaign`, `adgroup`, `creative`, `network`
- `goals`: `payout_type`

**One-time backfill (guarded by `settings.assignments_backfilled`):** auto-creates `publisher_advertisers` rows for every publisher↔advertiser pair already present in `clicks`/`conversions`, so enabling assignment-gated postbacks does **not** drop existing live traffic. Runs once; admins can unassign freely afterward.

## 3. Deploy steps (PM2)
```bash
# on the server, in the app dir
cd /home/komorebi/komorebi-affiliate
git pull            # or copy the updated server.js + db.js + e2e.test.js
# npm ci --omit=dev   # only if you sync node_modules; no new deps so optional
pm2 restart komorebi-affiliate --update-env
pm2 logs komorebi-affiliate --lines 50   # watch for migration / boot errors
```
The migration applies during boot. Confirm startup is clean (no `SQLITE_ERROR`).

## 4. Required / notable environment variables
| Var | Why it matters now |
|---|---|
| **`BASE_URL`** | **Must** be the real https domain. Used for tracking URLs, smart links (`/go/:pub`), **password-reset email links** (F2), and marketplace. If unset it defaults to `http://localhost:PORT` and reset links will be wrong. |
| `GMAIL_USER` / `GMAIL_PASS` | If set, password-reset emails (F2) and cap alerts send. If unset, reset tokens surface on the admin publisher-edit page (F2) and Telegram cap alerts (F12) are skipped. |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` | F12 advertiser-cap 80%/100% alerts. |
| `POSTBACK_WHITELIST_ENABLED` | Keep **on** in prod (AppsFlyer/Adjust IPs). Independent of the new gating. |
| `RATE_LIMIT_MAX` | New, optional. Per-IP req/min cap; **defaults to 100** (unchanged). Only raise it for load tests. |

## 5. Post-deploy verification
```bash
curl -s https://<domain>/health         # {"status":"ok",...}
```
- Log in to `/admin`, open the dashboard — confirm new **Revenue / Margin / Cap (mo)** columns render.
- Open an advertiser edit page — confirm Payout Type, Click Lookback, Monthly Cap, and Marketplace fields.
- Fire one real test postback for an **already-assigned** pair → expect `200`.
- A postback for an **unassigned** pair now returns `403` (expected — assign it or approve via marketplace).

## 6. Behavioral changes to be aware of (these are intentional)
1. **Assignment gating (F3):** postbacks only accepted for assigned publisher↔advertiser pairs (`403` otherwise). Existing pairs backfilled. New pairs need an assignment (admin edit page) or marketplace approval.
2. **Click expiry (F11):** postbacks for clicks older than the advertiser's `click_lookback_window` (default **30 days**) are rejected `410`.
3. **Advertiser cap (F12):** only active if you set `monthly_conversion_cap` (default null = unlimited). At cap → `429` + advertiser auto-pauses. Counts **approved** conversions.
4. **Percentage payout (F13/F14):** only for advertisers/goals set to `percent`; reads `loan_amount`. Existing fixed payouts unchanged. (The `payout` query param was already ignored.)
5. **Duplicate detection (F15):** only triggers when `user_id` is sent; duplicate → recorded as `status=duplicate`, `payout=0`, `200`.
6. **CSRF:** admin forms + publisher change-password require tokens (server-rendered).

## 7. Rollback
- **Code rollback is safe:** the new tables/columns are inert to old code (it ignores them). Revert `server.js`/`db.js` and `pm2 restart`. Behavior (gating, caps, etc.) reverts with the code.
- The migrated schema + backfilled assignment rows + `assignments_backfilled` flag remain in the DB — harmless. If you must fully revert data, restore the pre-deploy backup from step 1.
- Requires **Node ≥ 22.5** (for `node:sqlite`) — already true since the app runs today.

## 8. ⚠️ About `e2e.test.js`
It seeds advertisers/publishers/conversions into whatever DB the target server uses. **Never run it against production.** Run only against a throwaway/fresh DB:
```bash
# local/staging only
ADMIN_USER=admin ADMIN_PASS=testpass123 SESSION_SECRET=x PORT=3999 \
  BASE_URL=http://localhost:3999 POSTBACK_WHITELIST_ENABLED=false RATE_LIMIT_MAX=100000 \
  node server.js &
E2E_BASE=http://localhost:3999 node e2e.test.js   # expects "ALL GREEN ✓"
```
Consider adding it to `.gitignore` or a `test/` dir if you don't want it deployed.
