# Komorebi Affiliate Tracker

Self-hosted affiliate / CPA tracking platform for Komorebi Media (primarily loan offers). It generates publisher tracking links, records clicks (with geo/device), accepts server-to-server (S2S) postbacks to register conversions and compute payouts, and provides an admin console plus a publisher portal for advertisers, assignments, payments, invoices, and reconciliation.

## Tech stack
- **Runtime:** Node.js **≥ 22.5** (uses the built-in `node:sqlite`)
- **Web:** Express, server-rendered HTML (template strings — no frontend framework)
- **Database:** SQLite (`node:sqlite` `DatabaseSync`), WAL mode
- **Security/middleware:** Helmet, `express-session`, custom CSRF + rate limiting
- **Integrations:** nodemailer (email), geoip-lite (geo), multer (CSV upload), node-cron, AppsFlyer MMP
- **Process manager (prod):** PM2 (`ecosystem.config.js`) behind an HTTPS reverse proxy

## Run locally
Requires Node **≥ 22.5**.

```bash
git clone <repo-url> komorebi-affiliate
cd komorebi-affiliate
npm ci

cp .env.example .env          # then edit values (see comments in the file)

# Quick start for local review (creates a fresh affiliate.db on first boot):
ADMIN_USER=admin ADMIN_PASS=testpass123 SESSION_SECRET=dev-only-secret \
  BASE_URL=http://localhost:3000 POSTBACK_WHITELIST_ENABLED=false \
  node server.js
```

`POSTBACK_WHITELIST_ENABLED=false` lets you fire test postbacks from localhost (production keeps the AppsFlyer/Adjust IP whitelist on). See `.env.example` for every variable and what happens if it's unset.

> Heads-up: admin **and** publisher sessions idle out after **5 minutes**. For relaxed local browsing add `ADMIN_IDLE_SECONDS=3600`; to test the real timeout, use a short value (e.g. `ADMIN_IDLE_SECONDS=10`).

### URLs (default `PORT=3000`)
| Area | URL |
|---|---|
| Admin console | http://localhost:3000/admin  (login: `admin` / `testpass123`) |
| Publisher login | http://localhost:3000/publisher/login |
| Publisher register | http://localhost:3000/publisher/register |
| Marketplace (public) | http://localhost:3000/marketplace |
| Documentation | http://localhost:3000/docs |
| Health check | http://localhost:3000/health |

A newly registered publisher is **pending** until an admin approves it under `/admin/publishers`. To exercise full flows, create an advertiser, approve/assign a publisher, then generate clicks via `/track/:slug?pub=...` and conversions via `/postback/:slug?click_id=...`.

## Tests
HTTP-driven end-to-end suites (run against a throwaway/staging DB only — **never production**):
- `e2e.test.js` — full F1–F17 feature suite
- `sec.test.js` — F18/F19 security hardening
- `mmp.test.js` — F20 AppsFlyer MMP (uses a mock AppsFlyer server)

## Documentation
- **[TEAM-BRIEF.md](TEAM-BRIEF.md)** — handoff brief for the UI/UX and Security & QA teams (overview, local-run guide, review checklists, flagged items, sign-off process). *(Vietnamese)*
- **[DEPLOY-F1-F17.md](DEPLOY-F1-F17.md)** — deployment & migration guide for features F1–F17.
- **[DEPLOY-F18-F20.md](DEPLOY-F18-F20.md)** — deployment & migration guide for F18/F19 (security hardening) and F20 (MMP integration).

## Status
F1–F20 are built and pass local tests. **Not yet deployed** — pending UI/UX review and Security & QA sign-off before any production release.
