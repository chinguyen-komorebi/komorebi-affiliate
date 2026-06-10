'use strict';

const { DatabaseSync } = require('node:sqlite');
const { randomBytes, createHash } = require('node:crypto');
const path = require('node:path');

const db = new DatabaseSync(path.join(__dirname, 'affiliate.db'));

db.exec('PRAGMA journal_mode = WAL');
db.exec('PRAGMA foreign_keys = ON');

// ---------------------------------------------------------------------------
// Advertisers
// ---------------------------------------------------------------------------
db.exec(`
  CREATE TABLE IF NOT EXISTS advertisers (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    slug          TEXT UNIQUE NOT NULL,
    name          TEXT NOT NULL,
    offer_url     TEXT NOT NULL DEFAULT '',
    payout_amount REAL NOT NULL DEFAULT 0,
    payout_type   TEXT NOT NULL DEFAULT 'fixed',
    click_lookback_window INTEGER NOT NULL DEFAULT 30,
    monthly_conversion_cap INTEGER,
    cap_reset_month TEXT,
    cap_reset_at    TEXT,
    cap_alert_month TEXT,
    cap_alerted_80  INTEGER NOT NULL DEFAULT 0,
    cap_alerted_100 INTEGER NOT NULL DEFAULT 0,
    is_public        INTEGER NOT NULL DEFAULT 0,
    category         TEXT,
    description      TEXT,
    countries_allowed TEXT,
    postback_secret  TEXT,
    mmp_type      TEXT NOT NULL DEFAULT 'none',
    mmp_app_id    TEXT,
    mmp_api_token TEXT,
    status        TEXT NOT NULL DEFAULT 'active',
    created_at    TEXT DEFAULT (datetime('now'))
  );
`);

// Migration: payout_type · click_lookback_window · advertiser-level conversion cap (F12)
const advCols = db.prepare('PRAGMA table_info(advertisers)').all().map(c => c.name);
if (!advCols.includes('payout_type')) {
  db.exec("ALTER TABLE advertisers ADD COLUMN payout_type TEXT NOT NULL DEFAULT 'fixed'");
}
if (!advCols.includes('click_lookback_window')) {
  db.exec('ALTER TABLE advertisers ADD COLUMN click_lookback_window INTEGER NOT NULL DEFAULT 30');
}
// F12 advertiser-level conversion cap:
//   monthly_conversion_cap — hard ceiling on approved conversions per UTC month (null = unlimited)
//   cap_reset_month — admin-set YYYY-MM marker; cap_reset_at — internal count-floor timestamp
//   cap_alert_month / cap_alerted_80 / cap_alerted_100 — Telegram alert throttle state
if (!advCols.includes('monthly_conversion_cap')) db.exec('ALTER TABLE advertisers ADD COLUMN monthly_conversion_cap INTEGER');
if (!advCols.includes('cap_reset_month'))        db.exec('ALTER TABLE advertisers ADD COLUMN cap_reset_month TEXT');
if (!advCols.includes('cap_reset_at'))           db.exec('ALTER TABLE advertisers ADD COLUMN cap_reset_at TEXT');
if (!advCols.includes('cap_alert_month'))        db.exec('ALTER TABLE advertisers ADD COLUMN cap_alert_month TEXT');
if (!advCols.includes('cap_alerted_80'))         db.exec('ALTER TABLE advertisers ADD COLUMN cap_alerted_80 INTEGER NOT NULL DEFAULT 0');
if (!advCols.includes('cap_alerted_100'))        db.exec('ALTER TABLE advertisers ADD COLUMN cap_alerted_100 INTEGER NOT NULL DEFAULT 0');
// F6 marketplace fields
if (!advCols.includes('is_public'))         db.exec('ALTER TABLE advertisers ADD COLUMN is_public INTEGER NOT NULL DEFAULT 0');
if (!advCols.includes('category'))          db.exec('ALTER TABLE advertisers ADD COLUMN category TEXT');
if (!advCols.includes('description'))       db.exec('ALTER TABLE advertisers ADD COLUMN description TEXT');
if (!advCols.includes('countries_allowed')) db.exec('ALTER TABLE advertisers ADD COLUMN countries_allowed TEXT');
// F18 HMAC postback signature secret (optional/per-advertiser, backward-compatible)
if (!advCols.includes('postback_secret'))   db.exec('ALTER TABLE advertisers ADD COLUMN postback_secret TEXT');
// F20 MMP integration (AppsFlyer) — mmp_api_token stored AES-256-GCM-encrypted when MMP_ENCRYPTION_KEY is set
if (!advCols.includes('mmp_type'))      db.exec("ALTER TABLE advertisers ADD COLUMN mmp_type TEXT NOT NULL DEFAULT 'none'");
if (!advCols.includes('mmp_app_id'))    db.exec('ALTER TABLE advertisers ADD COLUMN mmp_app_id TEXT');
if (!advCols.includes('mmp_api_token')) db.exec('ALTER TABLE advertisers ADD COLUMN mmp_api_token TEXT');
// Backlog #4 — per-advertiser timezone + default currency (additive). Must match the
// advertiser's AppsFlyer app settings exactly; the #1 cause of reconciliation disputes.
//   timezone — IANA name (e.g. Asia/Ho_Chi_Minh); null = fall back to the platform default.
//   currency — default currency for this advertiser's conversions (e.g. USD, VND).
if (!advCols.includes('timezone')) db.exec('ALTER TABLE advertisers ADD COLUMN timezone TEXT');
if (!advCols.includes('currency')) db.exec("ALTER TABLE advertisers ADD COLUMN currency TEXT NOT NULL DEFAULT 'USD'");
// Backlog #5 — per-advertiser partner-link template (macro mapping for AppsFlyer onboarding).
if (!advCols.includes('partner_link_template')) db.exec('ALTER TABLE advertisers ADD COLUMN partner_link_template TEXT');
// Backlog #11 — advertiser portal login (separate from admin). Username = slug; password
// is set by an admin. Null = portal access disabled for this advertiser.
if (!advCols.includes('portal_password_hash')) db.exec('ALTER TABLE advertisers ADD COLUMN portal_password_hash TEXT');

// ---------------------------------------------------------------------------
// Clicks  (advertiser_slug added via migration for existing dbs)
// ---------------------------------------------------------------------------
db.exec(`
  CREATE TABLE IF NOT EXISTS clicks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    click_id        TEXT UNIQUE NOT NULL,
    advertiser_slug TEXT NOT NULL DEFAULT 'legacy',
    publisher       TEXT NOT NULL,
    ip              TEXT,
    user_agent      TEXT,
    created_at      TEXT DEFAULT (datetime('now'))
  );
`);

const clickCols = db.prepare('PRAGMA table_info(clicks)').all().map(c => c.name);
if (!clickCols.includes('advertiser_slug')) {
  db.exec("ALTER TABLE clicks ADD COLUMN advertiser_slug TEXT NOT NULL DEFAULT 'legacy'");
}
if (!clickCols.includes('country'))     db.exec('ALTER TABLE clicks ADD COLUMN country TEXT');
if (!clickCols.includes('device_type')) db.exec('ALTER TABLE clicks ADD COLUMN device_type TEXT');
if (!clickCols.includes('os'))          db.exec('ALTER TABLE clicks ADD COLUMN os TEXT');
if (!clickCols.includes('browser'))     db.exec('ALTER TABLE clicks ADD COLUMN browser TEXT');

// Tracking-pipeline columns (all nullable TEXT), added via migration:
//   F7 sub-parameters · F8 enhanced tracking · F10 AppsFlyer/Adjust (raw + mapped)
const CLICK_EXTRA_COLS = [
  'sub1', 'sub2', 'sub3', 'sub4', 'sub5', 'subpub',                          // F7
  'gclid', 'fbclid', 'referrer',                                            // F8
  'af_siteid', 'af_campaign', 'af_adset', 'af_ad',                          // F10 raw (AppsFlyer)
  'adjust_network', 'adjust_campaign', 'adjust_adgroup', 'adjust_creative', // F10 raw (Adjust)
  'campaign', 'adgroup', 'creative', 'network',                             // F10 mapped (internal)
  'af_sub1', 'af_sub2',                                                     // Backlog #17 agency / sub-affiliate
  'smart_link_slug',                                                        // Group 4 — smart link that generated this click
];
const clickColsNow = db.prepare('PRAGMA table_info(clicks)').all().map(c => c.name);
for (const col of CLICK_EXTRA_COLS) {
  if (!clickColsNow.includes(col)) db.exec(`ALTER TABLE clicks ADD COLUMN ${col} TEXT`);
}
db.exec('CREATE INDEX IF NOT EXISTS idx_clicks_sub1 ON clicks(sub1)');

// ---------------------------------------------------------------------------
// Conversions  (advertiser_slug added via migration for existing dbs)
// ---------------------------------------------------------------------------
db.exec(`
  CREATE TABLE IF NOT EXISTS conversions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    click_id        TEXT NOT NULL,
    advertiser_slug TEXT NOT NULL DEFAULT 'legacy',
    publisher       TEXT NOT NULL,
    event           TEXT NOT NULL DEFAULT 'sale',
    payout          REAL NOT NULL DEFAULT 0,
    currency        TEXT NOT NULL DEFAULT 'USD',
    loan_amount     REAL,
    revenue         REAL,
    received_at     TEXT DEFAULT (datetime('now')),
    raw_params      TEXT
  );
`);

const convCols = db.prepare('PRAGMA table_info(conversions)').all().map(c => c.name);
if (!convCols.includes('advertiser_slug')) {
  db.exec("ALTER TABLE conversions ADD COLUMN advertiser_slug TEXT NOT NULL DEFAULT 'legacy'");
}

// Migration: add status / reason / reconciliation_run_id to conversions
const convCols2 = db.prepare('PRAGMA table_info(conversions)').all().map(c => c.name);
if (!convCols2.includes('status')) {
  db.exec("ALTER TABLE conversions ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'");
}
if (!convCols2.includes('reason')) {
  db.exec('ALTER TABLE conversions ADD COLUMN reason TEXT');
}
if (!convCols2.includes('reconciliation_run_id')) {
  db.exec('ALTER TABLE conversions ADD COLUMN reconciliation_run_id INTEGER');
}
// Migration: loan_amount (basis for percentage payout) + revenue (advertiser pays Komorebi)
if (!convCols2.includes('loan_amount')) db.exec('ALTER TABLE conversions ADD COLUMN loan_amount REAL');
if (!convCols2.includes('revenue'))     db.exec('ALTER TABLE conversions ADD COLUMN revenue REAL');
// QA2 — currency per conversion (USD default; VND for percent-of-loan payouts) so aggregates never mix currencies
if (!convCols2.includes('currency'))    db.exec("ALTER TABLE conversions ADD COLUMN currency TEXT NOT NULL DEFAULT 'USD'");
// Migration: transaction_id (F9) — advertiser's own conversion id, for reconciliation
if (!convCols2.includes('transaction_id')) db.exec('ALTER TABLE conversions ADD COLUMN transaction_id TEXT');
db.exec('CREATE INDEX IF NOT EXISTS idx_conv_transaction ON conversions(transaction_id)');
// Migration: user_id (F15) — advertiser's end-user id, for duplicate-user detection
if (!convCols2.includes('user_id')) db.exec('ALTER TABLE conversions ADD COLUMN user_id TEXT');
db.exec('CREATE INDEX IF NOT EXISTS idx_conv_user ON conversions(advertiser_slug, user_id)');
// Backlog #1 — dispute / adjustment state per conversion (additive, backward-compatible):
//   dispute_state — 'none' | 'disputed' | 'resolved'; set when a reconciliation run
//     overturns a previously-decided conversion, or manually by an admin.
//   adjustment / adjustment_note — a signed payout adjustment (e.g. clawback) applied
//     during dispute resolution, kept separate from the original payout for an audit trail.
// Backlog #13–17 — fraud / quality / sub-affiliate columns (all additive, nullable):
//   fraud_source  (#13) — 'protect360' when flagged by the Protect360 ingest endpoint
//   fraud_flag    (#14/#15) — 'duplicate_click_id', 'ctit_too_fast', 'ctit_too_slow' (pipe-joined when multiple)
//   ctit_seconds  (#15) — click-to-conversion time in seconds
//   af_sub1/af_sub2 (#17) — agency / sub-affiliate dimension propagated from the click
if (!convCols2.includes('fraud_source')) db.exec('ALTER TABLE conversions ADD COLUMN fraud_source TEXT');
if (!convCols2.includes('fraud_flag'))   db.exec('ALTER TABLE conversions ADD COLUMN fraud_flag TEXT');
if (!convCols2.includes('ctit_seconds')) db.exec('ALTER TABLE conversions ADD COLUMN ctit_seconds INTEGER');
if (!convCols2.includes('af_sub1'))      db.exec('ALTER TABLE conversions ADD COLUMN af_sub1 TEXT');
if (!convCols2.includes('af_sub2'))      db.exec('ALTER TABLE conversions ADD COLUMN af_sub2 TEXT');
// Group 5 #1 — multi-currency. `payout` stays in the conversion currency (existing
// per-currency invoicing/earnings rely on that); payout_local mirrors it explicitly and
// payout_usd is the USD-normalized amount (via exchange_rates) for cross-currency totals.
if (!convCols2.includes('payout_local')) db.exec('ALTER TABLE conversions ADD COLUMN payout_local REAL');
if (!convCols2.includes('payout_usd'))   db.exec('ALTER TABLE conversions ADD COLUMN payout_usd REAL');
// Group 5 #4 — attribution model applied to this conversion.
if (!convCols2.includes('attribution_model')) db.exec("ALTER TABLE conversions ADD COLUMN attribution_model TEXT NOT NULL DEFAULT 'last_click'");
db.exec('CREATE INDEX IF NOT EXISTS idx_conv_fraud_flag ON conversions(fraud_flag)');
db.exec('CREATE INDEX IF NOT EXISTS idx_conv_af_sub1 ON conversions(af_sub1)');
if (!convCols2.includes('dispute_state'))   db.exec("ALTER TABLE conversions ADD COLUMN dispute_state TEXT NOT NULL DEFAULT 'none'");
if (!convCols2.includes('adjustment'))      db.exec('ALTER TABLE conversions ADD COLUMN adjustment REAL');
if (!convCols2.includes('adjustment_note')) db.exec('ALTER TABLE conversions ADD COLUMN adjustment_note TEXT');
db.exec('CREATE INDEX IF NOT EXISTS idx_conv_dispute ON conversions(advertiser_slug, dispute_state)');

// ---------------------------------------------------------------------------
// Reconciliation
// ---------------------------------------------------------------------------
db.exec(`
  CREATE TABLE IF NOT EXISTS reconciliation_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    advertiser_slug TEXT NOT NULL,
    filename        TEXT NOT NULL,
    uploaded_at     TEXT DEFAULT (datetime('now')),
    total_rows      INTEGER NOT NULL DEFAULT 0,
    matched         INTEGER NOT NULL DEFAULT 0,
    approved        INTEGER NOT NULL DEFAULT 0,
    rejected        INTEGER NOT NULL DEFAULT 0,
    unmatched       INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS reconciliation_unmatched (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id     INTEGER NOT NULL,
    click_id   TEXT,
    raw_status TEXT,
    reason     TEXT,
    issue      TEXT
  );

  CREATE INDEX IF NOT EXISTS idx_recon_runs_adv  ON reconciliation_runs(advertiser_slug);
  CREATE INDEX IF NOT EXISTS idx_recon_um_run    ON reconciliation_unmatched(run_id);
  CREATE INDEX IF NOT EXISTS idx_conv_status     ON conversions(status);
`);

// Backlog #1 — discrepancy count per reconciliation run (additive). A discrepancy is a
// matched row whose advertiser-supplied status overturns a conversion we had already
// decided (e.g. we approved, the advertiser rejects), surfaced for dispute handling.
const reconRunCols = db.prepare('PRAGMA table_info(reconciliation_runs)').all().map(c => c.name);
if (!reconRunCols.includes('discrepancy')) db.exec('ALTER TABLE reconciliation_runs ADD COLUMN discrepancy INTEGER NOT NULL DEFAULT 0');

// ---------------------------------------------------------------------------
// Indexes
// ---------------------------------------------------------------------------
db.exec(`
  CREATE INDEX IF NOT EXISTS idx_clicks_advertiser  ON clicks(advertiser_slug);
  CREATE INDEX IF NOT EXISTS idx_clicks_publisher   ON clicks(publisher);
  CREATE INDEX IF NOT EXISTS idx_clicks_created_at  ON clicks(created_at);
  CREATE INDEX IF NOT EXISTS idx_clicks_country     ON clicks(country);
  CREATE INDEX IF NOT EXISTS idx_clicks_device      ON clicks(device_type);
  CREATE INDEX IF NOT EXISTS idx_conv_advertiser    ON conversions(advertiser_slug);
  CREATE INDEX IF NOT EXISTS idx_conv_publisher     ON conversions(publisher);
  CREATE INDEX IF NOT EXISTS idx_conv_received_at   ON conversions(received_at);
  CREATE INDEX IF NOT EXISTS idx_conv_click_id      ON conversions(click_id);
  CREATE UNIQUE INDEX IF NOT EXISTS ux_conv_clickid_event ON conversions(click_id, event);
`);

// ---------------------------------------------------------------------------
// Publishers  (session-auth portal accounts)
// ---------------------------------------------------------------------------
db.exec(`
  CREATE TABLE IF NOT EXISTS publishers (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    postback_url  TEXT NOT NULL DEFAULT '',
    api_key       TEXT UNIQUE,
    api_key_hash  TEXT,
    api_key_suffix TEXT,
    status        TEXT NOT NULL DEFAULT 'active',
    created_at    TEXT DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_pub_username     ON publishers(username);
  CREATE INDEX IF NOT EXISTS idx_pub_api_key      ON publishers(api_key);
  CREATE INDEX IF NOT EXISTS idx_pub_api_key_hash ON publishers(api_key_hash);
`);

// Migrations for existing databases
const pubCols = db.prepare('PRAGMA table_info(publishers)').all().map(c => c.name);
if (!pubCols.includes('postback_url'))      db.exec("ALTER TABLE publishers ADD COLUMN postback_url TEXT NOT NULL DEFAULT ''");
if (!pubCols.includes('api_key'))           db.exec('ALTER TABLE publishers ADD COLUMN api_key TEXT UNIQUE');
if (!pubCols.includes('email'))             db.exec("ALTER TABLE publishers ADD COLUMN email TEXT NOT NULL DEFAULT ''");
if (!pubCols.includes('company'))           db.exec("ALTER TABLE publishers ADD COLUMN company TEXT NOT NULL DEFAULT ''");
if (!pubCols.includes('website'))           db.exec("ALTER TABLE publishers ADD COLUMN website TEXT NOT NULL DEFAULT ''");
if (!pubCols.includes('traffic_sources'))   db.exec("ALTER TABLE publishers ADD COLUMN traffic_sources TEXT NOT NULL DEFAULT ''");
if (!pubCols.includes('registration_note')) db.exec("ALTER TABLE publishers ADD COLUMN registration_note TEXT NOT NULL DEFAULT ''");
if (!pubCols.includes('minimum_payout'))    db.exec('ALTER TABLE publishers ADD COLUMN minimum_payout REAL NOT NULL DEFAULT 50');
if (!pubCols.includes('api_key_hash'))      db.exec('ALTER TABLE publishers ADD COLUMN api_key_hash TEXT');
if (!pubCols.includes('api_key_suffix'))    db.exec('ALTER TABLE publishers ADD COLUMN api_key_suffix TEXT'); // M3 — last 8 chars for UI badge
// Backlog #12 — per-publisher custom tracking domain. Null = use the platform default.
if (!pubCols.includes('custom_domain'))     db.exec('ALTER TABLE publishers ADD COLUMN custom_domain TEXT');

// Ensure index exists for api_key_hash on existing databases
db.exec('CREATE INDEX IF NOT EXISTS idx_pub_api_key_hash ON publishers(api_key_hash)');

// Backfill: hash + suffix for legacy rows that have a plaintext key but no hash (preserve the key).
const needHash = db.prepare('SELECT id, api_key FROM publishers WHERE api_key IS NOT NULL AND api_key_hash IS NULL').all();
const setHash  = db.prepare('UPDATE publishers SET api_key_hash = ?, api_key_suffix = ? WHERE id = ?');
for (const p of needHash) {
  setHash.run(createHash('sha256').update(p.api_key).digest('hex'), p.api_key.slice(-8), p.id);
}

// Backfill: suffix for rows that still have a plaintext key + hash but no suffix yet.
db.exec("UPDATE publishers SET api_key_suffix = substr(api_key, -8) WHERE api_key IS NOT NULL AND api_key_suffix IS NULL");

// Issue a fresh hash-only key for any publisher with no key at all (never clobbers
// a regenerated hash-only key, which has api_key NULL but api_key_hash present).
const needKey = db.prepare('SELECT id FROM publishers WHERE api_key IS NULL AND api_key_hash IS NULL').all();
const setKey  = db.prepare('UPDATE publishers SET api_key_hash = ?, api_key_suffix = ? WHERE id = ?');
for (const p of needKey) {
  const k = 'kom_live_' + randomBytes(16).toString('hex');
  setKey.run(createHash('sha256').update(k).digest('hex'), k.slice(-8), p.id);
}

// M3 residual — purge any remaining plaintext API keys now that hash + suffix are
// backfilled. Lookups are hash-only, so the plaintext column is no longer needed.
db.exec('UPDATE publishers SET api_key = NULL WHERE api_key IS NOT NULL AND api_key_hash IS NOT NULL');

// ---------------------------------------------------------------------------
// Postback log  (S2S fire attempts)
// ---------------------------------------------------------------------------
db.exec(`
  CREATE TABLE IF NOT EXISTS postback_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    publisher   TEXT NOT NULL,
    click_id    TEXT NOT NULL,
    url         TEXT NOT NULL,
    http_status INTEGER,
    attempt     INTEGER NOT NULL DEFAULT 1,
    success     INTEGER NOT NULL DEFAULT 0,
    error       TEXT,
    fired_at    TEXT DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_pblog_publisher ON postback_log(publisher);
  CREATE INDEX IF NOT EXISTS idx_pblog_click_id  ON postback_log(click_id);
  CREATE INDEX IF NOT EXISTS idx_pblog_fired_at  ON postback_log(fired_at);
`);

// Backlog #2 — direction on the postback delivery log (additive). 'sent' = outbound S2S
// postback Komorebi fires to a publisher (existing rows); 'received' = inbound conversion
// postback an advertiser/MMP fires to Komorebi. Lets the global log show both legs.
const pbLogCols = db.prepare('PRAGMA table_info(postback_log)').all().map(c => c.name);
if (!pbLogCols.includes('direction')) db.exec("ALTER TABLE postback_log ADD COLUMN direction TEXT NOT NULL DEFAULT 'sent'");
db.exec('CREATE INDEX IF NOT EXISTS idx_pblog_direction ON postback_log(direction, fired_at)');

// ---------------------------------------------------------------------------
// Settings  (key-value store for admin toggles)
// ---------------------------------------------------------------------------
db.exec(`
  CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
`);
// Default settings (INSERT OR IGNORE — never overwrite user changes)
for (const [key, value] of [
  ['email_notifications',    'true'],
  ['daily_summary',          'true'],
  ['webhook_notifications',  'true'],
  ['webhook_daily_summary',  'true'],
]) {
  db.prepare('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)').run(key, value);
}

// ---------------------------------------------------------------------------
// Admin settings  (key-value store for admin credentials that must survive restarts)
// Holds 'admin_pass_hash' so a password changed via the UI persists across reboots
// instead of reverting to the ADMIN_PASS env var. See server.js boot sequence.
// ---------------------------------------------------------------------------
db.exec(`
  CREATE TABLE IF NOT EXISTS admin_settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
`);

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------
db.exec(`
  CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    action      TEXT NOT NULL,
    entity_type TEXT,
    entity_id   TEXT,
    detail      TEXT,
    ip_address  TEXT,
    timezone    TEXT,
    created_at  TEXT DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_audit_action     ON audit_log(action);
  CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_log(created_at);
`);

// Migration: add timezone column for existing databases
const auditCols = db.prepare('PRAGMA table_info(audit_log)').all().map(c => c.name);
if (!auditCols.includes('timezone')) {
  db.exec('ALTER TABLE audit_log ADD COLUMN timezone TEXT');
}

// ---------------------------------------------------------------------------
// Payments
// ---------------------------------------------------------------------------
db.exec(`
  CREATE TABLE IF NOT EXISTS payments (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    publisher_id   INTEGER NOT NULL,
    publisher_name TEXT NOT NULL,
    amount_usd     REAL NOT NULL,
    paid_at        TEXT NOT NULL,
    method         TEXT NOT NULL DEFAULT 'Wire Transfer',
    notes          TEXT NOT NULL DEFAULT '',
    created_at     TEXT DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_payments_publisher ON payments(publisher_id);
  CREATE INDEX IF NOT EXISTS idx_payments_paid_at   ON payments(paid_at);
`);

// ---------------------------------------------------------------------------
// Invoices
// ---------------------------------------------------------------------------
db.exec(`
  CREATE TABLE IF NOT EXISTS invoices (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    publisher_id    INTEGER NOT NULL,
    publisher_name  TEXT NOT NULL,
    year            INTEGER NOT NULL,
    month           INTEGER NOT NULL,
    status          TEXT NOT NULL DEFAULT 'draft',
    total_amount    REAL NOT NULL DEFAULT 0,
    notes           TEXT NOT NULL DEFAULT '',
    created_at      TEXT DEFAULT (datetime('now')),
    updated_at      TEXT DEFAULT (datetime('now')),
    UNIQUE(publisher_id, year, month)
  );

  CREATE INDEX IF NOT EXISTS idx_invoices_publisher ON invoices(publisher_id);
  CREATE INDEX IF NOT EXISTS idx_invoices_period    ON invoices(year, month);
  CREATE INDEX IF NOT EXISTS idx_invoices_status    ON invoices(status);
`);

// ---------------------------------------------------------------------------
// Conversion goals  (multiple payable events per advertiser)
// A postback's `event` is matched against goals.event_token to pick the payout.
// ---------------------------------------------------------------------------
db.exec(`
  CREATE TABLE IF NOT EXISTS goals (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    advertiser_id INTEGER NOT NULL REFERENCES advertisers(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    event_token   TEXT NOT NULL,
    payout        REAL NOT NULL DEFAULT 0,
    payout_type   TEXT NOT NULL DEFAULT 'fixed',
    description   TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'active',
    created_at    TEXT DEFAULT (datetime('now')),
    UNIQUE(advertiser_id, event_token)
  );

  CREATE INDEX IF NOT EXISTS idx_goals_advertiser ON goals(advertiser_id);
  CREATE INDEX IF NOT EXISTS idx_goals_token      ON goals(advertiser_id, event_token);
`);

// Migration: add payout_type to goals for databases created before percentage payouts
const goalCols = db.prepare('PRAGMA table_info(goals)').all().map(c => c.name);
if (!goalCols.includes('payout_type')) {
  db.exec("ALTER TABLE goals ADD COLUMN payout_type TEXT NOT NULL DEFAULT 'fixed'");
}

// ---------------------------------------------------------------------------
// Backlog #7 — Event name mapping per advertiser.
// ---------------------------------------------------------------------------
db.exec(`
  CREATE TABLE IF NOT EXISTS event_mappings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    advertiser_id INTEGER NOT NULL REFERENCES advertisers(id) ON DELETE CASCADE,
    source_event  TEXT NOT NULL,
    mapped_event  TEXT NOT NULL,
    created_at    TEXT DEFAULT (datetime('now')),
    UNIQUE(advertiser_id, source_event)
  );
  CREATE INDEX IF NOT EXISTS idx_evmap_advertiser ON event_mappings(advertiser_id);
`);


// ---------------------------------------------------------------------------
// Publisher ↔ Advertiser assignments  (junction)
// Gates portal visibility and postback acceptance. payout_override (when set)
// takes precedence over goal/advertiser payout. valid_from/valid_until define an
// inclusive UTC date window and monthly_cap limits APPROVED conversions per
// UTC month — all enforced at postback time (see assignmentBlock in server.js).
// ---------------------------------------------------------------------------
db.exec(`
  CREATE TABLE IF NOT EXISTS publisher_advertisers (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    publisher_id    INTEGER NOT NULL REFERENCES publishers(id)  ON DELETE CASCADE,
    advertiser_id   INTEGER NOT NULL REFERENCES advertisers(id) ON DELETE CASCADE,
    assigned_at     TEXT DEFAULT (datetime('now')),
    payout_override REAL,
    valid_from      TEXT,
    valid_until     TEXT,
    monthly_cap     INTEGER,
    UNIQUE(publisher_id, advertiser_id)
  );

  CREATE INDEX IF NOT EXISTS idx_pa_publisher  ON publisher_advertisers(publisher_id);
  CREATE INDEX IF NOT EXISTS idx_pa_advertiser ON publisher_advertisers(advertiser_id);
`);

// ---------------------------------------------------------------------------
// Password reset tokens  (publisher self-service + admin-surfaced)
// ---------------------------------------------------------------------------
db.exec(`
  CREATE TABLE IF NOT EXISTS password_resets (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    publisher_id INTEGER NOT NULL REFERENCES publishers(id) ON DELETE CASCADE,
    token        TEXT UNIQUE NOT NULL,
    expires_at   TEXT NOT NULL,
    used_at      TEXT,
    created_at   TEXT DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_pwreset_token ON password_resets(token);
  CREATE INDEX IF NOT EXISTS idx_pwreset_pub   ON password_resets(publisher_id);
`);

// ---------------------------------------------------------------------------
// Smart-link routing rules (F5) — per-publisher geo/device → advertiser rules
// ---------------------------------------------------------------------------
db.exec(`
  CREATE TABLE IF NOT EXISTS smart_link_rules (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    publisher_id  INTEGER NOT NULL REFERENCES publishers(id)  ON DELETE CASCADE,
    advertiser_id INTEGER NOT NULL REFERENCES advertisers(id) ON DELETE CASCADE,
    country       TEXT NOT NULL DEFAULT '*',
    device_type   TEXT NOT NULL DEFAULT '*',
    priority      INTEGER NOT NULL DEFAULT 100,
    created_at    TEXT DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_slr_publisher ON smart_link_rules(publisher_id, priority);
`);

// ---------------------------------------------------------------------------
// Marketplace applications (F6) — publisher requests to run a public campaign
// ---------------------------------------------------------------------------
db.exec(`
  CREATE TABLE IF NOT EXISTS marketplace_applications (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    publisher_id  INTEGER NOT NULL REFERENCES publishers(id)  ON DELETE CASCADE,
    advertiser_id INTEGER NOT NULL REFERENCES advertisers(id) ON DELETE CASCADE,
    status        TEXT NOT NULL DEFAULT 'pending',
    applied_at    TEXT DEFAULT (datetime('now')),
    decided_at    TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_mktapp_status ON marketplace_applications(status);
  CREATE INDEX IF NOT EXISTS idx_mktapp_pub    ON marketplace_applications(publisher_id);
`);

// ---------------------------------------------------------------------------
// Group 4 — Smart Links (named multi-rule routing links).
// NOTE: table is `smartlink_rules` (not `smart_link_rules`, which already exists for
// the F5 per-publisher /go routing) so the two features coexist.
// ---------------------------------------------------------------------------
db.exec(`
  CREATE TABLE IF NOT EXISTS smart_links (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    slug       TEXT UNIQUE NOT NULL,
    name       TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS smartlink_rules (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    smart_link_id   INTEGER NOT NULL REFERENCES smart_links(id) ON DELETE CASCADE,
    priority        INTEGER NOT NULL DEFAULT 0,
    geo             TEXT,        -- comma-separated country codes (e.g. "VN,SG"); NULL = any
    device_type     TEXT,       -- mobile / desktop / tablet; NULL = any
    os              TEXT,        -- android / ios / windows; NULL = any
    advertiser_slug TEXT NOT NULL REFERENCES advertisers(slug),
    publisher       TEXT,        -- override publisher; NULL = use ?pub= from the query
    created_at      TEXT DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_slrules_link ON smartlink_rules(smart_link_id, priority);
`);

// ---------------------------------------------------------------------------
// Group 4 — Marketplace listings + applications.
// NOTE: applications table is `marketplace_apps` (not `marketplace_applications`,
// which already exists for the F6 marketplace) so the two features coexist.
// ---------------------------------------------------------------------------
db.exec(`
  CREATE TABLE IF NOT EXISTS marketplace_listings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    advertiser_slug TEXT NOT NULL REFERENCES advertisers(slug),
    title           TEXT NOT NULL,
    description     TEXT,
    payout_display  TEXT,        -- e.g. "3.5% CPS" or "150,000 VND per account"
    category        TEXT,        -- fintech / ecom / finance ...
    geo             TEXT,        -- target GEO e.g. "VN"
    status          TEXT NOT NULL DEFAULT 'active',  -- active / paused
    created_at      TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS marketplace_apps (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    listing_id  INTEGER NOT NULL REFERENCES marketplace_listings(id) ON DELETE CASCADE,
    publisher   TEXT NOT NULL REFERENCES publishers(username),
    status      TEXT NOT NULL DEFAULT 'pending',  -- pending / approved / rejected
    note        TEXT,
    created_at  TEXT DEFAULT (datetime('now')),
    UNIQUE(listing_id, publisher)
  );
  CREATE INDEX IF NOT EXISTS idx_mktlist_status ON marketplace_listings(status);
  CREATE INDEX IF NOT EXISTS idx_mktapps_listing ON marketplace_apps(listing_id);
  CREATE INDEX IF NOT EXISTS idx_mktapps_pub     ON marketplace_apps(publisher);
`);

// ===========================================================================
// Group 5 — multi-currency, white-label, traffic AI, multi-touch attribution
// ===========================================================================

// #1 — exchange rates (rate = value of 1 unit of `base` in `target`). Seeded base→USD.
db.exec(`
  CREATE TABLE IF NOT EXISTS exchange_rates (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    base       TEXT NOT NULL,
    target     TEXT NOT NULL,
    rate       REAL NOT NULL,
    updated_at TEXT DEFAULT (datetime('now')),
    UNIQUE(base, target)
  );
`);
for (const [base, rate] of [['USD', 1], ['VND', 0.000040], ['SGD', 0.74]]) {
  db.prepare('INSERT OR IGNORE INTO exchange_rates (base, target, rate) VALUES (?, ?, ?)').run(base, 'USD', rate);
}

// #2 — per-advertiser white-label branding.
db.exec(`
  CREATE TABLE IF NOT EXISTS advertiser_branding (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    advertiser_slug TEXT NOT NULL REFERENCES advertisers(slug) ON DELETE CASCADE,
    logo_url        TEXT,
    primary_color   TEXT DEFAULT '#00bfa5',
    company_name    TEXT,
    custom_domain   TEXT UNIQUE,
    created_at      TEXT DEFAULT (datetime('now')),
    UNIQUE(advertiser_slug)
  );
  CREATE INDEX IF NOT EXISTS idx_brand_domain ON advertiser_branding(custom_domain);
`);

// #3 — traffic-distribution AI: per-smart-link mode + per-advertiser stats.
const smartLinkCols = db.prepare('PRAGMA table_info(smart_links)').all().map(c => c.name);
if (!smartLinkCols.includes('ai_mode')) db.exec('ALTER TABLE smart_links ADD COLUMN ai_mode INTEGER NOT NULL DEFAULT 0');
db.exec(`
  CREATE TABLE IF NOT EXISTS smart_link_stats (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    smart_link_id   INTEGER NOT NULL REFERENCES smart_links(id) ON DELETE CASCADE,
    advertiser_slug TEXT NOT NULL,
    clicks          INTEGER NOT NULL DEFAULT 0,
    conversions     INTEGER NOT NULL DEFAULT 0,
    revenue         REAL NOT NULL DEFAULT 0,
    updated_at      TEXT DEFAULT (datetime('now')),
    UNIQUE(smart_link_id, advertiser_slug)
  );
`);

// #4 — multi-touch attribution touchpoints (one row per click in a journey).
// Spec columns + two additive extras to make multi-touch real & testable: `user_id`
// is the journey/identity key (the platform has no other cross-click identity), and
// `credit` stores the per-touchpoint share once the model is applied at conversion.
db.exec(`
  CREATE TABLE IF NOT EXISTS attribution_touchpoints (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    conversion_id   INTEGER,
    click_id        TEXT,
    advertiser_slug TEXT,
    publisher       TEXT,
    user_id         TEXT,
    position        INTEGER,
    credit          REAL,
    touched_at      TEXT DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_touch_click ON attribution_touchpoints(click_id);
  CREATE INDEX IF NOT EXISTS idx_touch_conv  ON attribution_touchpoints(conversion_id);
  CREATE INDEX IF NOT EXISTS idx_touch_user  ON attribution_touchpoints(user_id, advertiser_slug);
`);

// Default attribution model (admin-settable). Stored in the existing settings table.
db.prepare('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)').run('default_attribution_model', 'last_click');

// ===========================================================================
// Group 6 — Operational & Campaign Management
//   #1 multi-campaign per advertiser  ·  #3 per-campaign monthly conversion cap
// One advertiser can host many campaigns (offers), each with its own offer URL,
// payout, currency, event token and monthly cap. Clicks and conversions carry an
// optional campaign_id so traffic and payouts can be attributed per campaign.
// ===========================================================================
db.exec(`
  CREATE TABLE IF NOT EXISTS campaigns (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    advertiser_slug TEXT NOT NULL REFERENCES advertisers(slug),
    name            TEXT NOT NULL,
    offer_url       TEXT NOT NULL,
    payout          REAL DEFAULT 0,
    currency        TEXT DEFAULT 'USD',
    event           TEXT DEFAULT 'sale',
    cap_monthly     INTEGER,
    status          TEXT DEFAULT 'active',
    created_at      TEXT DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_campaigns_adv ON campaigns(advertiser_slug, status);
`);

// Additive, guarded — campaign_id on clicks + conversions (NULL = no specific campaign).
const clickColsG6 = db.prepare('PRAGMA table_info(clicks)').all().map(c => c.name);
if (!clickColsG6.includes('campaign_id')) db.exec('ALTER TABLE clicks ADD COLUMN campaign_id INTEGER REFERENCES campaigns(id)');
const convColsG6 = db.prepare('PRAGMA table_info(conversions)').all().map(c => c.name);
if (!convColsG6.includes('campaign_id')) db.exec('ALTER TABLE conversions ADD COLUMN campaign_id INTEGER REFERENCES campaigns(id)');
db.exec('CREATE INDEX IF NOT EXISTS idx_clicks_campaign ON clicks(campaign_id)');
db.exec('CREATE INDEX IF NOT EXISTS idx_conv_campaign   ON conversions(campaign_id)');

// ---------------------------------------------------------------------------
// MMP sync log (F20) — one row per manual AppsFlyer sync run
// ---------------------------------------------------------------------------
db.exec(`
  CREATE TABLE IF NOT EXISTS mmp_sync_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    advertiser_slug TEXT NOT NULL,
    synced_at       TEXT DEFAULT (datetime('now')),
    events_pulled   INTEGER NOT NULL DEFAULT 0,
    matched         INTEGER NOT NULL DEFAULT 0,
    auto_approved   INTEGER NOT NULL DEFAULT 0,
    auto_rejected   INTEGER NOT NULL DEFAULT 0,
    errors          TEXT,
    status          TEXT NOT NULL DEFAULT 'success'
  );
  CREATE INDEX IF NOT EXISTS idx_mmp_sync_adv ON mmp_sync_log(advertiser_slug, synced_at);
`);

// Conversions whose AppsFlyer media_source = "restricted" (attributed to a privacy-
// restricted SRN, not our affiliate) are left pending for manual review rather than
// auto-decided; this column records how many a sync flagged.
const mmpLogCols = db.prepare('PRAGMA table_info(mmp_sync_log)').all().map(c => c.name);
if (!mmpLogCols.includes('flagged')) db.exec('ALTER TABLE mmp_sync_log ADD COLUMN flagged INTEGER NOT NULL DEFAULT 0');

// ===========================================================================
// Group 7 — Operational growth: commission tiers, publisher notifications,
//   advertiser self-onboarding, scheduled weekly reports.
// ===========================================================================

// G7-3 — per-advertiser commission tiers. The highest tier a publisher has
// reached (by their approved-conversion count with that advertiser) sets the
// flat payout rate, overriding the advertiser's default payout_amount.
db.exec(`
  CREATE TABLE IF NOT EXISTS commission_tiers (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    advertiser_slug  TEXT NOT NULL,
    min_conversions  INTEGER NOT NULL,
    payout_rate      REAL NOT NULL,
    currency         TEXT NOT NULL DEFAULT 'USD'
  );
  CREATE INDEX IF NOT EXISTS idx_tiers_adv ON commission_tiers(advertiser_slug, min_conversions);
`);

// G7-4 — publisher notification outbox. One row per dispatched publisher email
// (gated by the per-type Settings toggles). Persisted so delivery is observable
// independent of SMTP, and doubles as a notification history.
db.exec(`
  CREATE TABLE IF NOT EXISTS publisher_notifications (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    publisher   TEXT NOT NULL,
    email       TEXT NOT NULL DEFAULT '',
    type        TEXT NOT NULL,
    subject     TEXT NOT NULL DEFAULT '',
    sent        INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_pubnotif_pub  ON publisher_notifications(publisher, type);
`);

// G7-5 — advertiser self-onboarding applications (public submissions, admin-decided).
db.exec(`
  CREATE TABLE IF NOT EXISTS advertiser_applications (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    email       TEXT NOT NULL,
    website     TEXT NOT NULL DEFAULT '',
    notes       TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'pending',
    created_at  TEXT DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_advapps_status ON advertiser_applications(status);
`);

// G7-4 / G7-6 — notification toggles (default on). INSERT OR IGNORE never clobbers
// an admin's saved preference.
for (const [key, value] of [
  ['notify_conversion_approved',  'true'],
  ['notify_marketplace_approved', 'true'],
  ['notify_invoice_ready',        'true'],
  ['weekly_report',               'true'],
]) {
  db.prepare('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)').run(key, value);
}

// Sessions table — sessions live in affiliate.db (one file, always present), served by
// better-sqlite3-session-store with this `db` (node:sqlite) as its client. See server.js.
db.exec(`
  CREATE TABLE IF NOT EXISTS sessions (
    sid    TEXT PRIMARY KEY,
    sess   TEXT NOT NULL,
    expire INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_sessions_expire ON sessions(expire);
`);

// Seed a legacy advertiser so pre-migration rows have a valid foreign key target
db.prepare(`
  INSERT OR IGNORE INTO advertisers (slug, name, offer_url, status)
  VALUES ('legacy', 'Legacy (Pre-migration)', '', 'paused')
`).run();

// One-time backfill: create publisher↔advertiser assignments for every pair
// that already has click or conversion history, so enabling assignment-gated
// postbacks does not drop live traffic from existing publishers. Guarded by a
// settings flag so it only runs once (admins can freely unassign afterwards).
const backfilled = db.prepare("SELECT value FROM settings WHERE key = 'assignments_backfilled'").get()?.value;
if (backfilled !== 'done') {
  db.exec(`
    INSERT OR IGNORE INTO publisher_advertisers (publisher_id, advertiser_id)
    SELECT DISTINCT p.id, a.id
    FROM (
      SELECT publisher, advertiser_slug FROM clicks
      UNION
      SELECT publisher, advertiser_slug FROM conversions
    ) hist
    JOIN publishers  p ON p.username = hist.publisher
    JOIN advertisers a ON a.slug     = hist.advertiser_slug
    WHERE a.slug != 'legacy'
  `);
  db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('assignments_backfilled', 'done')").run();
}

module.exports = db;
