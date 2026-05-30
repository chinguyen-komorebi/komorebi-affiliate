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
    status        TEXT NOT NULL DEFAULT 'active',
    created_at    TEXT DEFAULT (datetime('now'))
  );
`);

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

// Ensure index exists for api_key_hash on existing databases
db.exec('CREATE INDEX IF NOT EXISTS idx_pub_api_key_hash ON publishers(api_key_hash)');

// Backfill: generate API keys for any publisher that doesn't have one
const needKey = db.prepare('SELECT id FROM publishers WHERE api_key IS NULL').all();
const setKey  = db.prepare('UPDATE publishers SET api_key = ? WHERE id = ?');
for (const p of needKey) {
  setKey.run('kom_live_' + randomBytes(16).toString('hex'), p.id);
}

// Backfill: compute api_key_hash for any publisher that has api_key but no hash yet
const needHash = db.prepare('SELECT id, api_key FROM publishers WHERE api_key IS NOT NULL AND api_key_hash IS NULL').all();
const setHash  = db.prepare('UPDATE publishers SET api_key_hash = ? WHERE id = ?');
for (const p of needHash) {
  setHash.run(createHash('sha256').update(p.api_key).digest('hex'), p.id);
}

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

// Seed a legacy advertiser so pre-migration rows have a valid foreign key target
db.prepare(`
  INSERT OR IGNORE INTO advertisers (slug, name, offer_url, status)
  VALUES ('legacy', 'Legacy (Pre-migration)', '', 'paused')
`).run();

module.exports = db;
