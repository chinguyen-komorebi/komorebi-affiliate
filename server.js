'use strict';

const crypto      = require('node:crypto');
const fs          = require('node:fs');
const os          = require('node:os');
const path        = require('node:path');
const express     = require('express');
const session     = require('express-session');
const SQLiteStore  = require('better-sqlite3-session-store')(session);
const multer      = require('multer');
const nodemailer  = require('nodemailer');
const cron        = require('node-cron');
const db          = require('./db');
const geoip       = require('geoip-lite');
const helmet      = require('helmet');

// CSV upload — memory storage, 10 MB cap, CSV only
const csvUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) =>
    /\.(csv|txt)$/i.test(file.originalname) ? cb(null, true) : cb(new Error('CSV files only')),
}).single('csv_file');

function parseCSV(buf) {
  const text  = buf.toString('utf-8').replace(/^﻿/, ''); // strip BOM
  const lines = text.split(/\r?\n/).filter(l => l.trim());
  if (lines.length < 2) return [];

  function splitLine(line) {
    const fields = [];
    let field = '', inQ = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (c === '"') {
        if (inQ && line[i + 1] === '"') { field += '"'; i++; }
        else inQ = !inQ;
      } else if (c === ',' && !inQ) { fields.push(field.trim()); field = ''; }
      else field += c;
    }
    fields.push(field.trim());
    return fields;
  }

  const headers = splitLine(lines[0]).map(h => h.toLowerCase().replace(/[\s\-]+/g, '_'));
  return lines.slice(1).map(l => {
    const vals = splitLine(l);
    const row  = {};
    headers.forEach((h, i) => { row[h] = (vals[i] ?? '').trim(); });
    return row;
  }).filter(r => Object.values(r).some(v => v !== ''));
}

const app = express();
app.set('trust proxy', 1);

// I1 — per-request CSP nonce. Generated BEFORE helmet so the CSP header's
// scriptSrc nonce-<base64> matches the nonce we stamp onto every inline <script>
// (done centrally in the res.send wrapper below). 'unsafe-inline' is removed from
// scriptSrc: all inline event-handler attributes have been refactored to delegated
// addEventListener in BEHAVIORS_JS, so no inline handlers remain to allow.
app.use((req, res, next) => { res.locals.cspNonce = crypto.randomBytes(16).toString('base64'); next(); });

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc:   ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"], // styleSrc keeps 'unsafe-inline' (lower risk)
      fontSrc:    ["'self'", "https://fonts.gstatic.com"],
      scriptSrc:  ["'self'", (req, res) => `'nonce-${res.locals.cspNonce}'`],
      imgSrc:     ["'self'", "data:"],
    },
  },
  // F19(G) — explicit HSTS (sent by browsers only over HTTPS). 1 year + subdomains.
  hsts: { maxAge: 31_536_000, includeSubDomains: true },
}));
// F19(G) — Permissions-Policy (opt out of FLoC/Topics)
app.use((req, res, next) => { res.setHeader('Permissions-Policy', 'interest-cohort=()'); next(); });

// I1 — CSP nonce plumbing for HTML responses. Centralized here (rather than threaded
// through ~30 template functions): for any full HTML page we (1) stamp the per-request
// nonce onto every inline <script> so it matches the CSP header, and (2) inject the
// global delegated-behaviors script (BEHAVIORS_JS) that replaces all former inline
// on* event handlers. styleSrc still allows 'unsafe-inline', so inline style="" is fine.
app.use((req, res, next) => {
  const send = res.send.bind(res);
  res.send = (body) => {
    if (typeof body === 'string' && body.includes('</body>')) {
      const n = res.locals.cspNonce;
      body = body
        .replace(/<script>/g, `<script nonce="${n}">`)
        .replace('</body>', `<script nonce="${n}">${BEHAVIORS_JS}</script></body>`);
    }
    return send(body);
  };
  next();
});

app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// F19(F) — input hardening on POST bodies: strip null bytes, reject oversized fields.
app.use((req, res, next) => {
  if (req.body && typeof req.body === 'object') {
    for (const [k, v] of Object.entries(req.body)) {
      if (typeof v === 'string') {
        if (v.length > 2000) return res.status(400).json({ error: `Field "${k}" exceeds 2000 characters` });
        req.body[k] = v.replace(/\0/g, '');
      } else if (Array.isArray(v)) {
        for (let i = 0; i < v.length; i++) {
          if (typeof v[i] === 'string') {
            if (v[i].length > 2000) return res.status(400).json({ error: `Field "${k}" exceeds 2000 characters` });
            v[i] = v[i].replace(/\0/g, '');
          }
        }
      }
    }
  }
  next();
});

// Persist sessions in the main application database (affiliate.db) rather than a
// separate sessions.db file. One file means it always exists and can't be deleted
// out from under the store (the old separate sessions.db could go missing, causing
// "no such column: expire" on a fresh start). `db` (node:sqlite, from db.js) is a
// valid client for better-sqlite3-session-store — the store is pure JS and only uses
// prepare/run/get/all/exec, so this also drops the native better-sqlite3 dependency.
// The `sessions` table + index are created in db.js so they exist before the store runs.
app.use(session({
  // Prune expired rows every 15 min so the sessions table doesn't grow unbounded.
  store: new SQLiteStore({ client: db, expired: { clear: true, intervalMs: 15 * 60 * 1000 } }),
  secret: process.env.SESSION_SECRET || 'komorebi-dev-secret-change-in-prod',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'strict',                 // F18(A) — hardened from 'lax'
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 60 * 60 * 1000,        // F18(A) — 24h cookie ceiling; admin + publisher also have a 5-min idle timeout
  },
}));

const PORT       = process.env.PORT       || 3000;
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
let ADMIN_PASS   = process.env.ADMIN_PASS;
const BASE_URL   = process.env.BASE_URL   || `http://localhost:${PORT}`;

if (!process.env.SESSION_SECRET) {
  if (process.env.NODE_ENV === 'production') {
    console.error('FATAL: SESSION_SECRET must be set in production.');
    process.exit(1);
  }
  console.warn('WARNING: SESSION_SECRET not set — using insecure default. Set it in production.');
}

const ADMIN_EMAIL    = process.env.ADMIN_EMAIL        || 'chi@komorebimedia.com';
const GMAIL_USER     = process.env.GMAIL_USER;
const GMAIL_PASS     = process.env.GMAIL_PASS;
const TELEGRAM_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const TELEGRAM_CHAT  = process.env.TELEGRAM_CHAT_ID   || '';
const SLACK_URL      = process.env.SLACK_WEBHOOK_URL  || '';

if (process.env.NODE_ENV === 'production' && !ADMIN_PASS) {
  console.error('FATAL: ADMIN_PASS must be set in production.');
  process.exit(1);
}

// M1 — hash the admin password once at startup; login compares in constant time
// (timingSafeEqual via checkPassword), never a plaintext === comparison.
// Persisted in the DB (admin_settings.admin_pass_hash) so a password changed via the
// admin UI survives restarts instead of reverting to the ADMIN_PASS env var. The DB
// value takes priority over env; the first boot migrates the env hash into the DB.
let ADMIN_PASS_HASH = null;
{
  const storedHash = db.prepare("SELECT value FROM admin_settings WHERE key = 'admin_pass_hash'").get()?.value;
  if (storedHash) {
    ADMIN_PASS_HASH = storedHash;                       // DB wins — UI-changed password persists
  } else if (ADMIN_PASS) {
    ADMIN_PASS_HASH = hashPassword(ADMIN_PASS);         // first boot — migrate env password into the DB
    db.prepare("INSERT OR REPLACE INTO admin_settings (key, value) VALUES ('admin_pass_hash', ?)").run(ADMIN_PASS_HASH);
  }
}

// ---------------------------------------------------------------------------
// F20 — MMP (AppsFlyer) config + token encryption (AES-256-GCM)
// ---------------------------------------------------------------------------
const MMP_APPSFLYER_BASE = process.env.MMP_APPSFLYER_BASE || 'https://hq1.appsflyer.com';

function mmpKey() {
  const k = process.env.MMP_ENCRYPTION_KEY;
  if (!k) return null;
  return /^[0-9a-fA-F]{64}$/.test(k) ? Buffer.from(k, 'hex') : crypto.createHash('sha256').update(k).digest();
}
if (!mmpKey()) {
  console.warn('WARNING: MMP_ENCRYPTION_KEY not set — MMP API tokens will be stored in PLAINTEXT. Set a 32-byte hex key in production.');
}

// Encrypt an MMP token for storage. Returns "enc:v1:<iv>:<tag>:<ct>" (hex) or, if
// no key is configured, the plaintext (a startup warning is logged in that case).
function encryptToken(plain) {
  if (plain == null || plain === '') return null;
  const key = mmpKey();
  if (!key) return plain;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  return `enc:v1:${iv.toString('hex')}:${cipher.getAuthTag().toString('hex')}:${ct.toString('hex')}`;
}
// Decrypt a stored token. Plaintext (no "enc:v1:" prefix) is returned as-is.
function decryptToken(stored) {
  if (stored == null || stored === '') return null;
  if (!String(stored).startsWith('enc:v1:')) return stored;
  const key = mmpKey();
  if (!key) return null;
  try {
    const [, , ivh, tagh, cth] = stored.split(':');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivh, 'hex'));
    decipher.setAuthTag(Buffer.from(tagh, 'hex'));
    return Buffer.concat([decipher.update(Buffer.from(cth, 'hex')), decipher.final()]).toString('utf8');
  } catch { return null; }
}

// Pull in-app events from the AppsFlyer Reports API v5 (CSV) for a date range.
// Returns normalized [{ click_id, status }] where status ∈ {attributed, organic, fraud}.
//
// QA1 — real AppsFlyer raw in-app-events columns are: appsflyer_id, customer_user_id,
// event_name, event_time, media_source, campaign (NOT click_id / status). We therefore:
//   - take click_id from customer_user_id (the value the tracking link sets), then
//     fall back to appsflyer_id, then to a literal click_id column;
//   - derive attribution from media_source: organic → reject; "restricted" (attributed
//     to a privacy-restricted SRN such as Facebook/Google, i.e. NOT our affiliate) →
//     flag for manual review (left pending); anything else → approve. Falls back to a
//     literal status column (attributed/organic/fraud) for the non-real-export format.
async function mmpFetchEvents(adv, from, to, maxRows = 200000) {
  const token = decryptToken(adv.mmp_api_token);
  if (!token) throw new Error('No API token configured');
  if (!adv.mmp_app_id) throw new Error('No app ID configured');
  const url = `${MMP_APPSFLYER_BASE}/api/raw-data/export/app/${encodeURIComponent(adv.mmp_app_id)}/in_app_events_report/v5`
    + `?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}&maximum_rows=${maxRows}`;
  const resp = await fetch(url, { headers: { Authorization: `Bearer ${token}`, accept: 'text/csv' }, signal: AbortSignal.timeout(30_000) });
  if (!resp.ok) throw new Error(`AppsFlyer API HTTP ${resp.status}`);
  const rows = parseCSV(await resp.text()); // headers lowercased + underscored by parseCSV
  return rows
    .map(r => {
      const click_id = (r.customer_user_id || r.appsflyer_id || r.click_id || r.clickid || '').trim();
      const ms = (r.media_source != null ? String(r.media_source) : '').trim().toLowerCase();
      let status;
      if (ms) status = ms === 'organic' ? 'organic' : (ms === 'restricted' ? 'restricted' : 'attributed'); // real export
      else    status = (r.status || r.af_status || '').trim().toLowerCase(); // fallback format
      return { click_id, status };
    })
    .filter(r => r.click_id || r.status);
}

// Lightweight connection test — a 1-row report request validates token + app access.
async function mmpTestConnection(adv) {
  const token = decryptToken(adv.mmp_api_token);
  if (!token) return { ok: false, message: 'No API token configured.' };
  if (!adv.mmp_app_id) return { ok: false, message: 'No app ID configured.' };
  const today = new Date().toISOString().slice(0, 10);
  const url = `${MMP_APPSFLYER_BASE}/api/raw-data/export/app/${encodeURIComponent(adv.mmp_app_id)}/in_app_events_report/v5?from=${today}&to=${today}&maximum_rows=1`;
  try {
    const resp = await fetch(url, { headers: { Authorization: `Bearer ${token}`, accept: 'text/csv' }, signal: AbortSignal.timeout(15_000) });
    if (resp.ok) return { ok: true, message: 'Connection OK — AppsFlyer credentials valid.' };
    if (resp.status === 401 || resp.status === 403) return { ok: false, message: `Authentication failed (HTTP ${resp.status}).` };
    return { ok: false, message: `AppsFlyer returned HTTP ${resp.status}.` };
  } catch (e) { return { ok: false, message: `Connection error: ${e.message}` }; }
}

// Manual sync: pull last 24h of events, match by click_id, auto-approve/reject
// pending conversions, log the run, and send a Telegram summary.
async function runMmpSync(adv) {
  const fromStr = new Date(Date.now() - 24 * 3600_000).toISOString().slice(0, 10);
  const toStr   = new Date().toISOString().slice(0, 10);
  let events;
  try {
    events = await mmpFetchEvents(adv, fromStr, toStr);
  } catch (e) {
    db.prepare('INSERT INTO mmp_sync_log (advertiser_slug, events_pulled, matched, auto_approved, auto_rejected, errors, status) VALUES (?,?,?,?,?,?,?)')
      .run(adv.slug, 0, 0, 0, 0, JSON.stringify([e.message]), 'failed');
    sendTelegram(`\u{274C} MMP sync failed for <b>${adv.name}</b>: ${e.message}`).catch(() => {});
    return { ok: false, error: e.message };
  }

  let matched = 0, approved = 0, rejected = 0, flagged = 0; const errors = [];
  const findConv  = db.prepare("SELECT id, status FROM conversions WHERE advertiser_slug = ? AND click_id = ? ORDER BY (status='pending') DESC, id DESC LIMIT 1");
  const setStatus = db.prepare('UPDATE conversions SET status = ?, reason = ? WHERE id = ?');
  for (const ev of events) {
    if (!ev.click_id) { errors.push(`event with no click_id (status=${ev.status || '?'})`); continue; }
    const conv = findConv.get(adv.slug, ev.click_id);
    if (!conv) { errors.push(`unmatched click_id ${ev.click_id}`); continue; }
    matched++;
    if (conv.status !== 'pending') continue; // never override an already-decided conversion
    const s = ev.status;
    if (s === 'attributed' || s === 'non-organic' || s === 'nonorganic') { setStatus.run('approved', 'mmp_attributed', conv.id); approved++; }
    else if (s === 'organic' || s === 'fraud' || s === 'rejected')        { setStatus.run('rejected', 'mmp_rejected', conv.id); rejected++; }
    // "restricted" = attributed to a privacy-restricted SRN, not our affiliate. Leave the
    // conversion pending (tagged so an admin can review) rather than auto-deciding it.
    else if (s === 'restricted') { setStatus.run('pending', 'mmp_restricted', conv.id); flagged++; }
  }

  db.prepare('INSERT INTO mmp_sync_log (advertiser_slug, events_pulled, matched, auto_approved, auto_rejected, flagged, errors, status) VALUES (?,?,?,?,?,?,?,?)')
    .run(adv.slug, events.length, matched, approved, rejected, flagged, errors.length ? JSON.stringify(errors.slice(0, 500)) : null, 'success');
  sendTelegram(`\u{1F4E5} MMP sync — <b>${adv.name}</b>: ${events.length} pulled, ${matched} matched, ${approved} auto-approved, ${rejected} auto-rejected${flagged ? `, ${flagged} flagged for review` : ''}.`).catch(() => {});
  return { ok: true, events_pulled: events.length, matched, auto_approved: approved, auto_rejected: rejected, flagged, errors };
}

// ---------------------------------------------------------------------------
// IP whitelist for /postback/*
// Full current lists:
//   AppsFlyer : https://support.appsflyer.com/hc/en-us/articles/207032106
//   Adjust    : https://help.adjust.com/en/article/server-to-server-events
// Disable via POSTBACK_WHITELIST_ENABLED=false | add IPs via POSTBACK_TRUSTED_IPS=1.2.3.4
// ---------------------------------------------------------------------------

const APPSFLYER_IPS = [
  '52.6.61.4','52.87.100.26','54.82.244.37','54.83.87.6','54.209.4.3',
  '54.247.23.133','34.193.152.12','52.23.177.28','52.73.232.47',
  '52.73.178.39','54.164.118.156','54.86.29.77','34.202.42.78',
  '52.0.22.188','52.55.243.251','54.84.196.64','34.227.148.18',
  '34.228.55.40','52.72.214.218','3.209.104.136','3.218.36.71',
];
const ADJUST_IPS = [
  '52.28.45.153','52.29.210.126','52.57.50.121','52.58.201.201',
  '52.212.58.78','54.220.181.220','34.253.115.83','52.209.165.161',
];
const ADJUST_CIDRS = ['185.151.204.0/24'];
const EXTRA_IPS    = (process.env.POSTBACK_TRUSTED_IPS || '').split(',').filter(Boolean);
const WHITELIST_ON = process.env.POSTBACK_WHITELIST_ENABLED !== 'false';

function ipToInt(ip) {
  return ip.split('.').reduce((n, o) => (n << 8) | parseInt(o, 10), 0) >>> 0;
}
function inCidr(ip, cidr) {
  const [range, bits] = cidr.split('/');
  const mask = bits === '32' ? 0xffffffff : (~((1 << (32 - +bits)) - 1)) >>> 0;
  return (ipToInt(ip) & mask) === (ipToInt(range) & mask);
}
function isWhitelisted(ip) {
  if (!WHITELIST_ON) return true;
  const addr = ip.replace(/^::ffff:/, '');
  if (addr === '127.0.0.1' || addr === '::1') return true;
  return [...APPSFLYER_IPS, ...ADJUST_IPS, ...EXTRA_IPS].includes(addr)
    || ADJUST_CIDRS.some(c => inCidr(addr, c));
}

// ---------------------------------------------------------------------------
// Rate limiter — 100 req/min per IP (all routes)
// ---------------------------------------------------------------------------

const RATE_LIMIT_MAX          = parseInt(process.env.RATE_LIMIT_MAX, 10) > 0 ? parseInt(process.env.RATE_LIMIT_MAX, 10) : 100; // global req/min per IP
const POSTBACK_RATE_LIMIT_MAX = parseInt(process.env.POSTBACK_RATE_LIMIT_MAX, 10) > 0 ? parseInt(process.env.POSTBACK_RATE_LIMIT_MAX, 10) : 300; // F19(E) — MMP bulk postbacks
const adminLoginAttempts     = new Map(); // ip → { count, firstAt, blockedUntil }
const publisherLoginAttempts = new Map();

// Per-IP fixed-window rate limiter factory (60s window). Each limiter has its own map.
function makeRateLimiter(max) {
  const map = new Map();
  setInterval(() => { const now = Date.now(); for (const [k, r] of map) if (now > r.resetAt) map.delete(k); }, 60_000).unref();
  return function (req, res, next) {
    const ip = req.ip, now = Date.now();
    let r = map.get(ip);
    if (!r || now > r.resetAt) { r = { count: 0, resetAt: now + 60_000 }; map.set(ip, r); }
    r.count++;
    res.setHeader('X-RateLimit-Limit', String(max));
    res.setHeader('X-RateLimit-Remaining', Math.max(0, max - r.count));
    if (r.count > max) return res.status(429).json({ error: `Rate limit exceeded — max ${max} req/min` });
    next();
  };
}

const globalLimiter   = makeRateLimiter(RATE_LIMIT_MAX);
const postbackLimiter = makeRateLimiter(POSTBACK_RATE_LIMIT_MAX); // F19(E) mounted on /postback/*
const applyLimiter    = makeRateLimiter(10);                      // F19(E) mounted on /marketplace/apply

// Global limiter applies everywhere except /postback/* (those get their own higher limit).
app.use((req, res, next) => (req.path.startsWith('/postback/') ? next() : globalLimiter(req, res, next)));

const LOGIN_WINDOW_MS = 15 * 60_000;
const LOGIN_MAX_FAILS = 5;

function renderRateLimitPage(backUrl) {
  const css = `
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Inter',system-ui,sans-serif;background:#0d1117;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
    .card{background:#fff;border-radius:12px;padding:36px;width:100%;max-width:360px;box-shadow:0 8px 32px rgba(0,0,0,.5);text-align:center}
    .icon{width:44px;height:44px;background:#fff3cd;border:1px solid #ffc107;border-radius:10px;display:flex;align-items:center;justify-content:center;margin:0 auto 16px;font-size:20px}
    h1{font-size:17px;font-weight:600;color:#111827;margin-bottom:8px}
    p{font-size:13px;color:#6b7280;margin-bottom:24px;line-height:1.5}
    a{display:block;padding:10px;background:#00e5c3;color:#0d1117;border-radius:6px;font-size:14px;font-weight:600;text-decoration:none}
    a:hover{background:#00c9aa}
  `;
  return `<!DOCTYPE html><html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Too Many Attempts — Komorebi</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>${css}</style></head>
<body>
<div class="card">
  <div class="icon">&#x26A0;</div>
  <h1>Too many login attempts</h1>
  <p>Please try again in 15 minutes.</p>
  <a href="${backUrl}">Back to login</a>
</div>
</body></html>`;
}

function checkLoginLockout(req, res, map) {
  const ip  = req.ip;
  const now = Date.now();
  const a   = map.get(ip);
  if (a?.blockedUntil) {
    if (now < a.blockedUntil) {
      const backUrl = req.path.startsWith('/admin') ? '/admin/login' : '/publisher/login';
      return res.status(429).send(renderRateLimitPage(backUrl));
    }
    map.delete(ip);
  }
  return null;
}

function recordLoginFailure(ip, map) {
  const now = Date.now();
  let a = map.get(ip) || { count: 0, firstAt: now };
  if (now - a.firstAt > LOGIN_WINDOW_MS) a = { count: 0, firstAt: now };
  a.count++;
  if (a.count >= LOGIN_MAX_FAILS) a.blockedUntil = now + LOGIN_WINDOW_MS;
  map.set(ip, a);
}

function recordLoginSuccess(ip, map) {
  map.delete(ip);
}

// ---------------------------------------------------------------------------
// Postback logger → postback.log  (NDJSON)
// ---------------------------------------------------------------------------

// NOTE: this append-only NDJSON debug log can grow unbounded, so rotate it
// externally (see ops/komorebi-postback.logrotate: daily, rotate 14, compress).
// Params are PII-masked (maskPII, same as the DB conversions.raw_params column)
// and the file is created mode 0600 so only the process owner can read it.
const logStream = fs.createWriteStream(path.join(__dirname, 'postback.log'), { flags: 'a', mode: 0o600 });
function logPostback(req, result) {
  logStream.write(JSON.stringify({ ts: new Date().toISOString(), ip: req.ip, params: maskPII(req.query), result }) + '\n');
}

// ---------------------------------------------------------------------------
// Email — nodemailer + daily cron
// ---------------------------------------------------------------------------

const transporter = (GMAIL_USER && GMAIL_PASS)
  ? nodemailer.createTransport({
      service: 'gmail',
      auth: { user: GMAIL_USER, pass: GMAIL_PASS },
    })
  : null;

if (!transporter) {
  console.warn('WARNING: GMAIL_USER / GMAIL_PASS not set — email notifications disabled.');
}

function getSetting(key, def = 'true') {
  return db.prepare('SELECT value FROM settings WHERE key = ?').get(key)?.value ?? def;
}
function setSetting(key, value) {
  db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').run(key, String(value));
}

// Audit log — write a row for every significant admin action
// ---------------------------------------------------------------------------
// Timezone helpers
// ---------------------------------------------------------------------------

const FALLBACK_TZ = 'Asia/Ho_Chi_Minh'; // UTC+7 — default when no cookie present

function validTz(tz) {
  if (!tz || typeof tz !== 'string' || tz.length > 64) return null;
  try { new Intl.DateTimeFormat('en', { timeZone: tz }); return tz; } catch { return null; }
}

function getCookie(req, name) {
  for (const part of (req.headers.cookie || '').split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) return decodeURIComponent(part.slice(eq + 1).trim());
  }
  return null;
}

function detectTz(req) {
  return validTz(getCookie(req, 'tz')) || FALLBACK_TZ;
}

// Format a SQLite UTC string ("YYYY-MM-DD HH:MM:SS") in any IANA timezone
function formatInTz(utcStr, tz) {
  const date = new Date(utcStr.replace(' ', 'T') + 'Z');
  const safeTz = validTz(tz) || FALLBACK_TZ;
  return new Intl.DateTimeFormat('en-GB', {
    timeZone: safeTz,
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: false,
  }).format(date).replace(',', '');
}

// Backlog #12 — normalize a custom tracking domain to a bare host (strip scheme,
// path, port, whitespace, lowercase). Returns null for blank/invalid input.
function normalizeDomain(input) {
  let d = (input || '').trim().toLowerCase();
  if (!d) return null;
  d = d.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '');
  return /^[a-z0-9.-]+\.[a-z]{2,}$/.test(d) ? d : null;
}

// Base URL for a publisher's tracking links — their custom domain if set, else the platform default.
function publisherBase(pub) {
  return pub && pub.custom_domain ? `https://${pub.custom_domain}` : BASE_URL;
}

function generateApiKey() {
  return 'kom_live_' + crypto.randomBytes(16).toString('hex');
}

function hashApiKey(key) {
  return crypto.createHash('sha256').update(key).digest('hex');
}

function requireApiKey(req, res, next) {
  const key = (req.headers['x-api-key'] || '').trim();
  if (!key.startsWith('kom_live_')) {
    return res.status(401).json({ error: 'Missing or invalid API key. Send X-API-Key: kom_live_...' });
  }
  const keyHash = hashApiKey(key);
  // M3 — hash-only lookup (no plaintext fallback; all keys have api_key_hash).
  const pub = db.prepare(
    "SELECT * FROM publishers WHERE api_key_hash = ? AND status = 'active'"
  ).get(keyHash);
  if (!pub) {
    return res.status(401).json({ error: 'API key not found or account is paused' });
  }
  req.publisher = pub;
  next();
}

// F18(C) — PII masking for audit-log detail. Masks API keys, emails, phones.
function maskValue(s) {
  if (typeof s !== 'string') return s;
  let out = s;
  out = out.replace(/kom_live_[A-Za-z0-9]+/g, 'kom_live_***');                       // never store full API keys
  out = out.replace(/([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/g,
    (_m, a, d) => `${a}***@${d}`);                                                    // c***@domain
  // VN phone, tolerant of spaces/dots/dashes between digits (e.g. "+84 967 123 857").
  out = out.replace(/(?:\+?84|0)[\s.-]?\d(?:[\s.-]?\d){7,10}/g, (m) => {
    const d = m.replace(/\D/g, '');
    return (d.length >= 9 && d.length <= 12) ? d.slice(0, 4) + '***' + d.slice(-3) : m;
  });
  return out;
}
function maskPII(v) {
  if (typeof v === 'string') return maskValue(v);
  if (Array.isArray(v)) return v.map(maskPII);
  if (v && typeof v === 'object') { const o = {}; for (const [k, val] of Object.entries(v)) o[k] = maskPII(val); return o; }
  return v;
}

function logAudit(action, entityType, entityId, detail, reqOrIp) {
  const isReq = reqOrIp && typeof reqOrIp === 'object';
  const ip = isReq ? getIp(reqOrIp) : (reqOrIp || '');
  const tz = isReq ? detectTz(reqOrIp) : FALLBACK_TZ;
  db.prepare(
    'INSERT INTO audit_log (action, entity_type, entity_id, detail, ip_address, timezone) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(action, entityType ?? null, String(entityId ?? ''), JSON.stringify(maskPII(detail ?? {})), ip, tz);
}


function emailEnabled()   { return transporter && getSetting('email_notifications') === 'true'; }
function summaryEnabled() { return transporter && getSetting('daily_summary')       === 'true'; }

// ---------------------------------------------------------------------------
// Webhook helpers — Telegram + Slack
// ---------------------------------------------------------------------------

function telegramOk()          { return !!(TELEGRAM_TOKEN && TELEGRAM_CHAT); }
function slackOk()             { return !!SLACK_URL; }
function anyWebhook()          { return telegramOk() || slackOk(); }
function webhookNotifEnabled() { return anyWebhook() && getSetting('webhook_notifications', 'true') === 'true'; }
function webhookSumEnabled()   { return anyWebhook() && getSetting('webhook_daily_summary', 'true') === 'true'; }

async function postJson(url, body) {
  return fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(8_000),
  });
}

async function sendTelegram(text) {
  if (!telegramOk()) return;
  const r = await postJson(`https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage`, {
    chat_id: TELEGRAM_CHAT, text, parse_mode: 'HTML',
  });
  if (!r.ok) throw new Error(`Telegram ${r.status}: ${await r.text()}`);
}

async function sendSlack(text, blocks) {
  if (!slackOk()) return;
  const r = await postJson(SLACK_URL, blocks ? { text, blocks } : { text });
  if (!r.ok) throw new Error(`Slack ${r.status}: ${await r.text()}`);
}

async function fireWebhookConversion({ advertiserName, publisher, payout, event }) {
  if (!webhookNotifEnabled()) return;
  const amt   = `$${Number(payout).toFixed(2)}`;
  const plain = `\u{1F4B0} New conversion: ${advertiserName} via ${publisher} — ${amt} (${event})`;
  await Promise.allSettled([
    sendTelegram(plain),
    sendSlack(plain, [
      {
        type: 'section',
        text: { type: 'mrkdwn', text: `\u{1F4B0} *New Conversion*` },
        fields: [
          { type: 'mrkdwn', text: `*Advertiser*\n${advertiserName}` },
          { type: 'mrkdwn', text: `*Publisher*\n${publisher}` },
          { type: 'mrkdwn', text: `*Payout*\n${amt}` },
          { type: 'mrkdwn', text: `*Event*\n${event}` },
        ],
      },
    ]),
  ]);
}

async function fireWebhookDailySummary() {
  if (!webhookSumEnabled()) return;
  const yesterday = new Date(Date.now() + 8 * 3600_000 - 86_400_000).toISOString().slice(0, 10);
  // QA2 — group totals by currency (USD and VND shown separately, never summed).
  const curRows = db.prepare(`
    SELECT currency, COUNT(*) as conversions,
           COALESCE(SUM(payout), 0) as total_payout,
           COALESCE(SUM(CASE WHEN status='approved' THEN payout ELSE 0 END), 0) as approved_payout
    FROM conversions WHERE date(received_at, '+8 hours') = ? GROUP BY currency
  `).all(yesterday);
  const conversions = curRows.reduce((s, r) => s + r.conversions, 0);
  if (conversions === 0) return;
  const totalStr    = curRows.map(r => fmtCur(r.total_payout, r.currency)).join(' · ');
  const approvedStr = curRows.map(r => fmtCur(r.approved_payout, r.currency)).join(' · ');
  const byAdv = db.prepare(`
    SELECT a.name, COUNT(*) as conversions, cv.currency, COALESCE(SUM(cv.payout),0) as payout
    FROM conversions cv JOIN advertisers a ON a.slug = cv.advertiser_slug
    WHERE date(cv.received_at, '+8 hours') = ?
    GROUP BY cv.advertiser_slug, cv.currency ORDER BY payout DESC
  `).all(yesterday);
  const advLines = byAdv.map(r => `• ${r.name}: ${r.conversions} conv — ${fmtCur(r.payout, r.currency)}`).join('\n');
  const plain = `\u{1F4CA} Daily Summary ${yesterday} SGT\n` +
    `Conversions: ${conversions} | Total: ${totalStr} | Approved: ${approvedStr}\n` +
    advLines;
  await Promise.allSettled([
    sendTelegram(plain),
    sendSlack(plain, [
      {
        type: 'section',
        text: { type: 'mrkdwn', text: `\u{1F4CA} *Daily Summary — ${yesterday} SGT*` },
        fields: [
          { type: 'mrkdwn', text: `*Conversions*\n${conversions}` },
          { type: 'mrkdwn', text: `*Total Payout*\n${totalStr}` },
          { type: 'mrkdwn', text: `*Approved*\n${approvedStr}` },
        ],
      },
      ...(byAdv.length > 0 ? [{
        type: 'section',
        text: { type: 'mrkdwn', text: byAdv.map(r => `• *${r.name}*: ${r.conversions} conv — ${fmtCur(r.payout, r.currency)}`).join('\n') },
      }] : []),
    ]),
  ]);
}

async function sendMail(opts) {
  if (!transporter) return;
  return transporter.sendMail({ from: `"Komorebi Tracker" <${GMAIL_USER}>`, to: ADMIN_EMAIL, ...opts });
}

async function sendConversionEmail({ advertiserName, publisher, payout, click_id, event, received_at }) {
  if (!emailEnabled()) return;
  await sendMail({
    subject: `[Komorebi] New Conversion — ${advertiserName} $${Number(payout).toFixed(2)}`,
    text:
      `New conversion recorded on Komorebi Affiliate Tracker.\n\n` +
      `Advertiser : ${advertiserName}\n` +
      `Publisher  : ${publisher}\n` +
      `Payout     : $${Number(payout).toFixed(2)}\n` +
      `Event      : ${event}\n` +
      `Click ID   : ${click_id}\n` +
      `Timestamp  : ${received_at} (UTC)\n`,
    html: `
      <div style="font-family:sans-serif;max-width:520px">
        <h2 style="color:#1d1d1f;margin-bottom:4px">New Conversion</h2>
        <p style="color:#6e6e73;font-size:13px;margin-bottom:20px">Komorebi Affiliate Tracker</p>
        <table style="border-collapse:collapse;width:100%">
          ${[
            ['Advertiser', advertiserName],
            ['Publisher',  publisher],
            ['Payout',     `<strong style="color:#2e7d32">$${Number(payout).toFixed(2)}</strong>`],
            ['Event',      event],
            ['Click ID',   `<code style="font-size:12px">${click_id}</code>`],
            ['Timestamp',  `${received_at} UTC`],
          ].map(([k,v]) => `<tr>
            <td style="padding:8px 12px;background:#f5f5f7;font-weight:600;font-size:13px;width:110px">${k}</td>
            <td style="padding:8px 12px;font-size:13px;border-bottom:1px solid #f0f0f0">${v}</td>
          </tr>`).join('')}
        </table>
      </div>`,
  });
}

async function sendDailySummaryEmail() {
  if (!summaryEnabled()) return;

  // "Yesterday" in Singapore time (UTC+8) — DB stores UTC, offset by +8h for SGT date
  const yesterday = new Date(Date.now() + 8 * 3600_000 - 86_400_000).toISOString().slice(0, 10);

  // QA2 — totals grouped by currency (USD and VND shown separately, never summed).
  const curRows = db.prepare(`
    SELECT currency, COUNT(*) as conversions,
           COALESCE(SUM(payout), 0) as total_payout,
           COALESCE(SUM(CASE WHEN status='approved' THEN payout ELSE 0 END), 0) as approved_payout
    FROM conversions WHERE date(received_at, '+8 hours') = ? GROUP BY currency
  `).all(yesterday);

  const conversions = curRows.reduce((s, r) => s + r.conversions, 0);
  if (conversions === 0) return; // nothing to report
  const totalStr    = curRows.map(r => fmtCur(r.total_payout, r.currency)).join(' · ');
  const approvedStr = curRows.map(r => fmtCur(r.approved_payout, r.currency)).join(' · ');

  const byAdv = db.prepare(`
    SELECT a.name, COUNT(*) as conversions, cv.currency, COALESCE(SUM(cv.payout),0) as payout
    FROM conversions cv
    JOIN advertisers a ON a.slug = cv.advertiser_slug
    WHERE date(cv.received_at, '+8 hours') = ?
    GROUP BY cv.advertiser_slug, cv.currency ORDER BY payout DESC
  `).all(yesterday);

  // QA2 — per-currency rows per publisher (a publisher running USD + VND advertisers
  // appears as separate rows; payouts are never summed across currencies).
  const byPub = db.prepare(`
    SELECT publisher, COUNT(*) as conversions, currency, COALESCE(SUM(payout),0) as payout
    FROM conversions
    WHERE date(received_at, '+8 hours') = ?
    GROUP BY publisher, currency ORDER BY payout DESC
  `).all(yesterday);

  // Payout passed pre-formatted (string) so the table renders the currency as-is.
  const tableHtml = (rows, cols) => `
    <table style="border-collapse:collapse;width:100%;margin-bottom:20px">
      <thead><tr>${cols.map(c=>`<th style="padding:6px 12px;background:#f5f5f7;text-align:left;font-size:12px">${c}</th>`).join('')}</tr></thead>
      <tbody>${rows.map(r=>`<tr>${Object.values(r).map(v=>`<td style="padding:7px 12px;border-bottom:1px solid #f0f0f0;font-size:13px">${v}</td>`).join('')}</tr>`).join('')}</tbody>
    </table>`;

  await sendMail({
    subject: `[Komorebi] Daily Summary — ${yesterday} SGT`,
    text:
      `Daily Summary for ${yesterday} (Singapore time)\n\n` +
      `Conversions : ${conversions}\n` +
      `Total Payout: ${totalStr}\n` +
      `Approved    : ${approvedStr}\n\n` +
      `By Advertiser:\n${byAdv.map(r=>`  ${r.name}: ${r.conversions} conv — ${fmtCur(r.payout, r.currency)}`).join('\n')}\n\n` +
      `By Publisher:\n${byPub.map(r=>`  ${r.publisher}: ${r.conversions} conv — ${fmtCur(r.payout, r.currency)}`).join('\n')}\n`,
    html: `
      <div style="font-family:sans-serif;max-width:600px">
        <h2 style="color:#1d1d1f;margin-bottom:4px">Daily Summary</h2>
        <p style="color:#6e6e73;font-size:13px;margin-bottom:20px">${yesterday} · Singapore Time</p>
        <div style="display:flex;gap:16px;margin-bottom:24px">
          ${[
            ['Conversions', conversions],
            ['Total Payout', totalStr],
            ['Approved', approvedStr],
          ].map(([l,v])=>`<div style="background:#f5f5f7;border-radius:8px;padding:12px 16px;min-width:120px">
            <div style="font-size:11px;color:#6e6e73;font-weight:700;text-transform:uppercase;margin-bottom:4px">${l}</div>
            <div style="font-size:22px;font-weight:700">${v}</div>
          </div>`).join('')}
        </div>
        <h3 style="font-size:13px;margin-bottom:8px">By Advertiser</h3>
        ${tableHtml(byAdv.map(r=>({Advertiser:r.name,Conversions:r.conversions,Payout:fmtCur(r.payout,r.currency)})),['Advertiser','Conversions','Payout'])}
        <h3 style="font-size:13px;margin-bottom:8px">By Publisher</h3>
        ${tableHtml(byPub.map(r=>({Publisher:r.publisher,Conversions:r.conversions,Payout:fmtCur(r.payout,r.currency)})),['Publisher','Conversions','Payout'])}
      </div>`,
  });
}

// ---------------------------------------------------------------------------
// S2S postback — fire publisher's postback URL on conversion
// ---------------------------------------------------------------------------

const S2S_MAX_ATTEMPTS = 3;
const S2S_RETRY_MS     = 5 * 60 * 1_000; // 5 minutes

async function fireS2SPostback(publisher, data, attempt = 1) {
  const { click_id, payout, event, advertiser } = data;
  const pub = db.prepare('SELECT postback_url FROM publishers WHERE username = ?').get(publisher);
  if (!pub?.postback_url) return;

  // Macro map — supports {click_id} {payout} {event} {advertiser},
  // sub-params {sub1}…{sub5} {subpub} (F7), and mapped {campaign} {adgroup} {creative} {network} (F10).
  // Missing values resolve to empty string; every occurrence is replaced.
  const macros = {
    click_id, payout, event, advertiser,
    sub1: data.sub1, sub2: data.sub2, sub3: data.sub3, sub4: data.sub4, sub5: data.sub5, subpub: data.subpub,
    campaign: data.campaign, adgroup: data.adgroup, creative: data.creative, network: data.network,
  };
  const url = Object.entries(macros).reduce(
    (u, [k, v]) => u.replaceAll(`{${k}}`, encodeURIComponent(v == null ? '' : String(v))),
    pub.postback_url
  );

  let http_status = null;
  let success     = false;
  let error       = null;

  try {
    const resp  = await fetch(url, { signal: AbortSignal.timeout(10_000) });
    http_status = resp.status;
    success     = resp.ok;
  } catch (e) {
    error = e.message;
  }

  db.prepare(`
    INSERT INTO postback_log (publisher, click_id, url, http_status, attempt, success, error)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(publisher, click_id, url, http_status, attempt, success ? 1 : 0, error);

  if (!success && attempt < S2S_MAX_ATTEMPTS) {
    setTimeout(
      () => fireS2SPostback(publisher, data, attempt + 1).catch(() => {}),
      S2S_RETRY_MS
    );
  }
}

// ---------------------------------------------------------------------------
// Admin auth — Session-based
// ---------------------------------------------------------------------------

function generateCsrfToken() {
  return crypto.randomBytes(24).toString('hex');
}

function verifyCsrf(req, res, next) {
  const bodyToken    = (req.body._csrf || '').trim();
  const sessionToken = req.session.csrfToken || '';
  if (!bodyToken || !sessionToken || bodyToken !== sessionToken) {
    return res.status(403).send('Invalid CSRF token');
  }
  next();
}

// Idle timeouts. ADMIN_IDLE_SECONDS (env) overrides BOTH admin and publisher (for tests).
const IDLE_OVERRIDE_MS = parseInt(process.env.ADMIN_IDLE_SECONDS, 10) > 0 ? parseInt(process.env.ADMIN_IDLE_SECONDS, 10) * 1000 : null;
const ADMIN_IDLE_MS     = IDLE_OVERRIDE_MS ?? 5 * 60 * 1000; // admin auto-logout after 5 min idle
const PUBLISHER_IDLE_MS = IDLE_OVERRIDE_MS ?? 5 * 60 * 1000; // publisher auto-logout after 5 min idle

function requireAdmin(req, res, next) {
  if (!req.session?.isAdmin) return res.redirect('/admin/login');
  // F18(A) — enforce idle timeout: destroy session if inactive > 5 min, else bump activity.
  const now = Date.now();
  if (req.session.adminLastActivity && now - req.session.adminLastActivity > ADMIN_IDLE_MS) {
    return req.session.destroy(() => res.redirect('/admin/login?err=' + encodeURIComponent('Session expired due to inactivity')));
  }
  req.session.adminLastActivity = now;
  if (!req.session.csrfToken) req.session.csrfToken = generateCsrfToken();
  res.cookie('_csrf', req.session.csrfToken, {
    httpOnly: false,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
  });
  next();
}

// ---------------------------------------------------------------------------
// Publisher auth — session
// ---------------------------------------------------------------------------

function hashPassword(plain) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(plain, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function checkPassword(plain, stored) {
  try {
    const [salt, hash] = stored.split(':');
    const attempt = crypto.scryptSync(plain, salt, 64);
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), attempt);
  } catch { return false; }
}

function requirePublisher(req, res, next) {
  const id = req.session?.pubId;
  if (!id) return res.redirect('/publisher/login');
  // Idle timeout (same pattern as requireAdmin): destroy session if inactive > 5 min.
  const now = Date.now();
  if (req.session.pubLastActivity && now - req.session.pubLastActivity > PUBLISHER_IDLE_MS) {
    return req.session.destroy(() => res.redirect('/publisher/login?err=' + encodeURIComponent('Session expired')));
  }
  const pub = db.prepare('SELECT * FROM publishers WHERE id = ?').get(id);
  if (!pub || pub.status !== 'active') {
    req.session.destroy(() => {});
    return res.redirect('/publisher/login?err=Account+is+disabled');
  }
  req.session.pubLastActivity = now;
  // Ensure a CSRF token exists for the portal's POST forms (change password).
  if (!req.session.csrfToken) req.session.csrfToken = generateCsrfToken();
  req.publisher = pub;
  next();
}

// ---------------------------------------------------------------------------
// Publisher ↔ advertiser assignment + conversion-goal helpers
// ---------------------------------------------------------------------------

// Advertisers a publisher is assigned to (active, non-legacy), with the
// assignment metadata (payout_override / validity window / monthly cap).
function assignedAdvertisers(publisherId) {
  return db.prepare(`
    SELECT a.*, pa.payout_override, pa.valid_from, pa.valid_until, pa.monthly_cap, pa.assigned_at
    FROM publisher_advertisers pa
    JOIN advertisers a ON a.id = pa.advertiser_id
    WHERE pa.publisher_id = ? AND a.slug != 'legacy'
    ORDER BY a.name
  `).all(publisherId);
}

// Returns the assignment row for a publisher (username) ↔ advertiser (slug)
// pair, or null if the publisher is not assigned to that advertiser.
function getAssignment(username, slug) {
  return db.prepare(`
    SELECT pa.*
    FROM publisher_advertisers pa
    JOIN publishers  p ON p.id = pa.publisher_id
    JOIN advertisers a ON a.id = pa.advertiser_id
    WHERE p.username = ? AND a.slug = ?
  `).get(username, slug) || null;
}

// Pick an active goal for an advertiser whose event_token matches the postback
// event, or null. Used to choose a per-event payout.
function matchGoal(advertiserId, event) {
  return db.prepare(
    "SELECT * FROM goals WHERE advertiser_id = ? AND event_token = ? AND status = 'active'"
  ).get(advertiserId, event) || null;
}

// Backlog #7 — map an advertiser's SDK event name to the Komorebi event value.
// Case-insensitive on source_event. Returns the original event if no mapping exists.
function mapEvent(advertiserId, event) {
  if (!event) return event;
  const row = db.prepare(
    'SELECT mapped_event FROM event_mappings WHERE advertiser_id = ? AND lower(source_event) = lower(?)'
  ).get(advertiserId, event);
  return row ? row.mapped_event : event;
}

// Resolve the payout for a conversion. Precedence:
//   1. assignment.payout_override — always a fixed dollar amount, wins outright
//   2. matching goal           — fixed dollars, or percent of loan_amount
//   3. advertiser default      — fixed dollars, or percent of loan_amount
// Percentage with a missing/zero loan_amount yields 0 (note: 'missing_loan_amount');
// it never falls back to a fixed default. Returns { amount, note }.
function computePayout(assignment, adv, goal, loanAmount) {
  if (assignment.payout_override != null) {
    return { amount: assignment.payout_override, note: null };
  }
  const src = goal
    ? { type: goal.payout_type, value: goal.payout }
    : { type: adv.payout_type,  value: adv.payout_amount };

  if (src.type === 'percent') {
    if (!loanAmount || loanAmount <= 0) return { amount: 0, note: 'missing_loan_amount' };
    return { amount: Math.round(loanAmount * src.value) / 100, note: null }; // value% of loanAmount, 2dp
  }
  return { amount: src.value > 0 ? src.value : 0, note: null };
}

// Enforce an assignment's validity window and monthly cap at postback time.
// Returns { reason, message } when the conversion must be blocked, else null.
//   - valid_from / valid_until: inclusive UTC date window (YYYY-MM-DD)
//   - monthly_cap: max APPROVED conversions for this pair in the UTC month.
//     Note: conversions are recorded as 'pending' and only count once approved
//     (e.g. via reconciliation), so the cap blocks new postbacks only after
//     enough prior conversions have been approved.
function assignmentBlock(assignment, publisher, slug) {
  const today = new Date().toISOString().slice(0, 10); // UTC date
  if (assignment.valid_from && today < assignment.valid_from) {
    return { reason: 'assignment_not_active', message: `Assignment for "${slug}" is not active until ${assignment.valid_from}` };
  }
  if (assignment.valid_until && today > assignment.valid_until) {
    return { reason: 'assignment_expired', message: `Assignment for "${slug}" expired on ${assignment.valid_until}` };
  }
  if (assignment.monthly_cap != null) {
    const used = db.prepare(`
      SELECT COUNT(*) AS n FROM conversions
      WHERE publisher = ? AND advertiser_slug = ? AND status = 'approved'
        AND strftime('%Y-%m', received_at) = strftime('%Y-%m', 'now')
    `).get(publisher, slug).n;
    if (used >= assignment.monthly_cap) {
      return { reason: 'monthly_cap_reached', message: `Monthly cap of ${assignment.monthly_cap} reached for "${slug}" this month` };
    }
  }
  return null;
}

// F12 — count APPROVED conversions for an advertiser in the current UTC month,
// excluding anything before the manual cap-reset floor (cap_reset_at).
function advertiserApprovedCount(adv) {
  return db.prepare(`
    SELECT COUNT(*) AS n FROM conversions
    WHERE advertiser_slug = ? AND status = 'approved'
      AND strftime('%Y-%m', received_at) = strftime('%Y-%m', 'now')
      AND (? IS NULL OR received_at > ?)
  `).get(adv.slug, adv.cap_reset_at, adv.cap_reset_at).n;
}

// F12 — send a Telegram cap alert at a threshold (80 or 100) at most once per
// UTC month per threshold. Alert-throttle state lives on the advertiser row.
function maybeAlertAdvertiserCap(adv, used, cap, threshold) {
  const month = new Date().toISOString().slice(0, 7);
  const row = db.prepare('SELECT cap_alert_month, cap_alerted_80, cap_alerted_100 FROM advertisers WHERE id = ?').get(adv.id);
  let alerted80  = row.cap_alert_month === month ? row.cap_alerted_80  : 0;
  let alerted100 = row.cap_alert_month === month ? row.cap_alerted_100 : 0;
  if (threshold === 100 ? alerted100 : alerted80) {
    // already alerted this month for this threshold — just keep month current
    db.prepare('UPDATE advertisers SET cap_alert_month = ?, cap_alerted_80 = ?, cap_alerted_100 = ? WHERE id = ?')
      .run(month, alerted80, alerted100, adv.id);
    return;
  }
  if (threshold === 100) alerted100 = 1; else alerted80 = 1;
  db.prepare('UPDATE advertisers SET cap_alert_month = ?, cap_alerted_80 = ?, cap_alerted_100 = ? WHERE id = ?')
    .run(month, alerted80, alerted100, adv.id);
  const msg = threshold === 100
    ? `\u{1F6D1} Advertiser <b>${adv.name}</b> hit its monthly conversion cap (${used}/${cap}) — auto-paused.`
    : `\u{26A0}\u{FE0F} Advertiser <b>${adv.name}</b> at ${threshold}% of monthly conversion cap (${used}/${cap}).`;
  sendTelegram(msg).catch(() => {});
}

// Generate a single-use 24h password-reset token for a publisher and return it.
function createResetToken(publisherId) {
  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + 24 * 3600_000).toISOString().replace('T', ' ').slice(0, 19);
  db.prepare('INSERT INTO password_resets (publisher_id, token, expires_at) VALUES (?, ?, ?)')
    .run(publisherId, token, expires);
  return { token, expires };
}

// Look up a valid (unused, unexpired) reset token; returns { ...row } or null.
function validResetToken(token) {
  if (!token) return null;
  return db.prepare(
    "SELECT * FROM password_resets WHERE token = ? AND used_at IS NULL AND expires_at > datetime('now')"
  ).get(token) || null;
}

// ---------------------------------------------------------------------------
// General helpers
// ---------------------------------------------------------------------------

function slugify(s) {
  return s.toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
}
function getIp(req) {
  return req.ip;
}

// ---------------------------------------------------------------------------
// Geo / device helpers
// ---------------------------------------------------------------------------

const COUNTRY_NAMES = {
  VN:'Vietnam', SG:'Singapore', US:'United States', TH:'Thailand',
  MY:'Malaysia', ID:'Indonesia', PH:'Philippines', KH:'Cambodia',
  MM:'Myanmar', LA:'Laos', AU:'Australia', CN:'China', JP:'Japan',
  KR:'South Korea', GB:'United Kingdom', IN:'India', DE:'Germany',
  FR:'France', HK:'Hong Kong', TW:'Taiwan', XX:'Unknown',
};
function countryName(code) { return COUNTRY_NAMES[code] || code; }

function geoLookup(ip) {
  const addr = ip.replace(/^::ffff:/, '');
  if (addr === '127.0.0.1' || addr === '::1') return 'XX';
  const geo = geoip.lookup(addr);
  return geo?.country || 'XX';
}

function parseUA(ua = '') {
  const u = ua.toLowerCase();
  let device = 'desktop';
  if (/tablet|ipad/.test(u)) device = 'tablet';
  else if (/mobile|android|iphone|ipod|blackberry|opera mini|iemobile/.test(u)) device = 'mobile';
  let os = 'Other';
  if      (/android/.test(u))           os = 'Android';
  else if (/iphone|ipad|ipod/.test(u))  os = 'iOS';
  else if (/windows/.test(u))           os = 'Windows';
  else if (/mac os|macintosh/.test(u))  os = 'Mac';
  else if (/linux/.test(u))             os = 'Linux';
  let browser = 'Other';
  if      (/edg\//.test(u))             browser = 'Edge';
  else if (/chrome|crios/.test(u))      browser = 'Chrome';
  else if (/firefox|fxios/.test(u))     browser = 'Firefox';
  else if (/safari/.test(u))            browser = 'Safari';
  return { device, os, browser };
}

// ---------------------------------------------------------------------------
// Click recording — shared by /track and /go (smart links). Captures geo,
// device, sub-params (F7), enhanced tracking (F8), AppsFlyer/Adjust (F10).
// Returns { clickId, device, country }.
// ---------------------------------------------------------------------------

function recordClick(req, slug, pub) {
  const clickId = crypto.randomUUID();
  const clickIp = getIp(req);
  const clickUa = req.get('User-Agent') || '';
  const { device, os, browser } = parseUA(clickUa);
  const country = geoLookup(clickIp);

  const q = name => {
    const v = req.query[name];
    return (typeof v === 'string' && v.trim() !== '') ? v.trim().slice(0, 500) : null;
  };
  const sub1 = q('sub1'), sub2 = q('sub2'), sub3 = q('sub3'), sub4 = q('sub4'), sub5 = q('sub5'), subpub = q('subpub');
  const gclid = q('gclid'), fbclid = q('fbclid');
  const referrer = (req.get('Referer') || '').slice(0, 500) || null;
  const af_siteid = q('af_siteid'), af_campaign = q('af_campaign'), af_adset = q('af_adset'), af_ad = q('af_ad');
  const adjust_network = q('adjust_network'), adjust_campaign = q('adjust_campaign'),
        adjust_adgroup = q('adjust_adgroup'), adjust_creative = q('adjust_creative');
  const campaign = af_campaign || adjust_campaign || null;
  const adgroup  = af_adset    || adjust_adgroup  || null;
  const creative = af_ad       || adjust_creative || null;
  const network  = af_siteid   || adjust_network  || null;
  // Backlog #17 — agency / sub-affiliate dimension carried on the tracking link
  const af_sub1 = q('af_sub1'), af_sub2 = q('af_sub2');

  db.prepare(
    `INSERT INTO clicks (click_id, advertiser_slug, publisher, ip, user_agent, country, device_type, os, browser,
       sub1, sub2, sub3, sub4, sub5, subpub, gclid, fbclid, referrer,
       af_siteid, af_campaign, af_adset, af_ad, adjust_network, adjust_campaign, adjust_adgroup, adjust_creative,
       campaign, adgroup, creative, network, af_sub1, af_sub2)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(clickId, slug, pub, clickIp, clickUa, country, device, os, browser,
    sub1, sub2, sub3, sub4, sub5, subpub, gclid, fbclid, referrer,
    af_siteid, af_campaign, af_adset, af_ad, adjust_network, adjust_campaign, adjust_adgroup, adjust_creative,
    campaign, adgroup, creative, network, af_sub1, af_sub2);

  return { clickId, device, country };
}

// ---------------------------------------------------------------------------
// Tracking  GET /track/:slug?pub=PUBLISHER
// ---------------------------------------------------------------------------

app.get('/track/:slug', (req, res) => {
  const { slug } = req.params;
  const { pub }  = req.query;
  if (!pub) return res.status(400).json({ error: 'Missing required param: pub' });
  if (pub.length > 200) return res.status(400).json({ error: 'Invalid publisher' });
  if (/[\x00-\x1f]/.test(pub)) return res.status(400).json({ error: 'Invalid publisher' });

  const adv = db.prepare('SELECT * FROM advertisers WHERE slug = ?').get(slug);
  if (!adv)                    return res.status(404).json({ error: `Unknown advertiser: ${slug}` });
  if (adv.status !== 'active') return res.status(404).json({ error: `Advertiser ${slug} is paused` });

  const { clickId } = recordClick(req, slug, pub);

  if (!adv.offer_url) return res.json({ click_id: clickId, advertiser: slug, publisher: pub });

  const url = new URL(adv.offer_url);
  url.searchParams.set('click_id', clickId);
  res.redirect(302, url.toString());
});

// ---------------------------------------------------------------------------
// Smart link  GET /go/:publisher_slug  (F5)
// Picks an advertiser by geo/device rule (highest priority = lowest number),
// falling back to the publisher's first active assigned advertiser.
// ---------------------------------------------------------------------------

app.get('/go/:publisher_slug', (req, res) => {
  const pubRow = db.prepare("SELECT * FROM publishers WHERE username = ? AND status = 'active'").get(req.params.publisher_slug);
  if (!pubRow) return res.status(404).json({ error: 'Unknown publisher' });

  const clickIp = getIp(req);
  const country = geoLookup(clickIp);
  const { device } = parseUA(req.get('User-Agent') || '');

  // Rules joined to active advertisers, highest priority first.
  const rules = db.prepare(`
    SELECT slr.country, slr.device_type, slr.priority, a.slug, a.offer_url
    FROM smart_link_rules slr
    JOIN advertisers a ON a.id = slr.advertiser_id
    WHERE slr.publisher_id = ? AND a.status = 'active'
    ORDER BY slr.priority ASC, slr.id ASC
  `).all(pubRow.id);

  const countryMatch = rule => rule.country === '*' ||
    rule.country.split(',').map(c => c.trim().toUpperCase()).filter(Boolean).includes(country);
  const deviceMatch  = rule => rule.device_type === '*' || rule.device_type === device;

  let target = rules.find(r => countryMatch(r) && deviceMatch(r)) || null;

  // Fallback: first active assigned advertiser.
  if (!target) {
    target = assignedAdvertisers(pubRow.id).find(a => a.status === 'active') || null;
  }
  if (!target) return res.status(404).json({ error: 'No matching offer for this publisher' });

  const { clickId } = recordClick(req, target.slug, pubRow.username);
  if (!target.offer_url) return res.json({ click_id: clickId, advertiser: target.slug, publisher: pubRow.username });

  const url = new URL(target.offer_url);
  url.searchParams.set('click_id', clickId);
  res.redirect(302, url.toString());
});

// ---------------------------------------------------------------------------
// Postback  GET /postback/:slug?click_id=X&payout=Y[&event=sale][&publisher=Z]
// ---------------------------------------------------------------------------

app.get('/postback/:slug', postbackLimiter, (req, res) => {
  const ip = getIp(req);
  if (!isWhitelisted(ip)) {
    logPostback(req, { status: 'rejected', reason: 'ip_not_whitelisted' });
    return res.status(403).json({ error: 'Forbidden — IP not whitelisted', ip });
  }

  const { slug }                             = req.params;
  const { click_id, payout }                 = req.query;
  const rawEvent                             = req.query.event || 'sale';
  // loan_amount is the basis for percentage payouts; revenue is what the
  // advertiser pays Komorebi (used for margin reporting). Both optional.
  const loanAmount = req.query.loan_amount != null && req.query.loan_amount !== '' && !isNaN(parseFloat(req.query.loan_amount))
    ? parseFloat(req.query.loan_amount) : null;
  const revenue = req.query.revenue != null && req.query.revenue !== '' && !isNaN(parseFloat(req.query.revenue))
    ? parseFloat(req.query.revenue) : null;
  // F9 transaction_id — advertiser's own conversion id (optional)
  const transactionId = (typeof req.query.transaction_id === 'string' && req.query.transaction_id.trim() !== '')
    ? req.query.transaction_id.trim().slice(0, 200) : null;
  // F15 user_id — advertiser's end-user id, for duplicate-user detection (optional)
  const userId = (typeof req.query.user_id === 'string' && req.query.user_id.trim() !== '')
    ? req.query.user_id.trim().slice(0, 200) : null;

  if (!click_id) {
    logPostback(req, { status: 'rejected', reason: 'missing_click_id' });
    return res.status(400).json({ error: 'Missing required param: click_id' });
  }

  const click = db.prepare('SELECT * FROM clicks WHERE click_id = ?').get(click_id);
  if (!click) {
    logPostback(req, { status: 'rejected', reason: 'invalid_click_id', click_id });
    return res.status(400).json({ error: 'Invalid click_id' });
  }

  const adv = db.prepare('SELECT * FROM advertisers WHERE slug = ?').get(slug);
  if (!adv) return res.status(404).json({ error: `Unknown advertiser: ${slug}` });

  // F18(B) — optional per-advertiser HMAC signature. If a secret is set, require
  // &sig=HMAC-SHA256(secret, "click_id:event:payout"). No secret → accept as before.
  // Advertiser must sign using the same format: click_id:event:payout
  if (adv.postback_secret) {
    const sig = String(req.query.sig || '').toLowerCase();
    const base = [click_id, rawEvent, payout ?? ''].join(':');
    const expected = crypto.createHmac('sha256', adv.postback_secret).update(base).digest('hex');
    const valid = sig.length === expected.length &&
      crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
    if (!valid) {
      logPostback(req, { status: 'rejected', reason: 'invalid_signature', advertiser: slug });
      return res.status(403).json({ error: 'Invalid or missing postback signature' });
    }
  }

  const pub = click.publisher;

  // Backlog #7 — map advertiser SDK event name to Komorebi event before goal matching
  const event = mapEvent(adv.id, rawEvent);

  // F11 click expiry — reject if the click is older than the advertiser's lookback window.
  const lookbackDays = adv.click_lookback_window != null ? adv.click_lookback_window : 30;
  const clickAgeMs = Date.now() - new Date((click.created_at || '').replace(' ', 'T') + 'Z').getTime();
  if (Number.isFinite(clickAgeMs) && clickAgeMs > lookbackDays * 86_400_000) {
    logPostback(req, { status: 'rejected', reason: 'click_expired', click_id, advertiser: slug, age_days: Math.floor(clickAgeMs / 86_400_000) });
    return res.status(410).json({ error: `Click expired — older than ${lookbackDays}-day lookback window` });
  }

  // Assignment gating — only accept postbacks for publisher↔advertiser pairs
  // that have been explicitly assigned. Existing pairs were backfilled from
  // click/conversion history on migration, so live traffic is not dropped.
  const assignment = getAssignment(pub, slug);
  if (!assignment) {
    logPostback(req, { status: 'rejected', reason: 'publisher_not_assigned', publisher: pub, advertiser: slug });
    return res.status(403).json({ error: `Publisher "${pub}" is not assigned to advertiser "${slug}"` });
  }

  // Enforce the assignment's validity window and monthly cap.
  const block = assignmentBlock(assignment, pub, slug);
  if (block) {
    logPostback(req, { status: 'rejected', reason: block.reason, publisher: pub, advertiser: slug });
    return res.status(403).json({ error: block.message });
  }

  // F12 — advertiser-level monthly conversion cap (hard ceiling on approved conversions).
  // At/over cap → reject (429), auto-pause the advertiser, fire the 100% alert. Below cap
  // but ≥80% → fire the 80% alert. Alerts are throttled to once per threshold per month.
  if (adv.monthly_conversion_cap != null) {
    const used = advertiserApprovedCount(adv);
    const cap  = adv.monthly_conversion_cap;
    if (used >= cap) {
      maybeAlertAdvertiserCap(adv, used, cap, 100);
      if (adv.status === 'active') {
        db.prepare("UPDATE advertisers SET status = 'paused' WHERE id = ?").run(adv.id);
        logAudit('advertiser.auto_paused', 'advertiser', slug, { reason: 'advertiser_cap_reached', used, cap }, req);
      }
      logPostback(req, { status: 'rejected', reason: 'advertiser_cap_reached', advertiser: slug, used, cap });
      return res.status(429).json({ error: `Advertiser "${slug}" monthly conversion cap reached (${used}/${cap})` });
    }
    if (used >= Math.floor(cap * 0.8)) maybeAlertAdvertiserCap(adv, used, cap, 80);
  }

  // Payout precedence: assignment override → matching conversion goal → advertiser default.
  // Percent payouts use loan_amount; revenue is recorded for margin reporting.
  const goal = matchGoal(adv.id, event);
  let { amount, note } = computePayout(assignment, adv, goal, loanAmount);

  // QA2 — currency for this conversion. Explicit ?currency= wins; otherwise a
  // percent-of-loan payout with a large loan_amount (>1000) is treated as VND.
  const payoutType = (assignment.payout_override == null)
    ? (goal ? goal.payout_type : adv.payout_type) : 'fixed';
  let currency = String(req.query.currency || '').trim().toUpperCase();
  if (currency !== 'USD' && currency !== 'VND') {
    currency = (payoutType === 'percent' && loanAmount != null && loanAmount > 1000) ? 'VND' : 'USD';
  }

  // F15 — duplicate-user detection. If this user_id already converted for this advertiser
  // (any publisher, any prior event), record the row as a zero-payout duplicate (HTTP 200).
  // First conversion for the user_id+advertiser wins and keeps its payout.
  let convStatus = null, convReason = null, duplicate = false;
  if (userId) {
    const prior = db.prepare(
      'SELECT 1 FROM conversions WHERE advertiser_slug = ? AND user_id = ? LIMIT 1'
    ).get(slug, userId);
    if (prior) {
      duplicate = true;
      convStatus = 'duplicate';
      convReason = 'duplicate_user';
      amount = 0;
      note = note || 'duplicate_user';
    }
  }

  // Backlog #13 (ordering) — if Protect360 already flagged this click_id for this
  // advertiser, a later sale postback must also be rejected ($0), not left pending.
  const preFlagged = db.prepare("SELECT 1 FROM conversions WHERE click_id = ? AND advertiser_slug = ? AND fraud_source = 'protect360'").get(click_id, slug);
  if (preFlagged) {
    convStatus = 'rejected';
    convReason = convReason || 'protect360';
    amount = 0;
    note = note || 'protect360_pre_flagged';
  }

  // Backlog #15 — CTIT (click-to-conversion time, seconds) + anomaly flag.
  // clickAgeMs was computed above for the lookback check.
  const ctitSeconds = Number.isFinite(clickAgeMs) ? Math.max(0, Math.floor(clickAgeMs / 1000)) : null;
  let fraudFlag = null;
  if (ctitSeconds != null) {
    if (ctitSeconds < 10) fraudFlag = 'ctit_too_fast';
    else if (ctitSeconds > 2592000) fraudFlag = 'ctit_too_slow'; // > 30 days
  }
  // Backlog #17 — propagate the sub-affiliate dimension from the click.
  const afSub1 = click.af_sub1 || null;
  const afSub2 = click.af_sub2 || null;

  let result;
  try {
    db.prepare(
      `INSERT INTO conversions (click_id, advertiser_slug, publisher, event, payout, currency, loan_amount, revenue, transaction_id, user_id, status, reason, raw_params, ctit_seconds, fraud_flag, af_sub1, af_sub2)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, 'pending'), ?, ?, ?, ?, ?, ?)`
    ).run(click_id, slug, pub, event, amount, currency, loanAmount, revenue, transactionId, userId, convStatus, convReason, JSON.stringify(maskPII(req.query)), ctitSeconds, fraudFlag, afSub1, afSub2);
    result = { status: duplicate ? 'duplicate' : 'ok', click_id, advertiser: slug, publisher: pub, event,
               payout: amount, currency, goal: goal?.name || null, loan_amount: loanAmount, revenue, transaction_id: transactionId, user_id: userId,
               ctit_seconds: ctitSeconds };
    if (fraudFlag) result.fraud_flag = fraudFlag;
    if (note) result.note = note;
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE' || (err.message && err.message.includes('UNIQUE constraint'))) {
      logPostback(req, { status: 'duplicate', click_id, event });
      return res.json({ status: 'duplicate' });
    }
    throw err;
  }

  // Backlog #14 — duplicate click_id across distinct events. Once a click_id has 2+
  // distinct events, flag every conversion for that click_id, preserving any CTIT flag
  // already set on the row (e.g. 'duplicate_click_id|ctit_too_fast').
  const distinctEvents = db.prepare('SELECT COUNT(DISTINCT event) AS n FROM conversions WHERE click_id = ?').get(click_id).n;
  if (distinctEvents >= 2) {
    const dupRows = db.prepare('SELECT id, fraud_flag FROM conversions WHERE click_id = ?').all(click_id);
    const setFlag = db.prepare('UPDATE conversions SET fraud_flag = ? WHERE id = ?');
    for (const r of dupRows) {
      const ctitPart = (r.fraud_flag || '').split('|').find(p => p.startsWith('ctit_'));
      setFlag.run(ctitPart ? `duplicate_click_id|${ctitPart}` : 'duplicate_click_id', r.id);
    }
    result.fraud_flag = (result.fraud_flag && result.fraud_flag.startsWith('ctit_'))
      ? `duplicate_click_id|${result.fraud_flag}` : 'duplicate_click_id';
  }

  logPostback(req, result);
  res.json(result);

  // Duplicate-user conversions ($0, flagged) are not payable events — skip the
  // S2S postback / email / webhook notifications for them.
  if (duplicate) return;

  // Fire S2S postback, email, and webhooks — all async, do not block response
  // Pass sub-params (F7) and mapped AppsFlyer/Adjust fields (F10) for macro substitution.
  fireS2SPostback(pub, {
    click_id, payout: amount, event, advertiser: slug,
    sub1: click.sub1, sub2: click.sub2, sub3: click.sub3, sub4: click.sub4, sub5: click.sub5, subpub: click.subpub,
    campaign: click.campaign, adgroup: click.adgroup, creative: click.creative, network: click.network,
  }).catch(() => {});
  sendConversionEmail({
    advertiserName: adv.name, publisher: pub, payout: amount,
    click_id, event, received_at: new Date().toISOString().replace('T', ' ').slice(0, 19),
  }).catch(() => {});
  fireWebhookConversion({ advertiserName: adv.name, publisher: pub, payout: amount, event }).catch(() => {});
});

// ---------------------------------------------------------------------------
// Backlog #13 — Protect360 fraud ingest.
// GET /postback/:slug/protect360?click_id=X&reason=Y
// Same IP whitelist as the main postback. A flagged click_id is rejected ($0):
// an existing conversion is overturned, otherwise a rejected row is inserted.
// ---------------------------------------------------------------------------
app.get('/postback/:slug/protect360', postbackLimiter, (req, res) => {
  const ip = getIp(req);
  if (!isWhitelisted(ip)) {
    logPostback(req, { status: 'rejected', reason: 'ip_not_whitelisted' });
    return res.status(403).json({ error: 'Forbidden — IP not whitelisted', ip });
  }
  const { slug } = req.params;
  const click_id = (req.query.click_id || '').toString().trim();
  const rawReason = (req.query.reason || '').toString().trim().slice(0, 120) || 'flagged';
  const reason = `protect360:${rawReason}`;
  if (!click_id) return res.status(400).json({ error: 'Missing required param: click_id' });

  const adv = db.prepare('SELECT * FROM advertisers WHERE slug = ?').get(slug);
  if (!adv) return res.status(404).json({ error: `Unknown advertiser: ${slug}` });

  const existing = db.prepare('SELECT * FROM conversions WHERE click_id = ? AND advertiser_slug = ?').all(click_id, slug);
  let action;
  if (existing.length > 0) {
    db.prepare("UPDATE conversions SET status='rejected', reason=?, payout=0, fraud_source='protect360' WHERE click_id = ? AND advertiser_slug = ?")
      .run(reason, click_id, slug);
    action = 'updated';
  } else {
    // No matching conversion — record a rejected protect360 row (publisher from the click if known).
    const click = db.prepare('SELECT publisher FROM clicks WHERE click_id = ?').get(click_id);
    const publisher = click?.publisher || 'unknown';
    db.prepare(`INSERT INTO conversions (click_id, advertiser_slug, publisher, event, payout, status, reason, fraud_source, raw_params)
                VALUES (?, ?, ?, 'protect360', 0, 'rejected', ?, 'protect360', ?)`)
      .run(click_id, slug, publisher, reason, JSON.stringify(maskPII(req.query)));
    action = 'inserted';
  }

  const publisher = existing[0]?.publisher || (db.prepare('SELECT publisher FROM clicks WHERE click_id = ?').get(click_id)?.publisher) || 'unknown';
  logAudit('protect360.flagged', 'conversion', click_id, { advertiser: slug, reason, action, publisher }, req);
  sendTelegram(`\u{1F6A8} Protect360: ${click_id} flagged [${rawReason}] — ${publisher} / ${slug}`).catch(() => {});
  logPostback(req, { status: 'rejected', reason, click_id, advertiser: slug });
  res.json({ status: 'flagged', action, click_id, advertiser: slug, reason });
});

// ---------------------------------------------------------------------------
// Static assets  (logo files served individually — no directory listing)
// ---------------------------------------------------------------------------

app.get('/static/komorebi-logo-white.png', (req, res) => {
  res.sendFile(path.join(__dirname, 'komorebi-logo-white.png'));
});
// komorebi-logo-full.png exists on disk but is not a valid PNG (see note)
app.get('/static/komorebi-logo-full.png', (req, res) => {
  res.sendFile(path.join(__dirname, 'komorebi-logo-white.png')); // fallback to working logo
});

// ---------------------------------------------------------------------------
// Legal pages  /terms  /privacy  (no auth)
// ---------------------------------------------------------------------------

app.get('/terms',   (req, res) => res.send(renderLegal('terms')));
app.get('/privacy', (req, res) => res.send(renderLegal('privacy')));

// ---------------------------------------------------------------------------
// Health check  GET /health  (no auth)
// ---------------------------------------------------------------------------

app.get('/health', (req, res) => {
  const h = res.getHeaders(); // headers already set by helmet + our middleware
  res.json({
    status: 'ok',
    // F19(D) — secrets configured? (booleans only, never values)
    secrets: {
      SESSION_SECRET:     !!process.env.SESSION_SECRET,
      ADMIN_PASS:         !!process.env.ADMIN_PASS,
      GMAIL_USER:         !!process.env.GMAIL_USER,
      TELEGRAM_BOT_TOKEN: !!process.env.TELEGRAM_BOT_TOKEN,
    },
    // F19(G) — which security headers are actually active on responses
    security_headers: {
      content_security_policy:   !!h['content-security-policy'],
      strict_transport_security: !!h['strict-transport-security'],
      permissions_policy:        h['permissions-policy'] || null,
      x_content_type_options:    h['x-content-type-options'] || null,
      x_frame_options:           h['x-frame-options'] || null,
      referrer_policy:           h['referrer-policy'] || null,
    },
  });
});

// ---------------------------------------------------------------------------
// Public documentation  GET /docs  (no auth)
// ---------------------------------------------------------------------------

app.get('/docs', (req, res) => res.send(renderDocs()));

// ---------------------------------------------------------------------------
// Affiliate marketplace (F6)  — public listing, publisher self-apply
// ---------------------------------------------------------------------------

app.get('/marketplace', (req, res) => {
  const campaigns = db.prepare(
    "SELECT * FROM advertisers WHERE is_public = 1 AND status = 'active' AND slug != 'legacy' ORDER BY name"
  ).all();

  // If logged in, compute each campaign's state for this publisher.
  const pubId = req.session?.pubId;
  let assignedIds = new Set(), pendingIds = new Set();
  if (pubId) {
    assignedIds = new Set(db.prepare('SELECT advertiser_id FROM publisher_advertisers WHERE publisher_id = ?').all(pubId).map(r => r.advertiser_id));
    pendingIds  = new Set(db.prepare("SELECT advertiser_id FROM marketplace_applications WHERE publisher_id = ? AND status = 'pending'").all(pubId).map(r => r.advertiser_id));
  }
  const flash = req.query.msg || null;
  res.send(renderMarketplace({ campaigns, loggedIn: !!pubId, assignedIds, pendingIds, flash }));
});

app.post('/marketplace/apply', applyLimiter, (req, res) => {
  const pubId = req.session?.pubId;
  if (!pubId) return res.redirect('/publisher/login?next=' + encodeURIComponent('/marketplace'));
  const advId = parseInt(req.body.advertiser_id, 10);
  const adv = advId ? db.prepare("SELECT id, name FROM advertisers WHERE id = ? AND is_public = 1 AND status = 'active'").get(advId) : null;
  if (!adv) return res.redirect('/marketplace?msg=' + encodeURIComponent('Campaign not available'));

  const assigned = db.prepare('SELECT 1 FROM publisher_advertisers WHERE publisher_id = ? AND advertiser_id = ?').get(pubId, adv.id);
  if (assigned) return res.redirect('/marketplace?msg=' + encodeURIComponent('You are already running this campaign'));
  const pending = db.prepare("SELECT 1 FROM marketplace_applications WHERE publisher_id = ? AND advertiser_id = ? AND status = 'pending'").get(pubId, adv.id);
  if (pending) return res.redirect('/marketplace?msg=' + encodeURIComponent('Your application is already pending'));

  db.prepare("INSERT INTO marketplace_applications (publisher_id, advertiser_id, status) VALUES (?, ?, 'pending')").run(pubId, adv.id);
  const pub = db.prepare('SELECT username FROM publishers WHERE id = ?').get(pubId);
  logAudit('marketplace.applied', 'advertiser', adv.id, { publisher: pub?.username, advertiser: adv.name }, req);
  res.redirect('/marketplace?msg=' + encodeURIComponent('Application submitted — pending review'));
});

// ---------------------------------------------------------------------------
// Publisher portal
// ---------------------------------------------------------------------------

app.get('/',                (req, res) => res.redirect('/publisher/login'));
app.get('/publisher',       requirePublisher, (req, res) => res.redirect('/publisher/dashboard'));
// Only allow same-origin relative redirect targets (no open redirect).
function safeNext(v) {
  return (typeof v === 'string' && v.startsWith('/') && !v.startsWith('//')) ? v : null;
}

app.get('/publisher/login', (req, res) => {
  if (req.session?.pubId) return res.redirect(safeNext(req.query.next) || '/publisher/dashboard');
  const success = req.query.registered
    ? 'Application submitted! We\'ll review it and notify you when approved.'
    : req.query.reset
      ? 'Your password has been reset. You can now sign in with your new password.'
      : null;
  res.send(renderPubLogin({ error: req.query.err, success, next: safeNext(req.query.next) }));
});

app.post('/publisher/login', (req, res) => {
  if (checkLoginLockout(req, res, publisherLoginAttempts)) return;
  const { username, password } = req.body;
  const next = safeNext(req.body.next);
  const uname = (username || '').trim().toLowerCase();
  const pub = uname ? db.prepare('SELECT * FROM publishers WHERE username = ?').get(uname) : null;
  if (!pub || !checkPassword(password || '', pub.password_hash)) {
    recordLoginFailure(req.ip, publisherLoginAttempts);
    return res.send(renderPubLogin({ error: 'Invalid username or password', username: uname, next }));
  }
  if (pub.status !== 'active') {
    const msg = pub.status === 'pending'
      ? 'Your application is pending review. We\'ll be in touch once it\'s approved.'
      : pub.status === 'rejected'
        ? 'Your application was not approved. Contact chi@komorebimedia.com for details.'
        : 'Your account has been disabled. Contact your account manager.';
    return res.send(renderPubLogin({ error: msg, next }));
  }
  req.session.regenerate(err => {
    if (err) return res.status(500).send('Session error');
    req.session.pubId = pub.id;
    req.session.save(saveErr => {
      if (saveErr) return res.status(500).send('Session error');
      recordLoginSuccess(req.ip, publisherLoginAttempts);
      res.redirect(next || '/publisher/dashboard');
    });
  });
});

app.post('/publisher/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/publisher/login'));
});

// ---------------------------------------------------------------------------
// Publisher self-registration  (public)
// ---------------------------------------------------------------------------

app.get('/publisher/register', (req, res) => {
  if (req.session?.pubId) return res.redirect('/publisher/dashboard');
  res.send(renderPubRegister());
});

app.post('/publisher/register', (req, res) => {
  const uname    = (req.body.username || '').trim().toLowerCase();
  const email    = (req.body.email    || '').trim();
  const company  = (req.body.company  || '').trim();
  const website  = (req.body.website  || '').trim();
  const password = req.body.password  || '';
  const password2= req.body.password2 || '';
  const traffic  = [].concat(req.body.traffic || []).filter(Boolean).join(',');
  const vals     = { username: uname, email, company, website, traffic };

  const fail = msg => res.send(renderPubRegister({ error: msg, values: vals }));

  if (!uname)                             return fail('Username is required.');
  if (!/^[a-z0-9_-]+$/.test(uname))      return fail('Username must be lowercase letters, numbers, hyphens, or underscores.');
  if (uname.length > 40)                 return fail('Username must be 40 characters or fewer.');
  if (!email || !email.includes('@'))    return fail('A valid email address is required.');
  if (!password || password.length < 8) return fail('Password must be at least 8 characters.');
  if (password !== password2)            return fail('Passwords do not match.');
  if (!traffic)                          return fail('Please select at least one traffic source.');
  if (website && !/^https?:\/\//i.test(website)) return fail('Website must start with http:// or https://.');

  if (db.prepare('SELECT id FROM publishers WHERE username = ?').get(uname)) {
    return fail(`Username "${uname}" is already taken — please choose another.`);
  }

  db.prepare(`
    INSERT INTO publishers (username, password_hash, email, company, website, traffic_sources, status)
    VALUES (?, ?, ?, ?, ?, ?, 'pending')
  `).run(uname, hashPassword(password), email, company, website, traffic);

  logAudit('publisher.registered', 'publisher', uname, { email, company, traffic }, req);

  sendMail({
    subject: `[Komorebi] New publisher application — ${uname}`,
    text:
      `A new publisher has applied for an account.\n\n` +
      `Username       : ${uname}\n` +
      `Email          : ${email}\n` +
      `Company        : ${company || '—'}\n` +
      `Website        : ${website || '—'}\n` +
      `Traffic sources: ${traffic || '—'}\n\n` +
      `Review at: ${BASE_URL}/admin/publishers`,
    html: (() => {
      const websiteHtml = /^https?:\/\//i.test(website)
        ? `<a href="${H(website)}">${H(website)}</a>`
        : (website ? H(website) : '—');
      return `<div style="font-family:sans-serif;max-width:520px">
      <h2 style="color:#1d1d1f;margin-bottom:4px">New Publisher Application</h2>
      <p style="color:#6e6e73;font-size:13px;margin-bottom:20px">Komorebi Affiliate Network</p>
      <table style="border-collapse:collapse;width:100%">
        ${[['Username', `<strong>${H(uname)}</strong>`], ['Email', H(email)],
           ['Company', company ? H(company) : '—'], ['Website', websiteHtml],
           ['Traffic', traffic ? H(traffic) : '—']
          ].map(([k,v]) => `<tr>
            <td style="padding:8px 12px;background:#f5f5f7;font-weight:600;font-size:13px;width:110px">${k}</td>
            <td style="padding:8px 12px;font-size:13px;border-bottom:1px solid #f0f0f0">${v}</td>
          </tr>`).join('')}
      </table>
      <p style="margin-top:20px">
        <a href="${BASE_URL}/admin/publishers" style="background:#0071e3;color:#fff;padding:9px 18px;border-radius:7px;text-decoration:none;font-size:13px;font-weight:600">
          Review Application →
        </a>
      </p>
    </div>`;
    })(),
  }).catch(() => {});

  res.redirect('/publisher/login?registered=1');
});

// ---------------------------------------------------------------------------
// Publisher — forgot / reset password  (public)
// ---------------------------------------------------------------------------

app.get('/publisher/forgot-password', (req, res) => {
  if (req.session?.pubId) return res.redirect('/publisher/dashboard');
  res.send(renderForgotPassword());
});

app.post('/publisher/forgot-password', (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  // Generic response regardless of whether the email exists (no enumeration).
  const generic = 'If an account exists for that email, a password reset link has been sent. Reset links expire in 24 hours.';

  if (email) {
    const pub = db.prepare("SELECT * FROM publishers WHERE lower(email) = ? AND status = 'active'").get(email);
    if (pub) {
      const { token } = createResetToken(pub.id);
      const link = `${BASE_URL}/publisher/reset-password?token=${token}`;
      logAudit('publisher.password_reset_requested', 'publisher', pub.username,
        { emailed: !!transporter }, req);
      if (transporter) {
        sendMail({
          to: pub.email,
          subject: '[Komorebi] Reset your publisher password',
          text:
            `We received a request to reset the password for your Komorebi publisher account "${pub.username}".\n\n` +
            `Reset your password using the link below (valid for 24 hours):\n${link}\n\n` +
            `If you didn't request this, you can safely ignore this email.`,
          html: `<div style="font-family:sans-serif;max-width:480px">
            <h2 style="color:#1d1d1f;margin-bottom:6px">Reset your password</h2>
            <p style="color:#6e6e73;font-size:13px">Account: <strong>${H(pub.username)}</strong></p>
            <p style="font-size:13px">Click the button below to choose a new password. This link is valid for 24 hours.</p>
            <p style="margin:20px 0">
              <a href="${H(link)}" style="background:#0F6E56;color:#fff;padding:10px 20px;border-radius:7px;text-decoration:none;font-size:13px;font-weight:600">Reset Password →</a>
            </p>
            <p style="font-size:11px;color:#8e8e93;word-break:break-all">${H(link)}</p>
            <p style="font-size:12px;color:#6e6e73">If you didn't request this, you can safely ignore this email.</p>
          </div>`,
        }).catch(() => {});
      }
      // When email isn't configured, the token surfaces on the admin publisher edit page.
    }
  }
  res.send(renderForgotPassword({ success: generic }));
});

app.get('/publisher/reset-password', (req, res) => {
  const reset = validResetToken((req.query.token || '').trim());
  if (!reset) return res.send(renderResetPassword({ invalid: true }));
  res.send(renderResetPassword({ token: reset.token }));
});

app.post('/publisher/reset-password', (req, res) => {
  const token = (req.body.token || '').trim();
  const reset = validResetToken(token);
  if (!reset) return res.send(renderResetPassword({ invalid: true }));

  const { new_password, confirm_password } = req.body;
  if (!new_password || new_password.length < 8) {
    return res.send(renderResetPassword({ token, error: 'Password must be at least 8 characters.' }));
  }
  if (new_password !== confirm_password) {
    return res.send(renderResetPassword({ token, error: 'Passwords do not match.' }));
  }

  const pub = db.prepare('SELECT username FROM publishers WHERE id = ?').get(reset.publisher_id);
  db.prepare('UPDATE publishers SET password_hash = ? WHERE id = ?').run(hashPassword(new_password), reset.publisher_id);
  db.prepare("UPDATE password_resets SET used_at = datetime('now') WHERE id = ?").run(reset.id);
  // Invalidate any other outstanding tokens for this publisher.
  db.prepare("UPDATE password_resets SET used_at = datetime('now') WHERE publisher_id = ? AND used_at IS NULL")
    .run(reset.publisher_id);
  logAudit('publisher.password_reset', 'publisher', pub?.username ?? reset.publisher_id, { via: 'token' }, req);
  res.redirect('/publisher/login?reset=1');
});

app.get('/publisher/dashboard', requirePublisher, (req, res) => {
  const pub       = req.publisher;
  const thisMonth = new Date().toISOString().slice(0, 7);

  const totalClicks = db.prepare(
    'SELECT COUNT(*) as n FROM clicks WHERE publisher = ?'
  ).get(pub.username).n;

  const totalConversions = db.prepare(
    'SELECT COUNT(*) as n FROM conversions WHERE publisher = ?'
  ).get(pub.username).n;

  // QA2 — earnings grouped by currency (never summed across currencies).
  const earnRows = db.prepare(`
    SELECT currency,
           COALESCE(SUM(CASE WHEN status='approved' THEN payout ELSE 0 END),0) as approved,
           COALESCE(SUM(CASE WHEN status='pending'  THEN payout ELSE 0 END),0) as pending
    FROM conversions WHERE publisher = ? GROUP BY currency
  `).all(pub.username);
  const monthRows = db.prepare(`
    SELECT currency,
           COALESCE(SUM(CASE WHEN status='approved' THEN payout ELSE 0 END),0) as approved,
           COALESCE(SUM(CASE WHEN status='pending'  THEN payout ELSE 0 END),0) as pending
    FROM conversions WHERE publisher = ? AND strftime('%Y-%m',received_at) = ? GROUP BY currency
  `).all(pub.username, thisMonth);
  const approvedByCurrency        = earnRows.map(r => ({ currency: r.currency, total: r.approved }));
  const pendingByCurrency         = earnRows.map(r => ({ currency: r.currency, total: r.pending }));
  const monthlyApprovedByCurrency = monthRows.map(r => ({ currency: r.currency, total: r.approved }));
  const monthlyPendingByCurrency  = monthRows.map(r => ({ currency: r.currency, total: r.pending }));
  // USD approved is the basis for the payout threshold (payments + minimum_payout are USD).
  const totalPayout = (earnRows.find(r => r.currency === 'USD') || {}).approved || 0;

  // Only advertisers this publisher is assigned to and that are active.
  const advertisers = assignedAdvertisers(pub.id).filter(a => a.status === 'active');

  const advClicks = db.prepare(
    'SELECT advertiser_slug, COUNT(*) as n FROM clicks WHERE publisher = ? GROUP BY advertiser_slug'
  ).all(pub.username);
  const advConv = db.prepare(`
    SELECT advertiser_slug, COUNT(*) as n,
           COALESCE(MAX(currency),'USD') as currency,
           COALESCE(SUM(CASE WHEN status='approved' THEN payout ELSE 0 END),0) as approved_payout,
           COALESCE(SUM(CASE WHEN status='pending'  THEN payout ELSE 0 END),0) as pending_payout,
           SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END) as approved_count,
           SUM(CASE WHEN status='pending'  THEN 1 ELSE 0 END) as pending_count,
           SUM(CASE WHEN status='rejected' THEN 1 ELSE 0 END) as rejected_count
    FROM conversions WHERE publisher = ? GROUP BY advertiser_slug
  `).all(pub.username);

  const clickMap = Object.fromEntries(advClicks.map(r => [r.advertiser_slug, r.n]));
  const convMap  = Object.fromEntries(advConv.map(r => [r.advertiser_slug, r]));

  const advStats = advertisers.map(a => ({
    ...a,
    clicks:         clickMap[a.slug] || 0,
    conversions:    convMap[a.slug]?.n || 0,
    currency:       convMap[a.slug]?.currency || 'USD',
    approved_payout: convMap[a.slug]?.approved_payout || 0,
    pending_payout: convMap[a.slug]?.pending_payout || 0,
    approved_count: convMap[a.slug]?.approved_count || 0,
    pending_count:  convMap[a.slug]?.pending_count || 0,
    rejected_count: convMap[a.slug]?.rejected_count || 0,
    trackingUrl: `${publisherBase(pub)}/track/${a.slug}?pub=${encodeURIComponent(pub.username)}`,
  }));

  const recent = db.prepare(`
    SELECT cv.received_at, cv.advertiser_slug, cv.click_id, cv.event,
           cv.payout, cv.currency, cv.loan_amount, cv.revenue, cv.status, cv.reason, a.name as adv_name
    FROM conversions cv
    LEFT JOIN advertisers a ON a.slug = cv.advertiser_slug
    WHERE cv.publisher = ?
    ORDER BY cv.received_at DESC LIMIT 30
  `).all(pub.username);

  const payments = db.prepare(`
    SELECT amount_usd, paid_at, method, notes FROM payments
    WHERE publisher_id = ? ORDER BY paid_at DESC LIMIT 50
  `).all(pub.id);

  const totalPaid = payments.reduce((s, p) => s + p.amount_usd, 0);

  // F7 — breakdown by sub1 (clicks joined to their conversions) for this publisher.
  const subStats = db.prepare(`
    SELECT c.sub1 AS sub1,
           COUNT(DISTINCT c.click_id) AS clicks,
           COUNT(cv.id)               AS conversions,
           COALESCE(MAX(cv.currency),'USD') AS currency,
           COALESCE(SUM(cv.payout),0) AS payout
    FROM clicks c
    LEFT JOIN conversions cv ON cv.click_id = c.click_id
    WHERE c.publisher = ? AND c.sub1 IS NOT NULL AND c.sub1 != ''
    GROUP BY c.sub1
    ORDER BY clicks DESC
    LIMIT 50
  `).all(pub.username);

  res.send(renderPubDashboard({ pub, totalClicks, totalConversions,
    totalPayout, approvedByCurrency, pendingByCurrency, monthlyApprovedByCurrency, monthlyPendingByCurrency,
    advStats, recent, thisMonth, payments, totalPaid, subStats }));
});

app.get('/publisher/conversions', requirePublisher, (req, res) => {
  const pub = req.publisher;
  const conversions = db.prepare(`
    SELECT cv.received_at, cv.advertiser_slug, cv.click_id, cv.event,
           cv.payout, cv.currency, cv.loan_amount, cv.revenue, cv.status, cv.reason, cv.af_sub1, a.name as adv_name
    FROM conversions cv
    LEFT JOIN advertisers a ON a.slug = cv.advertiser_slug
    WHERE cv.publisher = ?
    ORDER BY cv.received_at DESC LIMIT 500
  `).all(pub.username);
  res.send(renderPubConversions({ pub, conversions }));
});

app.get('/publisher/payments', requirePublisher, (req, res) => {
  const pub      = req.publisher;
  const payments = db.prepare(
    'SELECT * FROM payments WHERE publisher_id = ? ORDER BY paid_at DESC'
  ).all(pub.id);
  const totalPaid    = payments.reduce((s, p) => s + p.amount_usd, 0);
  // QA2 — approved balance grouped by currency (never summed across currencies).
  const balRows = db.prepare(
    "SELECT currency, COALESCE(SUM(CASE WHEN status='approved' THEN payout ELSE 0 END),0) as b FROM conversions WHERE publisher=? GROUP BY currency"
  ).all(pub.username);
  const approvedByCurrency = balRows.map(r => ({ currency: r.currency, total: r.b }));
  const approvedBalUsd = (balRows.find(r => r.currency === 'USD') || {}).b || 0;
  res.send(renderPubPayments({ pub, payments, totalPaid, approvedByCurrency, approvedBalUsd }));
});

app.get('/publisher/api-access', requirePublisher, (req, res) => {
  res.send(renderPubApiAccess({ pub: req.publisher }));
});

// ---------------------------------------------------------------------------
// Publisher — profile / change password
// ---------------------------------------------------------------------------

app.get('/publisher/profile', requirePublisher, (req, res) => {
  const flash = req.query.ok  ? 'Password updated successfully.' : null;
  const error = req.query.err || null;
  res.send(renderPubProfile({ pub: req.publisher, csrfToken: req.session.csrfToken, flash, error }));
});

app.post('/publisher/change-password', requirePublisher, verifyCsrf, (req, res) => {
  const { current_password, new_password, confirm_password } = req.body;
  const pub = req.publisher;
  const back = msg => res.send(renderPubProfile({ pub, csrfToken: req.session.csrfToken, error: msg }));

  if (!checkPassword(current_password || '', pub.password_hash)) {
    return back('Current password is incorrect.');
  }
  if (!new_password || new_password.length < 8) {
    return back('New password must be at least 8 characters.');
  }
  if (new_password !== confirm_password) {
    return back('New passwords do not match.');
  }
  if (current_password === new_password) {
    return back('New password must be different from the current password.');
  }

  db.prepare('UPDATE publishers SET password_hash = ? WHERE id = ?').run(hashPassword(new_password), pub.id);
  logAudit('publisher.password_changed', 'publisher', pub.username, { self_service: true }, req);
  res.send(renderPubProfile({ pub, csrfToken: req.session.csrfToken, flash: 'Password updated successfully.' }));
});

// ---------------------------------------------------------------------------
// Admin — main dashboard
// ---------------------------------------------------------------------------

// Admin login / logout
app.get('/admin/login', (req, res) => {
  if (req.session?.isAdmin) return res.redirect('/admin');
  res.send(renderAdminLogin(typeof req.query.err === 'string' ? req.query.err.slice(0, 200) : ''));
});

app.post('/admin/login', (req, res) => {
  if (checkLoginLockout(req, res, adminLoginAttempts)) return;
  const { username, password } = req.body;
  if (username === ADMIN_USER && ADMIN_PASS_HASH && checkPassword(password || '', ADMIN_PASS_HASH)) {
    req.session.regenerate(err => {
      if (err) return res.status(500).send('Session error');
      req.session.isAdmin = true;
      req.session.save(() => {
        recordLoginSuccess(req.ip, adminLoginAttempts);
        logAudit('admin.login.success', 'admin', ADMIN_USER, {}, req);
        res.redirect('/admin');
      });
    });
  } else {
    recordLoginFailure(req.ip, adminLoginAttempts);
    logAudit('admin.login.failed', 'admin', username || '?', {}, req);
    res.send(renderAdminLogin('Invalid username or password'));
  }
});

app.post('/admin/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/admin/login'));
});

// CSRF verification for all admin POST routes except /login and /logout
app.post('/admin/*', (req, res, next) => {
  if (req.path.endsWith('/login') || req.path.endsWith('/logout')) return next();
  // Multipart routes (e.g. /reconcile) parse their body via multer inside the
  // handler, so req.body._csrf isn't available yet here — those routes call
  // verifyCsrf themselves after the upload is parsed.
  if (req.path.endsWith('/reconcile')) return next();
  verifyCsrf(req, res, next);
});

// Global analytics page (sidebar link target)
app.get('/admin/analytics', requireAdmin, (req, res) => res.redirect('/admin#analytics'));

app.get('/admin', requireAdmin, (req, res) => {
  const flash = req.query.msg
    ? { type: req.query.ok === '0' ? 'error' : 'success', text: req.query.msg } : null;

  const totalClicks      = db.prepare('SELECT COUNT(*) as n FROM clicks').get().n;
  const totalConversions = db.prepare('SELECT COUNT(*) as n FROM conversions').get().n;
  const thisMonth        = new Date().toISOString().slice(0, 7);

  // QA2 — global payout totals grouped by currency (never summed across currencies).
  const globalRows = db.prepare(`
    SELECT currency,
           COALESCE(SUM(CASE WHEN status='approved' THEN payout ELSE 0 END),0) as approved,
           COALESCE(SUM(CASE WHEN status='pending'  THEN payout ELSE 0 END),0) as pending
    FROM conversions GROUP BY currency
  `).all();
  const monthRows = db.prepare(
    "SELECT currency, COALESCE(SUM(CASE WHEN status='approved' THEN payout ELSE 0 END),0) as s FROM conversions WHERE strftime('%Y-%m',received_at)=? GROUP BY currency"
  ).all(thisMonth);
  const approvedByCurrency = globalRows.map(r => ({ currency: r.currency, total: r.approved }));
  const pendingByCurrency  = globalRows.map(r => ({ currency: r.currency, total: r.pending }));
  const monthlyByCurrency  = monthRows.map(r => ({ currency: r.currency, total: r.s }));

  const advertisers = db.prepare('SELECT * FROM advertisers ORDER BY name').all();

  const advClicks = db.prepare('SELECT advertiser_slug, COUNT(*) as n FROM clicks GROUP BY advertiser_slug').all();
  const advConv   = db.prepare(`
    SELECT advertiser_slug, COUNT(*) as n,
           COALESCE(MAX(currency),'USD') as currency,
           COALESCE(SUM(payout),0) as payout,
           COALESCE(SUM(revenue),0) as revenue,
           COALESCE(SUM(CASE WHEN status='approved' THEN payout ELSE 0 END),0) as approved_payout,
           SUM(CASE WHEN status='pending'  THEN 1 ELSE 0 END) as pending_count
    FROM conversions GROUP BY advertiser_slug
  `).all();

  const clickMap = Object.fromEntries(advClicks.map(r => [r.advertiser_slug, r.n]));
  const convMap  = Object.fromEntries(advConv.map(r => [r.advertiser_slug, r]));

  const advStats = advertisers.map(a => ({
    ...a,
    clicks:          clickMap[a.slug] || 0,
    conversions:     convMap[a.slug]?.n || 0,
    currency:        convMap[a.slug]?.currency || 'USD',
    payout:          convMap[a.slug]?.payout || 0,
    revenue:         convMap[a.slug]?.revenue || 0,
    approved_payout: convMap[a.slug]?.approved_payout || 0,
    pending_count:   convMap[a.slug]?.pending_count || 0,
    cap_used:        a.monthly_conversion_cap != null ? advertiserApprovedCount(a) : null,
  }));

  const pubStats = db.prepare(`
    SELECT c.advertiser_slug, c.publisher,
           COUNT(DISTINCT c.click_id) as clicks,
           COUNT(cv.id) as conversions,
           COALESCE(MAX(cv.currency),'USD') as currency,
           COALESCE(SUM(cv.payout),0) as payout,
           COALESCE(SUM(cv.revenue),0) as revenue
    FROM clicks c
    LEFT JOIN conversions cv ON cv.click_id = c.click_id
    GROUP BY c.advertiser_slug, c.publisher
    ORDER BY payout DESC LIMIT 100
  `).all();

  // Backlog #14/#15/#17 — fraud filter + CTIT + sub-affiliate columns on the recent table
  const fraudFilter = ['flagged', 'duplicate_click_id', 'ctit', 'protect360'].includes(req.query.fraud) ? req.query.fraud : '';
  let recentWhere = '';
  if (fraudFilter === 'flagged')            recentWhere = 'WHERE fraud_flag IS NOT NULL OR fraud_source IS NOT NULL';
  else if (fraudFilter === 'duplicate_click_id') recentWhere = "WHERE fraud_flag LIKE '%duplicate_click_id%'";
  else if (fraudFilter === 'ctit')          recentWhere = "WHERE fraud_flag LIKE '%ctit%'";
  else if (fraudFilter === 'protect360')    recentWhere = "WHERE fraud_source = 'protect360'";
  const recent = db.prepare(
    `SELECT id, received_at, advertiser_slug, click_id, publisher, event, payout, status, reason,
            ctit_seconds, fraud_flag, fraud_source, af_sub1 FROM conversions ${recentWhere} ORDER BY received_at DESC LIMIT 50`
  ).all();

  const publisherCount = db.prepare("SELECT COUNT(*) as n FROM publishers WHERE status='active'").get().n;

  const topCountries = db.prepare(`
    SELECT country, COUNT(*) as n FROM clicks
    WHERE country IS NOT NULL AND country != 'XX'
    GROUP BY country ORDER BY n DESC LIMIT 5
  `).all();

  const deviceSplit = db.prepare(`
    SELECT device_type, COUNT(*) as n FROM clicks WHERE device_type IS NOT NULL GROUP BY device_type
  `).all();

  const osSplit = db.prepare(`
    SELECT os, COUNT(*) as n FROM clicks WHERE os IN ('Android','iOS') GROUP BY os
  `).all();

  const globalConvStatus = db.prepare(`
    SELECT
      SUM(CASE WHEN status='pending'  THEN 1 ELSE 0 END) as pending,
      SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END) as approved,
      SUM(CASE WHEN status='rejected' THEN 1 ELSE 0 END) as rejected
    FROM conversions
  `).get();

  res.send(renderAdminDashboard({ totalClicks, totalConversions,
    approvedByCurrency, pendingByCurrency, monthlyByCurrency,
    thisMonth, advStats, pubStats, recent, flash, publisherCount, fraudFilter,
    topCountries, deviceSplit, osSplit, globalConvStatus, csrfToken: req.session.csrfToken }));
});

// ---------------------------------------------------------------------------
// Admin — advertiser CRUD
// ---------------------------------------------------------------------------

app.get('/admin/advertisers', requireAdmin, (req, res) => {
  const flash = req.query.msg
    ? { type: req.query.ok === '0' ? 'error' : 'success', text: req.query.msg } : null;
  const advertisers = db.prepare('SELECT * FROM advertisers ORDER BY name').all();
  const advClicks   = db.prepare('SELECT advertiser_slug, COUNT(*) as n FROM clicks GROUP BY advertiser_slug').all();
  const advConv     = db.prepare(`
    SELECT advertiser_slug, COUNT(*) as n,
           COALESCE(SUM(payout),0) as payout,
           COALESCE(SUM(CASE WHEN status='approved' THEN payout ELSE 0 END),0) as approved_payout,
           SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) as pending_count
    FROM conversions GROUP BY advertiser_slug
  `).all();
  const clickMap = Object.fromEntries(advClicks.map(r => [r.advertiser_slug, r.n]));
  const convMap  = Object.fromEntries(advConv.map(r => [r.advertiser_slug, r]));
  const advStats = advertisers.map(a => ({
    ...a,
    clicks:          clickMap[a.slug] || 0,
    conversions:     convMap[a.slug]?.n || 0,
    approved_payout: convMap[a.slug]?.approved_payout || 0,
    pending_count:   convMap[a.slug]?.pending_count || 0,
  }));
  res.send(renderAdvList({ advStats, flash, csrfToken: req.session.csrfToken }));
});

app.get('/admin/advertisers/new', requireAdmin, (req, res) => {
  res.send(renderAdvForm({ title: 'New Advertiser', action: '/admin/advertisers', adv: {}, csrfToken: req.session.csrfToken }));
});

app.post('/admin/advertisers', requireAdmin, (req, res) => {
  const { name, slug, offer_url, payout_amount, status } = req.body;
  const payoutType = req.body.payout_type === 'percent' ? 'percent' : 'fixed';
  // Backlog #3 — default 90d aligns with AppsFlyer's default click lookback window;
  // a misaligned window rejects valid postbacks (and disputes the rejections).
  const lookback = parseInt(req.body.click_lookback_window, 10) > 0 ? parseInt(req.body.click_lookback_window, 10) : 90;
  const cap = (req.body.monthly_conversion_cap !== '' && req.body.monthly_conversion_cap != null && parseInt(req.body.monthly_conversion_cap, 10) >= 0)
    ? parseInt(req.body.monthly_conversion_cap, 10) : null;
  const isPublic = req.body.is_public ? 1 : 0;
  const category = (req.body.category || '').trim() || null;
  const description = (req.body.description || '').trim() || null;
  const countriesAllowed = (req.body.countries_allowed || '').trim() || null;
  const postbackSecret = (req.body.postback_secret || '').trim() || null;
  const mmpType = ['appsflyer', 'adjust'].includes(req.body.mmp_type) ? req.body.mmp_type : 'none';
  const mmpAppId = (req.body.mmp_app_id || '').trim() || null;
  const mmpToken = encryptToken((req.body.mmp_api_token || '').trim() || null);
  // Backlog #4 — per-advertiser timezone + currency (validated; default USD)
  const timezone = validTz((req.body.timezone || '').trim()) || null;
  const currency = ((req.body.currency || 'USD').trim().toUpperCase().slice(0, 8)) || 'USD';
  const s = slug || slugify(name);
  if (!name || !s) return res.send(renderAdvForm({ title: 'New Advertiser', action: '/admin/advertisers',
    adv: req.body, error: 'Name and slug are required.', csrfToken: req.session.csrfToken }));
  if (!/^[a-z0-9-]+$/.test(s)) return res.send(renderAdvForm({ title: 'New Advertiser',
    action: '/admin/advertisers', adv: req.body, error: 'Slug must be lowercase letters, numbers, and hyphens.', csrfToken: req.session.csrfToken }));
  try {
    db.prepare('INSERT INTO advertisers (slug, name, offer_url, payout_amount, payout_type, click_lookback_window, monthly_conversion_cap, is_public, category, description, countries_allowed, postback_secret, mmp_type, mmp_app_id, mmp_api_token, timezone, currency, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .run(s, name.trim(), offer_url || '', parseFloat(payout_amount) || 0, payoutType, lookback, cap, isPublic, category, description, countriesAllowed, postbackSecret, mmpType, mmpAppId, mmpToken, timezone, currency, status || 'active');
    logAudit('advertiser.created', 'advertiser', s,
      { name: name.trim(), slug: s, offer_url: offer_url || '', payout_type: payoutType, click_lookback_window: lookback, monthly_conversion_cap: cap, status: status || 'active' }, req);
    res.redirect(`/admin?msg=Advertiser+%22${encodeURIComponent(name)}%22+created`);
  } catch {
    res.send(renderAdvForm({ title: 'New Advertiser', action: '/admin/advertisers',
      adv: req.body, error: `Slug "${s}" is already taken.`, csrfToken: req.session.csrfToken }));
  }
});

app.get('/admin/advertisers/:slug/edit', requireAdmin, (req, res) => {
  const adv = db.prepare('SELECT * FROM advertisers WHERE slug = ?').get(req.params.slug);
  if (!adv) return res.redirect('/admin?msg=Advertiser+not+found&ok=0');
  const goals = db.prepare('SELECT * FROM goals WHERE advertiser_id = ? ORDER BY created_at').all(adv.id);
  const eventMappings = db.prepare('SELECT * FROM event_mappings WHERE advertiser_id = ? ORDER BY source_event').all(adv.id);
  const flash = req.query.msg && req.query.ok !== '0' ? req.query.msg : null;
  const error = req.query.msg && req.query.ok === '0' ? req.query.msg : null;
  const capUsed = adv.monthly_conversion_cap != null ? advertiserApprovedCount(adv) : null;
  // H2 — never send the decrypted token to the client. Pass only a "stored?" flag.
  const hasMmpToken = !!adv.mmp_api_token;
  const hasPortalPw = !!adv.portal_password_hash;
  adv.mmp_api_token = null;
  res.send(renderAdvForm({ title: `Edit — ${adv.name}`, action: `/admin/advertisers/${adv.slug}/update`,
    adv, csrfToken: req.session.csrfToken, goals, flash, error, capUsed, hasMmpToken, eventMappings, hasPortalPw }));
});

// ---------------------------------------------------------------------------
// Admin — MMP (AppsFlyer) integration: test connection, sync dashboard, run sync
// ---------------------------------------------------------------------------

app.post('/admin/advertisers/:slug/mmp-test', requireAdmin, async (req, res) => {
  const adv = db.prepare('SELECT * FROM advertisers WHERE slug = ?').get(req.params.slug);
  if (!adv) return res.redirect('/admin?msg=Advertiser+not+found&ok=0');
  const result = await mmpTestConnection(adv);
  logAudit('advertiser.mmp_test', 'advertiser', adv.slug, { ok: result.ok }, req);
  res.redirect(`/admin/advertisers/${adv.slug}/edit?msg=${encodeURIComponent('MMP test: ' + result.message)}&ok=${result.ok ? '1' : '0'}`);
});

app.get('/admin/advertisers/:slug/mmp-sync', requireAdmin, (req, res) => {
  const adv = db.prepare('SELECT * FROM advertisers WHERE slug = ?').get(req.params.slug);
  if (!adv) return res.redirect('/admin?msg=Advertiser+not+found&ok=0');
  const logs = db.prepare('SELECT * FROM mmp_sync_log WHERE advertiser_slug = ? ORDER BY synced_at DESC, id DESC LIMIT 30').all(adv.slug);
  const flash = req.query.msg && req.query.ok !== '0' ? req.query.msg : null;
  const error = req.query.msg && req.query.ok === '0' ? req.query.msg : null;
  res.send(renderMmpSync({ adv, logs, csrfToken: req.session.csrfToken, flash, error }));
});

app.post('/admin/advertisers/:slug/mmp-sync/run', requireAdmin, async (req, res) => {
  const adv = db.prepare('SELECT * FROM advertisers WHERE slug = ?').get(req.params.slug);
  if (!adv) return res.redirect('/admin?msg=Advertiser+not+found&ok=0');
  if (adv.mmp_type !== 'appsflyer') {
    return res.redirect(`/admin/advertisers/${adv.slug}/mmp-sync?msg=${encodeURIComponent('MMP type is not AppsFlyer')}&ok=0`);
  }
  const r = await runMmpSync(adv);
  logAudit('advertiser.mmp_sync', 'advertiser', adv.slug,
    r.ok ? { events_pulled: r.events_pulled, matched: r.matched, approved: r.auto_approved, rejected: r.auto_rejected, flagged: r.flagged } : { error: r.error }, req);
  const msg = r.ok
    ? `Sync complete — ${r.events_pulled} pulled, ${r.matched} matched, ${r.auto_approved} approved, ${r.auto_rejected} rejected${r.flagged ? `, ${r.flagged} flagged for review` : ''}`
    : `Sync failed — ${r.error}`;
  res.redirect(`/admin/advertisers/${adv.slug}/mmp-sync?msg=${encodeURIComponent(msg)}&ok=${r.ok ? '1' : '0'}`);
});

// ---------------------------------------------------------------------------
// Admin — manual conversion status override (F15: un-flag a duplicate)
// ---------------------------------------------------------------------------

app.post('/admin/conversions/:id/status', requireAdmin, (req, res) => {
  const conv = db.prepare('SELECT * FROM conversions WHERE id = ?').get(req.params.id);
  if (!conv) return res.redirect('/admin?msg=Conversion+not+found&ok=0');
  const next = req.body.status;
  if (!['pending', 'approved', 'rejected'].includes(next)) {
    return res.redirect('/admin?msg=Invalid+status&ok=0');
  }
  db.prepare('UPDATE conversions SET status = ?, reason = ? WHERE id = ?')
    .run(next, next === conv.status ? conv.reason : `manual_override_from_${conv.status}`, conv.id);
  logAudit('conversion.status_override', 'conversion', conv.id,
    { from: conv.status, to: next, click_id: conv.click_id, advertiser: conv.advertiser_slug }, req);
  res.redirect('/admin?msg=Conversion+status+updated');
});

// ---------------------------------------------------------------------------
// Backlog #1 — set dispute/adjustment state on a conversion (reconciliation report)
// ---------------------------------------------------------------------------
app.post('/admin/conversions/:id/dispute', requireAdmin, (req, res) => {
  const conv = db.prepare('SELECT * FROM conversions WHERE id = ?').get(req.params.id);
  if (!conv) return res.redirect('/admin?msg=Conversion+not+found&ok=0');
  const dispute = ['none', 'disputed', 'resolved'].includes(req.body.dispute_state) ? req.body.dispute_state : conv.dispute_state;
  const adjRaw  = (req.body.adjustment ?? '').toString().trim();
  const adjustment = adjRaw === '' ? null : (isNaN(parseFloat(adjRaw)) ? conv.adjustment : parseFloat(adjRaw));
  const note = (req.body.adjustment_note || '').toString().trim() || null;
  db.prepare('UPDATE conversions SET dispute_state=?, adjustment=?, adjustment_note=? WHERE id=?')
    .run(dispute, adjustment, note, conv.id);
  logAudit('conversion.dispute_updated', 'conversion', conv.id,
    { dispute_state: dispute, adjustment, click_id: conv.click_id, advertiser: conv.advertiser_slug }, req);
  const back = conv.reconciliation_run_id
    ? `/admin/advertisers/${conv.advertiser_slug}/reconcile?run=${conv.reconciliation_run_id}`
    : '/admin';
  res.redirect(`${back}${back.includes('?') ? '&' : '?'}msg=Dispute+state+updated`);
});

// ---------------------------------------------------------------------------
// Admin — conversion goals per advertiser
// ---------------------------------------------------------------------------

app.post('/admin/advertisers/:slug/goals', requireAdmin, (req, res) => {
  const adv = db.prepare('SELECT id, slug FROM advertisers WHERE slug = ?').get(req.params.slug);
  if (!adv) return res.redirect('/admin?msg=Advertiser+not+found&ok=0');
  const name        = (req.body.name || '').trim();
  const token       = (req.body.event_token || '').trim();
  const payout      = parseFloat(req.body.payout) || 0;
  const payoutType  = req.body.payout_type === 'percent' ? 'percent' : 'fixed';
  const description = (req.body.description || '').trim();
  if (!name || !token) {
    return res.redirect(`/admin/advertisers/${adv.slug}/edit?msg=Goal+name+and+event+token+are+required&ok=0`);
  }
  try {
    db.prepare('INSERT INTO goals (advertiser_id, name, event_token, payout, payout_type, description) VALUES (?, ?, ?, ?, ?, ?)')
      .run(adv.id, name, token, payout, payoutType, description);
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE' || (err.message && err.message.includes('UNIQUE'))) {
      return res.redirect(`/admin/advertisers/${adv.slug}/edit?msg=${encodeURIComponent(`Event token "${token}" already exists for this advertiser`)}&ok=0`);
    }
    throw err;
  }
  logAudit('advertiser.goal_added', 'advertiser', adv.slug, { name, event_token: token, payout, payout_type: payoutType }, req);
  res.redirect(`/admin/advertisers/${adv.slug}/edit?msg=${encodeURIComponent(`Goal "${name}" added`)}`);
});

app.post('/admin/advertisers/:slug/goals/:goalId/delete', requireAdmin, (req, res) => {
  const adv = db.prepare('SELECT id, slug FROM advertisers WHERE slug = ?').get(req.params.slug);
  if (!adv) return res.redirect('/admin?msg=Advertiser+not+found&ok=0');
  const goal = db.prepare('SELECT * FROM goals WHERE id = ? AND advertiser_id = ?').get(req.params.goalId, adv.id);
  if (goal) {
    db.prepare('DELETE FROM goals WHERE id = ?').run(goal.id);
    logAudit('advertiser.goal_deleted', 'advertiser', adv.slug, { name: goal.name, event_token: goal.event_token }, req);
  }
  res.redirect(`/admin/advertisers/${adv.slug}/edit?msg=Goal+deleted`);
});

// Backlog #5 — save partner-link template
app.post('/admin/advertisers/:slug/partner-link', requireAdmin, (req, res) => {
  const adv = db.prepare('SELECT id, slug FROM advertisers WHERE slug = ?').get(req.params.slug);
  if (!adv) return res.redirect('/admin?msg=Advertiser+not+found&ok=0');
  const tpl = (req.body.partner_link_template || '').trim().slice(0, 2000) || null;
  db.prepare('UPDATE advertisers SET partner_link_template = ? WHERE id = ?').run(tpl, adv.id);
  logAudit('advertiser.partner_link_saved', 'advertiser', adv.slug, {}, req);
  res.redirect(`/admin/advertisers/${adv.slug}/edit?msg=Partner-link+template+saved`);
});

// Backlog #7 — event name mappings CRUD
app.post('/admin/advertisers/:slug/event-mappings', requireAdmin, (req, res) => {
  const adv = db.prepare('SELECT id, slug FROM advertisers WHERE slug = ?').get(req.params.slug);
  if (!adv) return res.redirect('/admin?msg=Advertiser+not+found&ok=0');
  const src = (req.body.source_event || '').trim().slice(0, 120);
  const dst = (req.body.mapped_event || '').trim().slice(0, 120);
  if (!src || !dst) return res.redirect(`/admin/advertisers/${adv.slug}/edit?msg=Both+event+names+are+required&ok=0`);
  try {
    db.prepare('INSERT INTO event_mappings (advertiser_id, source_event, mapped_event) VALUES (?, ?, ?)').run(adv.id, src, dst);
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE' || (err.message || '').includes('UNIQUE')) {
      return res.redirect(`/admin/advertisers/${adv.slug}/edit?msg=${encodeURIComponent(`Mapping for "${src}" already exists`)}&ok=0`);
    }
    throw err;
  }
  logAudit('advertiser.event_mapping_added', 'advertiser', adv.slug, { source_event: src, mapped_event: dst }, req);
  res.redirect(`/admin/advertisers/${adv.slug}/edit?msg=Event+mapping+added`);
});

app.post('/admin/advertisers/:slug/event-mappings/:id/delete', requireAdmin, (req, res) => {
  const adv = db.prepare('SELECT id, slug FROM advertisers WHERE slug = ?').get(req.params.slug);
  if (!adv) return res.redirect('/admin?msg=Advertiser+not+found&ok=0');
  db.prepare('DELETE FROM event_mappings WHERE id = ? AND advertiser_id = ?').run(req.params.id, adv.id);
  logAudit('advertiser.event_mapping_deleted', 'advertiser', adv.slug, { id: req.params.id }, req);
  res.redirect(`/admin/advertisers/${adv.slug}/edit?msg=Event+mapping+deleted`);
});

// Backlog #8 — Postback Test Tool (admin fires a test postback and shows the response)
app.get('/admin/advertisers/:slug/postback-test', requireAdmin, (req, res) => {
  const adv = db.prepare('SELECT * FROM advertisers WHERE slug = ?').get(req.params.slug);
  if (!adv) return res.redirect('/admin?msg=Advertiser+not+found&ok=0');
  const recentClick = db.prepare('SELECT click_id FROM clicks WHERE advertiser_slug = ? ORDER BY created_at DESC LIMIT 1').get(adv.slug);
  res.send(renderPostbackTest({ adv, csrfToken: req.session.csrfToken, prefillClick: recentClick?.click_id || '', result: null }));
});

app.post('/admin/advertisers/:slug/postback-test', requireAdmin, async (req, res) => {
  const adv = db.prepare('SELECT * FROM advertisers WHERE slug = ?').get(req.params.slug);
  if (!adv) return res.redirect('/admin?msg=Advertiser+not+found&ok=0');
  const clickId = (req.body.click_id || '').trim();
  const event   = (req.body.event || 'sale').trim();
  const payout  = (req.body.payout || '').trim();
  const loan    = (req.body.loan_amount || '').trim();
  const params = new URLSearchParams({ click_id: clickId, event });
  if (payout) params.set('payout', payout);
  if (loan)   params.set('loan_amount', loan);
  // Backlog #8 — include an HMAC signature when the advertiser has a secret set, so the
  // test exercises the exact signed-postback path partners must use.
  if (adv.postback_secret) {
    const base = [clickId, event, payout || ''].join(':');
    params.set('sig', crypto.createHmac('sha256', adv.postback_secret).update(base).digest('hex'));
  }
  const url = `${BASE_URL}/postback/${adv.slug}?${params.toString()}`;
  let result;
  try {
    const r = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(8000) });
    let bodyTxt = ''; try { bodyTxt = await r.text(); } catch {}
    result = { ok: r.ok, status: r.status, url, body: bodyTxt.slice(0, 1000) };
  } catch (e) {
    result = { ok: false, status: 0, url, body: `Request failed: ${e.message}` };
  }
  logAudit('advertiser.postback_test', 'advertiser', adv.slug, { status: result.status, click_id: clickId, event }, req);
  res.send(renderPostbackTest({ adv, csrfToken: req.session.csrfToken, prefillClick: clickId, result }));
});

// Backlog #11 — set/clear advertiser portal password
app.post('/admin/advertisers/:slug/portal-password', requireAdmin, (req, res) => {
  const adv = db.prepare('SELECT id, slug FROM advertisers WHERE slug = ?').get(req.params.slug);
  if (!adv) return res.redirect('/admin?msg=Advertiser+not+found&ok=0');
  const pw = (req.body.portal_password || '').trim();
  if (pw === '') {
    db.prepare('UPDATE advertisers SET portal_password_hash = NULL WHERE id = ?').run(adv.id);
    logAudit('advertiser.portal_disabled', 'advertiser', adv.slug, {}, req);
    return res.redirect(`/admin/advertisers/${adv.slug}/edit?msg=Advertiser+portal+disabled`);
  }
  if (pw.length < 8) return res.redirect(`/admin/advertisers/${adv.slug}/edit?msg=Portal+password+must+be+at+least+8+characters&ok=0`);
  db.prepare('UPDATE advertisers SET portal_password_hash = ? WHERE id = ?').run(hashPassword(pw), adv.id);
  logAudit('advertiser.portal_enabled', 'advertiser', adv.slug, {}, req);
  res.redirect(`/admin/advertisers/${adv.slug}/edit?msg=Advertiser+portal+access+updated`);
});


app.post('/admin/advertisers/:slug/update', requireAdmin, (req, res) => {
  const { name, offer_url, payout_amount, status } = req.body;
  const payoutType = req.body.payout_type === 'percent' ? 'percent' : 'fixed';
  // Backlog #3 — default 90d aligns with AppsFlyer's default click lookback window;
  // a misaligned window rejects valid postbacks (and disputes the rejections).
  const lookback = parseInt(req.body.click_lookback_window, 10) > 0 ? parseInt(req.body.click_lookback_window, 10) : 90;
  const cap = (req.body.monthly_conversion_cap !== '' && req.body.monthly_conversion_cap != null && parseInt(req.body.monthly_conversion_cap, 10) >= 0)
    ? parseInt(req.body.monthly_conversion_cap, 10) : null;
  const isPublic = req.body.is_public ? 1 : 0;
  const category = (req.body.category || '').trim() || null;
  const description = (req.body.description || '').trim() || null;
  const countriesAllowed = (req.body.countries_allowed || '').trim() || null;
  const postbackSecret = (req.body.postback_secret || '').trim() || null;
  const mmpType = ['appsflyer', 'adjust'].includes(req.body.mmp_type) ? req.body.mmp_type : 'none';
  const mmpAppId = (req.body.mmp_app_id || '').trim() || null;
  const mmpTokenRaw = (req.body.mmp_api_token || '').trim();
  // Backlog #4 — per-advertiser timezone + currency (validated; default USD)
  const timezone = validTz((req.body.timezone || '').trim()) || null;
  const currency = ((req.body.currency || 'USD').trim().toUpperCase().slice(0, 8)) || 'USD';
  const { slug } = req.params;
  const adv = db.prepare('SELECT * FROM advertisers WHERE slug = ?').get(slug);
  if (!adv) return res.redirect('/admin?msg=Advertiser+not+found&ok=0');
  // H2 — only overwrite the encrypted token when a new non-empty value is submitted;
  // a blank field keeps the existing stored (encrypted) value.
  const mmpToken = mmpTokenRaw ? encryptToken(mmpTokenRaw) : adv.mmp_api_token;
  if (!name) return res.send(renderAdvForm({ title: 'Edit Advertiser',
    action: `/admin/advertisers/${slug}/update`, adv: { slug, ...req.body }, error: 'Name is required.', csrfToken: req.session.csrfToken }));

  // F12 — a changed cap_reset_month resets the month's count: stamp the count floor
  // (cap_reset_at = now), re-activate the advertiser, and clear the alert throttle.
  const submittedReset = (req.body.cap_reset_month || '').trim() || null;
  const isReset = submittedReset && submittedReset !== (adv.cap_reset_month || null);

  if (isReset) {
    db.prepare(`UPDATE advertisers SET name=?, offer_url=?, payout_amount=?, payout_type=?, click_lookback_window=?,
        monthly_conversion_cap=?, is_public=?, category=?, description=?, countries_allowed=?, postback_secret=?,
        mmp_type=?, mmp_app_id=?, mmp_api_token=?, timezone=?, currency=?,
        status='active', cap_reset_month=?, cap_reset_at=datetime('now'),
        cap_alert_month=strftime('%Y-%m','now'), cap_alerted_80=0, cap_alerted_100=0 WHERE slug=?`)
      .run(name.trim(), offer_url || '', parseFloat(payout_amount) || 0, payoutType, lookback, cap,
        isPublic, category, description, countriesAllowed, postbackSecret, mmpType, mmpAppId, mmpToken, timezone, currency, submittedReset, slug);
  } else {
    db.prepare(`UPDATE advertisers SET name=?, offer_url=?, payout_amount=?, payout_type=?, click_lookback_window=?,
        monthly_conversion_cap=?, is_public=?, category=?, description=?, countries_allowed=?, postback_secret=?,
        mmp_type=?, mmp_app_id=?, mmp_api_token=?, timezone=?, currency=?, status=? WHERE slug=?`)
      .run(name.trim(), offer_url || '', parseFloat(payout_amount) || 0, payoutType, lookback, cap,
        isPublic, category, description, countriesAllowed, postbackSecret, mmpType, mmpAppId, mmpToken, timezone, currency, status || 'active', slug);
  }
  logAudit('advertiser.updated', 'advertiser', slug,
    { name: name.trim(), offer_url: offer_url || '', payout_amount: parseFloat(payout_amount) || 0, payout_type: payoutType,
      click_lookback_window: lookback, monthly_conversion_cap: cap, cap_reset: isReset ? submittedReset : undefined, status: isReset ? 'active' : (status || 'active') }, req);
  res.redirect(`/admin?msg=Advertiser+%22${encodeURIComponent(name)}%22+updated`);
});

app.post('/admin/advertisers/:slug/delete', requireAdmin, (req, res) => {
  const adv = db.prepare('SELECT name FROM advertisers WHERE slug = ?').get(req.params.slug);
  if (!adv) return res.redirect('/admin?msg=Not+found&ok=0');
  db.prepare('DELETE FROM advertisers WHERE slug = ?').run(req.params.slug);
  logAudit('advertiser.deleted', 'advertiser', req.params.slug, { name: adv.name }, req);
  res.redirect(`/admin?msg=Advertiser+%22${encodeURIComponent(adv.name)}%22+deleted`);
});

app.post('/admin/advertisers/:slug/toggle', requireAdmin, (req, res) => {
  const adv = db.prepare('SELECT slug, name, status FROM advertisers WHERE slug = ?').get(req.params.slug);
  if (!adv) return res.redirect('/admin?msg=Not+found&ok=0');
  const next = adv.status === 'active' ? 'paused' : 'active';
  db.prepare('UPDATE advertisers SET status=? WHERE slug=?').run(next, adv.slug);
  logAudit('advertiser.toggled', 'advertiser', adv.slug, { name: adv.name, from: adv.status, to: next }, req);
  res.redirect(`/admin?msg=${encodeURIComponent(adv.name)}+is+now+${next}`);
});

// ---------------------------------------------------------------------------
// Admin — publisher CRUD
// ---------------------------------------------------------------------------

app.get('/admin/publishers', requireAdmin, (req, res) => {
  const flash = req.query.msg
    ? { type: req.query.ok === '0' ? 'error' : 'success', text: req.query.msg } : null;

  const allPubs = db.prepare(`
    SELECT p.id, p.username, p.email, p.company, p.website, p.traffic_sources,
           p.status, p.created_at,
           COUNT(DISTINCT c.click_id)   as clicks,
           COUNT(cv.id)                 as conversions,
           COALESCE(SUM(cv.payout), 0)  as payout
    FROM publishers p
    LEFT JOIN clicks      c  ON c.publisher  = p.username
    LEFT JOIN conversions cv ON cv.publisher = p.username
    GROUP BY p.id
    ORDER BY p.status = 'pending' DESC, payout DESC, p.username
  `).all();

  const pending    = allPubs.filter(p => p.status === 'pending');
  const publishers = allPubs.filter(p => p.status !== 'pending');

  res.send(renderPubList({ publishers, pending, flash, csrfToken: req.session.csrfToken }));
});

app.get('/admin/publishers/new', requireAdmin, (req, res) => {
  res.send(renderPubForm({ title: 'New Publisher', action: '/admin/publishers', pub: {}, csrfToken: req.session.csrfToken }));
});

app.post('/admin/publishers', requireAdmin, (req, res) => {
  const { username, password, status, postback_url } = req.body;
  const uname = (username || '').trim().toLowerCase();
  if (!uname || !password) return res.send(renderPubForm({ title: 'New Publisher',
    action: '/admin/publishers', pub: req.body, error: 'Username and password are required.', csrfToken: req.session.csrfToken }));
  if (!/^[a-z0-9_-]+$/.test(uname)) return res.send(renderPubForm({ title: 'New Publisher',
    action: '/admin/publishers', pub: req.body,
    error: 'Username must be lowercase letters, numbers, underscores, or hyphens.', csrfToken: req.session.csrfToken }));
  if (password.length < 8) return res.send(renderPubForm({ title: 'New Publisher',
    action: '/admin/publishers', pub: req.body, error: 'Password must be at least 8 characters.', csrfToken: req.session.csrfToken }));
  const pbUrl  = (postback_url || '').trim();
  const customDomain = normalizeDomain(req.body.custom_domain);
  const apiKey = generateApiKey();
  try {
    // M3 — store hash + suffix only (no plaintext); the key is shown once on the edit page.
    const info = db.prepare('INSERT INTO publishers (username, password_hash, postback_url, custom_domain, api_key_hash, api_key_suffix, status) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(uname, hashPassword(password), pbUrl, customDomain, hashApiKey(apiKey), apiKey.slice(-8), status || 'active');
    logAudit('publisher.created', 'publisher', uname,
      { username: uname, status: status || 'active', s2s_url: pbUrl || null }, req);
    req.session.newApiKey = apiKey; // shown once on the edit page
    res.redirect(`/admin/publishers/${info.lastInsertRowid}/edit?msg=Publisher+%22${encodeURIComponent(uname)}%22+created+%E2%80%94+copy+the+API+key+now`);
  } catch {
    res.send(renderPubForm({ title: 'New Publisher', action: '/admin/publishers',
      pub: req.body, error: `Username "${uname}" is already taken.`, csrfToken: req.session.csrfToken }));
  }
});

app.get('/admin/publishers/:id/edit', requireAdmin, (req, res) => {
  const pub = db.prepare('SELECT * FROM publishers WHERE id = ?').get(req.params.id);
  if (!pub) return res.redirect('/admin/publishers?msg=Publisher+not+found&ok=0');
  const flash = req.query.msg ? { type: 'success', text: req.query.msg } : null;
  const assignments = db.prepare(`
    SELECT pa.advertiser_id, pa.payout_override, pa.valid_from, pa.valid_until, pa.monthly_cap,
           a.name, a.slug
    FROM publisher_advertisers pa
    JOIN advertisers a ON a.id = pa.advertiser_id
    WHERE pa.publisher_id = ? AND a.slug != 'legacy'
    ORDER BY a.name
  `).all(pub.id);
  const allAdvertisers = db.prepare("SELECT id, name, slug FROM advertisers WHERE slug != 'legacy' ORDER BY name").all();
  const tokenRow = db.prepare(
    "SELECT token, expires_at FROM password_resets WHERE publisher_id = ? AND used_at IS NULL AND expires_at > datetime('now') ORDER BY created_at DESC LIMIT 1"
  ).get(pub.id);
  const resetLink = tokenRow
    ? { url: `${BASE_URL}/publisher/reset-password?token=${tokenRow.token}`, expires: tokenRow.expires_at }
    : null;
  // M2 — show a just-(re)generated API key once, then clear it from the session.
  const newApiKey = req.session.newApiKey || null;
  delete req.session.newApiKey;
  res.send(renderPubForm({ title: `Edit — ${pub.username}`,
    action: `/admin/publishers/${pub.id}/update`, pub, flash, csrfToken: req.session.csrfToken,
    assignments, allAdvertisers, resetLink, newApiKey }));
});

// ---------------------------------------------------------------------------
// Admin — publisher↔advertiser assignment + manual reset link
// ---------------------------------------------------------------------------

app.post('/admin/publishers/:id/assign', requireAdmin, (req, res) => {
  const pub = db.prepare('SELECT id, username FROM publishers WHERE id = ?').get(req.params.id);
  if (!pub) return res.redirect('/admin/publishers?msg=Not+found&ok=0');
  const advId = parseInt(req.body.advertiser_id, 10);
  const adv = advId ? db.prepare("SELECT id, name, slug FROM advertisers WHERE id = ? AND slug != 'legacy'").get(advId) : null;
  if (!adv) return res.redirect(`/admin/publishers/${pub.id}/edit?msg=Invalid+advertiser&ok=0`);

  const num = (v) => (v !== '' && v != null && !isNaN(parseFloat(v))) ? parseFloat(v) : null;
  const int = (v) => (v !== '' && v != null && !isNaN(parseInt(v, 10))) ? parseInt(v, 10) : null;
  const payoutOverride = num(req.body.payout_override);
  const validFrom  = (req.body.valid_from  || '').trim() || null;
  const validUntil = (req.body.valid_until || '').trim() || null;
  const monthlyCap = int(req.body.monthly_cap);

  db.prepare(`
    INSERT INTO publisher_advertisers (publisher_id, advertiser_id, payout_override, valid_from, valid_until, monthly_cap)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(publisher_id, advertiser_id) DO UPDATE SET
      payout_override = excluded.payout_override,
      valid_from      = excluded.valid_from,
      valid_until     = excluded.valid_until,
      monthly_cap     = excluded.monthly_cap
  `).run(pub.id, adv.id, payoutOverride, validFrom, validUntil, monthlyCap);

  logAudit('publisher.advertiser_assigned', 'publisher', pub.username,
    { advertiser: adv.slug, payout_override: payoutOverride, valid_from: validFrom, valid_until: validUntil, monthly_cap: monthlyCap }, req);
  res.redirect(`/admin/publishers/${pub.id}/edit?msg=${encodeURIComponent(adv.name + ' assigned')}`);
});

app.post('/admin/publishers/:id/unassign', requireAdmin, (req, res) => {
  const pub = db.prepare('SELECT id, username FROM publishers WHERE id = ?').get(req.params.id);
  if (!pub) return res.redirect('/admin/publishers?msg=Not+found&ok=0');
  const advId = parseInt(req.body.advertiser_id, 10);
  const adv = advId ? db.prepare('SELECT slug FROM advertisers WHERE id = ?').get(advId) : null;
  db.prepare('DELETE FROM publisher_advertisers WHERE publisher_id = ? AND advertiser_id = ?').run(pub.id, advId);
  logAudit('publisher.advertiser_unassigned', 'publisher', pub.username, { advertiser: adv?.slug ?? advId }, req);
  res.redirect(`/admin/publishers/${pub.id}/edit?msg=Advertiser+unassigned`);
});

app.post('/admin/publishers/:id/reset-link', requireAdmin, (req, res) => {
  const pub = db.prepare('SELECT id, username FROM publishers WHERE id = ?').get(req.params.id);
  if (!pub) return res.redirect('/admin/publishers?msg=Not+found&ok=0');
  // Invalidate any previous outstanding tokens, then issue a fresh one.
  db.prepare("UPDATE password_resets SET used_at = datetime('now') WHERE publisher_id = ? AND used_at IS NULL").run(pub.id);
  createResetToken(pub.id);
  logAudit('publisher.reset_link_generated', 'publisher', pub.username, { by: 'admin' }, req);
  res.redirect(`/admin/publishers/${pub.id}/edit?msg=Reset+link+generated`);
});

// ---------------------------------------------------------------------------
// Admin — smart-link rules per publisher (F5)
// ---------------------------------------------------------------------------

app.get('/admin/publishers/:id/smart-links', requireAdmin, (req, res) => {
  const pub = db.prepare('SELECT * FROM publishers WHERE id = ?').get(req.params.id);
  if (!pub) return res.redirect('/admin/publishers?msg=Publisher+not+found&ok=0');
  const rules = db.prepare(`
    SELECT slr.*, a.name AS adv_name, a.slug AS adv_slug
    FROM smart_link_rules slr JOIN advertisers a ON a.id = slr.advertiser_id
    WHERE slr.publisher_id = ? ORDER BY slr.priority ASC, slr.id ASC
  `).all(pub.id);
  const advertisers = db.prepare("SELECT id, name, slug FROM advertisers WHERE slug != 'legacy' ORDER BY name").all();
  const flash = req.query.msg && req.query.ok !== '0' ? req.query.msg : null;
  const error = req.query.msg && req.query.ok === '0' ? req.query.msg : null;
  res.send(renderSmartLinks({ pub, rules, advertisers, csrfToken: req.session.csrfToken, flash, error }));
});

app.post('/admin/publishers/:id/smart-links', requireAdmin, (req, res) => {
  const pub = db.prepare('SELECT id, username FROM publishers WHERE id = ?').get(req.params.id);
  if (!pub) return res.redirect('/admin/publishers?msg=Not+found&ok=0');
  const advId = parseInt(req.body.advertiser_id, 10);
  const adv = advId ? db.prepare("SELECT id, slug FROM advertisers WHERE id = ? AND slug != 'legacy'").get(advId) : null;
  if (!adv) return res.redirect(`/admin/publishers/${pub.id}/smart-links?msg=Invalid+advertiser&ok=0`);
  // Country: '*' or comma-separated ISO codes (uppercased). Device: mobile/desktop/tablet/*.
  const country = (req.body.country || '*').trim().toUpperCase() || '*';
  const device  = ['mobile', 'desktop', 'tablet', '*'].includes(req.body.device_type) ? req.body.device_type : '*';
  const priority = Number.isInteger(parseInt(req.body.priority, 10)) ? parseInt(req.body.priority, 10) : 100;
  db.prepare('INSERT INTO smart_link_rules (publisher_id, advertiser_id, country, device_type, priority) VALUES (?, ?, ?, ?, ?)')
    .run(pub.id, adv.id, country, device, priority);
  logAudit('publisher.smart_link_added', 'publisher', pub.username, { advertiser: adv.slug, country, device_type: device, priority }, req);
  res.redirect(`/admin/publishers/${pub.id}/smart-links?msg=Rule+added`);
});

app.post('/admin/publishers/:id/smart-links/:ruleId/delete', requireAdmin, (req, res) => {
  const pub = db.prepare('SELECT id, username FROM publishers WHERE id = ?').get(req.params.id);
  if (!pub) return res.redirect('/admin/publishers?msg=Not+found&ok=0');
  db.prepare('DELETE FROM smart_link_rules WHERE id = ? AND publisher_id = ?').run(req.params.ruleId, pub.id);
  logAudit('publisher.smart_link_deleted', 'publisher', pub.username, { rule_id: req.params.ruleId }, req);
  res.redirect(`/admin/publishers/${pub.id}/smart-links?msg=Rule+deleted`);
});

// ---------------------------------------------------------------------------
// Admin — marketplace application review (F6)
// ---------------------------------------------------------------------------

app.get('/admin/marketplace', requireAdmin, (req, res) => {
  const pending = db.prepare(`
    SELECT ma.id, ma.applied_at, p.id AS pub_id, p.username, a.id AS adv_id, a.name AS adv_name, a.slug AS adv_slug
    FROM marketplace_applications ma
    JOIN publishers  p ON p.id = ma.publisher_id
    JOIN advertisers a ON a.id = ma.advertiser_id
    WHERE ma.status = 'pending'
    ORDER BY ma.applied_at ASC
  `).all();

  // Per-advertiser aggregate stats (admin-only — these are business-sensitive) to
  // help decide approve/reject: active publishers, total paid, approval rate.
  const activePubsStmt = db.prepare('SELECT COUNT(DISTINCT publisher_id) AS n FROM publisher_advertisers WHERE advertiser_id = ?');
  const paidStmt       = db.prepare("SELECT COALESCE(SUM(payout),0) AS s FROM conversions WHERE advertiser_slug = ? AND status = 'approved'");
  const convCountStmt  = db.prepare("SELECT COUNT(*) AS total, SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END) AS approved FROM conversions WHERE advertiser_slug = ?");
  for (const row of pending) {
    row.active_publishers = activePubsStmt.get(row.adv_id).n;
    row.total_paid = paidStmt.get(row.adv_slug).s;
    const cc = convCountStmt.get(row.adv_slug);
    row.approval_rate = cc.total > 0 ? (cc.approved / cc.total) * 100 : null;
  }

  const flash = req.query.msg || null;
  res.send(renderAdminMarketplace({ pending, csrfToken: req.session.csrfToken, flash }));
});

app.post('/admin/marketplace/:appId/approve', requireAdmin, (req, res) => {
  const app_ = db.prepare("SELECT * FROM marketplace_applications WHERE id = ? AND status = 'pending'").get(req.params.appId);
  if (!app_) return res.redirect('/admin/marketplace?msg=' + encodeURIComponent('Application not found or already decided'));
  // Auto-create the assignment (no-op if it somehow already exists), then mark approved.
  db.prepare(`INSERT INTO publisher_advertisers (publisher_id, advertiser_id) VALUES (?, ?)
              ON CONFLICT(publisher_id, advertiser_id) DO NOTHING`).run(app_.publisher_id, app_.advertiser_id);
  db.prepare("UPDATE marketplace_applications SET status = 'approved', decided_at = datetime('now') WHERE id = ?").run(app_.id);
  const pub = db.prepare('SELECT username FROM publishers WHERE id = ?').get(app_.publisher_id);
  const adv = db.prepare('SELECT slug FROM advertisers WHERE id = ?').get(app_.advertiser_id);
  logAudit('marketplace.approved', 'publisher', pub?.username, { advertiser: adv?.slug, application_id: app_.id }, req);
  res.redirect('/admin/marketplace?msg=' + encodeURIComponent('Approved — assignment created'));
});

app.post('/admin/marketplace/:appId/reject', requireAdmin, (req, res) => {
  const app_ = db.prepare("SELECT * FROM marketplace_applications WHERE id = ? AND status = 'pending'").get(req.params.appId);
  if (!app_) return res.redirect('/admin/marketplace?msg=' + encodeURIComponent('Application not found or already decided'));
  db.prepare("UPDATE marketplace_applications SET status = 'rejected', decided_at = datetime('now') WHERE id = ?").run(app_.id);
  const pub = db.prepare('SELECT username FROM publishers WHERE id = ?').get(app_.publisher_id);
  const adv = db.prepare('SELECT slug FROM advertisers WHERE id = ?').get(app_.advertiser_id);
  logAudit('marketplace.rejected', 'publisher', pub?.username, { advertiser: adv?.slug, application_id: app_.id }, req);
  res.redirect('/admin/marketplace?msg=' + encodeURIComponent('Application rejected'));
});

app.post('/admin/publishers/:id/update', requireAdmin, (req, res) => {
  const { password, status, postback_url, minimum_payout } = req.body;
  const { id } = req.params;
  const pub = db.prepare('SELECT * FROM publishers WHERE id = ?').get(id);
  if (!pub) return res.redirect('/admin/publishers?msg=Not+found&ok=0');
  if (password && password.length < 8) return res.send(renderPubForm({ title: `Edit — ${pub.username}`,
    action: `/admin/publishers/${id}/update`, pub: { ...pub, ...req.body },
    error: 'Password must be at least 8 characters.', csrfToken: req.session.csrfToken }));
  const pbUrl  = (postback_url || '').trim();
  const minPay = parseFloat(minimum_payout) >= 0 ? parseFloat(minimum_payout) : 50;
  const customDomain = normalizeDomain(req.body.custom_domain);
  if (password) {
    db.prepare('UPDATE publishers SET password_hash=?, postback_url=?, custom_domain=?, status=?, minimum_payout=? WHERE id=?')
      .run(hashPassword(password), pbUrl, customDomain, status || 'active', minPay, id);
  } else {
    db.prepare('UPDATE publishers SET postback_url=?, custom_domain=?, status=?, minimum_payout=? WHERE id=?')
      .run(pbUrl, customDomain, status || 'active', minPay, id);
  }
  const detail = { status: status || 'active', password_changed: !!password, minimum_payout: minPay };
  if (pbUrl !== (pub.postback_url || '')) {
    detail.s2s_url_old = pub.postback_url || '';
    detail.s2s_url_new = pbUrl;
    logAudit('s2s_postback.updated', 'publisher', pub.username,
      { old_url: pub.postback_url || '', new_url: pbUrl }, req);
  }
  logAudit('publisher.updated', 'publisher', pub.username, detail, req);
  res.redirect(`/admin/publishers?msg=Publisher+%22${encodeURIComponent(pub.username)}%22+updated`);
});

app.post('/admin/publishers/:id/delete', requireAdmin, (req, res) => {
  const pub = db.prepare('SELECT username FROM publishers WHERE id = ?').get(req.params.id);
  if (!pub) return res.redirect('/admin/publishers?msg=Not+found&ok=0');
  db.prepare('DELETE FROM publishers WHERE id = ?').run(req.params.id);
  logAudit('publisher.deleted', 'publisher', pub.username, { username: pub.username }, req);
  res.redirect(`/admin/publishers?msg=Publisher+%22${encodeURIComponent(pub.username)}%22+deleted`);
});

app.post('/admin/publishers/:id/toggle', requireAdmin, (req, res) => {
  const pub = db.prepare('SELECT id, username, status FROM publishers WHERE id = ?').get(req.params.id);
  if (!pub) return res.redirect('/admin/publishers?msg=Not+found&ok=0');
  const next = pub.status === 'active' ? 'paused' : 'active';
  db.prepare('UPDATE publishers SET status=? WHERE id=?').run(next, pub.id);
  logAudit('publisher.toggled', 'publisher', pub.username, { from: pub.status, to: next }, req);
  res.redirect(`/admin/publishers?msg=${encodeURIComponent(pub.username)}+is+now+${next}`);
});

// Regenerate API key
app.post('/admin/publishers/:id/regenerate-key', requireAdmin, (req, res) => {
  const pub = db.prepare('SELECT id, username, api_key_suffix FROM publishers WHERE id = ?').get(req.params.id);
  if (!pub) return res.redirect('/admin/publishers?msg=Not+found&ok=0');
  const newKey = generateApiKey();
  // M3 — store hash + suffix only; never retain the plaintext key.
  db.prepare('UPDATE publishers SET api_key = NULL, api_key_hash = ?, api_key_suffix = ? WHERE id = ?')
    .run(hashApiKey(newKey), newKey.slice(-8), pub.id);
  // M2 — surface the new key once via the session (not the redirect URL).
  req.session.newApiKey = newKey;
  logAudit('api_key.regenerated', 'publisher', pub.username, { old_key_suffix: pub.api_key_suffix || null }, req);
  res.redirect(`/admin/publishers/${pub.id}/edit?msg=API+key+regenerated`);
});

// Revoke API key (sets to NULL — publisher can no longer use key auth)
app.post('/admin/publishers/:id/revoke-key', requireAdmin, (req, res) => {
  const pub = db.prepare('SELECT id, username FROM publishers WHERE id = ?').get(req.params.id);
  if (!pub) return res.redirect('/admin/publishers?msg=Not+found&ok=0');
  db.prepare('UPDATE publishers SET api_key = NULL, api_key_hash = NULL, api_key_suffix = NULL WHERE id = ?').run(pub.id);
  logAudit('api_key.revoked', 'publisher', pub.username, {}, req);
  res.redirect(`/admin/publishers/${pub.id}/edit?msg=API+key+revoked`);
});

// Payments
app.get('/admin/publishers/:id/payments', requireAdmin, (req, res) => {
  const pub = db.prepare('SELECT * FROM publishers WHERE id = ?').get(req.params.id);
  if (!pub) return res.redirect('/admin/publishers?msg=Not+found&ok=0');
  const flash = req.query.msg ? { type: req.query.ok === '0' ? 'error' : 'success', text: req.query.msg } : null;
  const payments = db.prepare(`
    SELECT * FROM payments WHERE publisher_id = ? ORDER BY paid_at DESC
  `).all(pub.id);
  const totalPaid = payments.reduce((s, p) => s + p.amount_usd, 0);
  const balRows = db.prepare(
    "SELECT currency, COALESCE(SUM(CASE WHEN status='approved' THEN payout ELSE 0 END),0) as bal FROM conversions WHERE publisher=? GROUP BY currency"
  ).all(pub.username);
  const approvedByCurrency = balRows.map(r => ({ currency: r.currency, total: r.bal }));
  const approvedBalance = (balRows.find(r => r.currency === 'USD') || {}).bal || 0; // USD-only for the balance math
  res.send(renderPaymentsPage({ pub, payments, totalPaid, approvedBalance, approvedByCurrency, flash, csrfToken: req.session.csrfToken }));
});

app.post('/admin/publishers/:id/payments', requireAdmin, (req, res) => {
  const pub = db.prepare('SELECT * FROM publishers WHERE id = ?').get(req.params.id);
  if (!pub) return res.redirect('/admin/publishers?msg=Not+found&ok=0');
  const amount = parseFloat(req.body.amount_usd);
  const paidAt = (req.body.paid_at || '').trim();
  const method = (req.body.method || 'Wire Transfer').trim();
  const notes  = (req.body.notes  || '').trim();
  if (!amount || amount <= 0) return res.redirect(`/admin/publishers/${pub.id}/payments?msg=Invalid+amount&ok=0`);
  if (!paidAt)                return res.redirect(`/admin/publishers/${pub.id}/payments?msg=Date+required&ok=0`);
  db.prepare(`
    INSERT INTO payments (publisher_id, publisher_name, amount_usd, paid_at, method, notes)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(pub.id, pub.username, amount, paidAt, method, notes);
  logAudit('payment.recorded', 'publisher', pub.username, { amount_usd: amount, paid_at: paidAt, method }, req);
  res.redirect(`/admin/publishers/${pub.id}/payments?msg=Payment+recorded`);
});

// Approve pending registration
app.post('/admin/publishers/:id/approve', requireAdmin, (req, res) => {
  const pub = db.prepare('SELECT * FROM publishers WHERE id = ?').get(req.params.id);
  if (!pub) return res.redirect('/admin/publishers?msg=Not+found&ok=0');
  const apiKey = generateApiKey();
  db.prepare("UPDATE publishers SET status='active', api_key=?, api_key_hash=? WHERE id=?").run(apiKey, hashApiKey(apiKey), pub.id);
  logAudit('publisher.approved', 'publisher', pub.username, { email: pub.email }, req);
  res.redirect(`/admin/publishers?msg=Publisher+%22${encodeURIComponent(pub.username)}%22+approved`);
});

// Reject pending registration
app.post('/admin/publishers/:id/reject', requireAdmin, (req, res) => {
  const pub = db.prepare('SELECT * FROM publishers WHERE id = ?').get(req.params.id);
  if (!pub) return res.redirect('/admin/publishers?msg=Not+found&ok=0');
  const note = (req.body.note || '').trim();
  db.prepare("UPDATE publishers SET status='rejected', registration_note=? WHERE id=?").run(note, pub.id);
  logAudit('publisher.rejected', 'publisher', pub.username, { note }, req);
  res.redirect(`/admin/publishers?msg=Publisher+%22${encodeURIComponent(pub.username)}%22+rejected`);
});

// Postback log per publisher
app.get('/admin/publishers/:id/postback-log', requireAdmin, (req, res) => {
  const pub = db.prepare('SELECT id, username, postback_url FROM publishers WHERE id = ?').get(req.params.id);
  if (!pub) return res.redirect('/admin/publishers?msg=Not+found&ok=0');

  const logs = db.prepare(`
    SELECT id, click_id, url, http_status, attempt, success, error, fired_at
    FROM postback_log
    WHERE publisher = ?
    ORDER BY fired_at DESC
    LIMIT 200
  `).all(pub.username);

  const stats = db.prepare(`
    SELECT COUNT(*) as total,
           SUM(success) as succeeded,
           COUNT(*) - SUM(success) as failed
    FROM postback_log WHERE publisher = ?
  `).get(pub.username);

  res.send(renderPostbackLog({ pub, logs, stats }));
});

// ---------------------------------------------------------------------------
// Backlog #2 — global Postback Delivery Log (sent S2S + received conversions),
// filterable, with duplicate detection for debugging failed/duplicate postbacks.
// "Sent" = outbound S2S we fire to publishers (postback_log). "Received" = inbound
// conversion postbacks advertisers/MMPs fire to us (one row per conversion).
// ---------------------------------------------------------------------------
app.get('/admin/postback-log', requireAdmin, (req, res) => {
  const dir    = ['sent', 'received'].includes(req.query.dir) ? req.query.dir : 'sent';
  const status = ['ok', 'fail'].includes(req.query.status) ? req.query.status : 'all';
  const q      = (req.query.q || '').trim();
  const like   = `%${q}%`;
  const LIMIT  = 300;

  let rows, stats, dupSet;
  if (dir === 'received') {
    const where = ['1=1'];
    const params = [];
    if (q) { where.push('(cv.click_id LIKE ? OR cv.publisher LIKE ? OR cv.advertiser_slug LIKE ?)'); params.push(like, like, like); }
    if (status === 'ok')   where.push("cv.status = 'approved'");
    if (status === 'fail') where.push("cv.status IN ('rejected','duplicate')");
    const w = where.join(' AND ');
    rows = db.prepare(`SELECT cv.id, cv.click_id, cv.advertiser_slug, cv.publisher, cv.event, cv.status, cv.reason, cv.received_at AS ts
      FROM conversions cv WHERE ${w} ORDER BY cv.received_at DESC LIMIT ${LIMIT}`).all(...params);
    const s = db.prepare(`SELECT COUNT(*) total,
        SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END) ok,
        SUM(CASE WHEN status IN ('rejected','duplicate') THEN 1 ELSE 0 END) fail FROM conversions`).get();
    stats = { total: s.total, succeeded: s.ok, failed: s.fail };
    // duplicate = same click_id received more than once (across events)
    const dups = db.prepare('SELECT click_id FROM conversions GROUP BY click_id HAVING COUNT(*) > 1').all();
    dupSet = new Set(dups.map(d => d.click_id));
  } else {
    const where = ['1=1'];
    const params = [];
    if (q) { where.push('(click_id LIKE ? OR publisher LIKE ? OR url LIKE ?)'); params.push(like, like, like); }
    if (status === 'ok')   where.push('success = 1');
    if (status === 'fail') where.push('success = 0');
    const w = where.join(' AND ');
    rows = db.prepare(`SELECT id, publisher, click_id, url, http_status, attempt, success, error, fired_at AS ts
      FROM postback_log WHERE ${w} ORDER BY fired_at DESC LIMIT ${LIMIT}`).all(...params);
    const s = db.prepare('SELECT COUNT(*) total, SUM(success) ok, COUNT(*)-SUM(success) fail FROM postback_log').get();
    stats = { total: s.total, succeeded: s.ok || 0, failed: s.fail || 0 };
    // duplicate = same click_id fired more than once
    const dups = db.prepare('SELECT click_id FROM postback_log GROUP BY click_id HAVING COUNT(*) > 1').all();
    dupSet = new Set(dups.map(d => d.click_id));
  }

  res.send(renderGlobalPostbackLog({ dir, status, q, rows, stats, dupCount: dupSet.size, dupSet }));
});

// ---------------------------------------------------------------------------
// Invoices
// ---------------------------------------------------------------------------

function invoiceLines(username, year, month) {
  const pad  = String(month).padStart(2, '0');
  const from = `${year}-${pad}-01`;
  const to   = `${year}-${pad}-31`;
  return db.prepare(`
    SELECT cv.id, cv.click_id, cv.advertiser_slug, cv.event, cv.payout, cv.currency,
           cv.received_at, a.name as adv_name
    FROM   conversions cv
    LEFT JOIN advertisers a ON a.slug = cv.advertiser_slug
    WHERE  cv.publisher = ?
      AND  cv.status    = 'approved'
      AND  date(cv.received_at) BETWEEN ? AND ?
    ORDER  BY cv.received_at
  `).all(username, from, to);
}

// QA2 — sum invoice lines per currency (never mixed). Returns [{currency, total}].
function invoiceTotalsByCurrency(lines) {
  const m = new Map();
  for (const l of lines) { const c = l.currency || 'USD'; m.set(c, (m.get(c) || 0) + l.payout); }
  return [...m.entries()].map(([currency, total]) => ({ currency, total }));
}

function upsertInvoice(pubId, pubName, year, month, total) {
  db.prepare(`
    INSERT INTO invoices (publisher_id, publisher_name, year, month, total_amount)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(publisher_id, year, month) DO UPDATE SET
      total_amount = excluded.total_amount,
      updated_at   = datetime('now')
  `).run(pubId, pubName, year, month, total);
  return db.prepare(
    'SELECT * FROM invoices WHERE publisher_id = ? AND year = ? AND month = ?'
  ).get(pubId, year, month);
}

// List all invoices
app.get('/admin/invoices', requireAdmin, (req, res) => {
  const flash = req.query.msg
    ? { type: req.query.ok === '0' ? 'error' : 'success', text: req.query.msg } : null;
  const invoices = db.prepare(`
    SELECT * FROM invoices ORDER BY year DESC, month DESC, publisher_name
  `).all();
  res.send(renderInvoiceList({ invoices, flash }));
});

// View / auto-create invoice
app.get('/admin/publishers/:id/invoice/:year/:month', requireAdmin, (req, res) => {
  const pub = db.prepare('SELECT * FROM publishers WHERE id = ?').get(req.params.id);
  if (!pub) return res.redirect('/admin/publishers?msg=Publisher+not+found&ok=0');

  const year  = parseInt(req.params.year,  10);
  const month = parseInt(req.params.month, 10);
  if (!year || month < 1 || month > 12) return res.redirect('/admin/publishers?msg=Invalid+period&ok=0');

  const lines = invoiceLines(pub.username, year, month);
  const totalsByCurrency = invoiceTotalsByCurrency(lines);
  const totalUsd = (totalsByCurrency.find(t => t.currency === 'USD') || {}).total || 0;

  const inv   = upsertInvoice(pub.id, pub.username, year, month, totalUsd); // stored total is USD-only (never mixed)
  const flash = req.query.msg
    ? { type: req.query.ok === '0' ? 'error' : 'success', text: req.query.msg } : null;

  res.send(renderInvoice({ inv, pub, lines, totalsByCurrency, flash, csrfToken: req.session.csrfToken }));
});

// Regenerate (recalculate total from live approved conversions)
app.post('/admin/publishers/:id/invoice/:year/:month/regenerate', requireAdmin, (req, res) => {
  const pub = db.prepare('SELECT * FROM publishers WHERE id = ?').get(req.params.id);
  if (!pub) return res.redirect('/admin/publishers?msg=Not+found&ok=0');

  const year  = parseInt(req.params.year,  10);
  const month = parseInt(req.params.month, 10);
  if (!year || month < 1 || month > 12) return res.redirect('/admin/publishers?msg=Invalid+period&ok=0');

  const lines = invoiceLines(pub.username, year, month);
  const totalUsd = (invoiceTotalsByCurrency(lines).find(t => t.currency === 'USD') || {}).total || 0;
  upsertInvoice(pub.id, pub.username, year, month, totalUsd);
  logAudit('invoice.regenerated', 'invoice', `${pub.username}/${year}/${month}`, { total }, req);
  res.redirect(`/admin/publishers/${pub.id}/invoice/${year}/${month}?msg=Invoice+regenerated`);
});

// Update notes
app.post('/admin/publishers/:id/invoice/:year/:month/notes', requireAdmin, (req, res) => {
  const pub = db.prepare('SELECT * FROM publishers WHERE id = ?').get(req.params.id);
  if (!pub) return res.redirect('/admin/publishers?msg=Not+found&ok=0');

  const year  = parseInt(req.params.year,  10);
  const month = parseInt(req.params.month, 10);
  const notes = (req.body.notes || '').trim().slice(0, 1000);

  db.prepare(`
    UPDATE invoices SET notes = ?, updated_at = datetime('now')
    WHERE publisher_id = ? AND year = ? AND month = ?
  `).run(notes, pub.id, year, month);
  res.redirect(`/admin/publishers/${pub.id}/invoice/${year}/${month}?msg=Notes+saved`);
});

// Update status
app.post('/admin/invoices/:id/status', requireAdmin, (req, res) => {
  const inv = db.prepare('SELECT * FROM invoices WHERE id = ?').get(req.params.id);
  if (!inv) return res.redirect('/admin/invoices?msg=Not+found&ok=0');

  const next = ['draft', 'sent', 'paid'].includes(req.body.status) ? req.body.status : null;
  if (!next) return res.redirect(`/admin/publishers/${inv.publisher_id}/invoice/${inv.year}/${inv.month}?msg=Invalid+status&ok=0`);

  db.prepare("UPDATE invoices SET status = ?, updated_at = datetime('now') WHERE id = ?").run(next, inv.id);
  logAudit('invoice.status_changed', 'invoice', inv.id, { from: inv.status, to: next, publisher: inv.publisher_name }, req);
  res.redirect(`/admin/publishers/${inv.publisher_id}/invoice/${inv.year}/${inv.month}?msg=Status+updated+to+${next}`);
});

// ---------------------------------------------------------------------------
// Admin settings
// ---------------------------------------------------------------------------

app.get('/admin/settings', requireAdmin, (req, res) => {
  const flash = req.query.msg
    ? { type: req.query.ok === '0' ? 'error' : 'success', text: req.query.msg } : null;
  res.send(renderSettingsPage({ flash, csrfToken: req.session.csrfToken || '' }));
});

app.post('/admin/settings', requireAdmin, (req, res) => {
  const emailOn      = req.body.email_notifications   === 'on';
  const summaryOn    = req.body.daily_summary         === 'on';
  const webhookOn    = req.body.webhook_notifications === 'on';
  const webhookSumOn = req.body.webhook_daily_summary === 'on';
  setSetting('email_notifications',   emailOn      ? 'true' : 'false');
  setSetting('daily_summary',         summaryOn    ? 'true' : 'false');
  setSetting('webhook_notifications', webhookOn    ? 'true' : 'false');
  setSetting('webhook_daily_summary', webhookSumOn ? 'true' : 'false');
  logAudit('settings.changed', 'settings', null,
    { email_notifications: emailOn, daily_summary: summaryOn,
      webhook_notifications: webhookOn, webhook_daily_summary: webhookSumOn }, req);
  res.redirect('/admin/settings?msg=Settings+saved');
});

app.post('/admin/settings/test-email', requireAdmin, (req, res) => {
  if (!transporter) {
    return res.redirect('/admin/settings?msg=Gmail+not+configured+%28set+GMAIL_USER+%26+GMAIL_PASS%29&ok=0');
  }
  sendMail({
    subject: '[Komorebi] Test email',
    text: 'This is a test email from Komorebi Affiliate Tracker. Email notifications are working correctly.',
    html: '<p style="font-family:sans-serif">This is a test email from <strong>Komorebi Affiliate Tracker</strong>. Email notifications are working correctly.</p>',
  })
    .then(() => res.redirect('/admin/settings?msg=Test+email+sent+to+' + encodeURIComponent(ADMIN_EMAIL)))
    .catch(e  => res.redirect('/admin/settings?msg=' + encodeURIComponent('Send failed: ' + e.message) + '&ok=0'));
});

app.post('/admin/settings/test-telegram', requireAdmin, (req, res) => {
  if (!telegramOk()) {
    return res.redirect('/admin/settings?msg=Telegram+not+configured+%28set+TELEGRAM_BOT_TOKEN+%26+TELEGRAM_CHAT_ID%29&ok=0');
  }
  sendTelegram('\u{2705} Komorebi test message — Telegram notifications are working correctly.')
    .then(() => res.redirect('/admin/settings?msg=Telegram+test+message+sent'))
    .catch(e  => res.redirect('/admin/settings?msg=' + encodeURIComponent('Telegram failed: ' + e.message) + '&ok=0'));
});

app.post('/admin/settings/test-slack', requireAdmin, (req, res) => {
  if (!slackOk()) {
    return res.redirect('/admin/settings?msg=Slack+not+configured+%28set+SLACK_WEBHOOK_URL%29&ok=0');
  }
  sendSlack('\u{2705} Komorebi test message — Slack notifications are working correctly.')
    .then(() => res.redirect('/admin/settings?msg=Slack+test+message+sent'))
    .catch(e  => res.redirect('/admin/settings?msg=' + encodeURIComponent('Slack failed: ' + e.message) + '&ok=0'));
});

function updateEnvFile(key, value) {
  const envPath = path.join(__dirname, '.env');
  let content = '';
  try { content = fs.readFileSync(envPath, 'utf8'); } catch { /* file may not exist yet */ }
  const regex = new RegExp(`^${key}=.*$`, 'm');
  const line  = `${key}=${value}`;
  if (regex.test(content)) {
    content = content.replace(regex, line);
  } else {
    content = content + (content && !content.endsWith('\n') ? '\n' : '') + line + '\n';
  }
  fs.writeFileSync(envPath, content, 'utf8');
}

app.post('/admin/settings/password', requireAdmin, (req, res) => {
  const { current_password, new_password, confirm_password } = req.body;

  // M1 — verify current password in constant time against the rotating hash.
  if (!ADMIN_PASS_HASH || !checkPassword(current_password || '', ADMIN_PASS_HASH)) {
    return res.redirect('/admin/settings?msg=Current+password+is+incorrect&ok=0');
  }
  if (!new_password || new_password.length < 8) {
    return res.redirect('/admin/settings?msg=New+password+must+be+at+least+8+characters&ok=0');
  }
  if (new_password !== confirm_password) {
    return res.redirect('/admin/settings?msg=Passwords+do+not+match&ok=0');
  }

  ADMIN_PASS             = new_password;
  ADMIN_PASS_HASH        = hashPassword(new_password); // M1 — rotate the in-memory login hash
  process.env.ADMIN_PASS = new_password;

  // Persist the new hash to the DB so it survives restarts (DB is the source of truth
  // on boot). This is what makes a UI password change permanent without an env update.
  db.prepare("INSERT OR REPLACE INTO admin_settings (key, value) VALUES ('admin_pass_hash', ?)").run(ADMIN_PASS_HASH);

  try {
    updateEnvFile('ADMIN_PASS', new_password);
  } catch (e) {
    console.error('[settings] Failed to persist password to .env:', e.message);
  }

  logAudit('admin.password.changed', 'admin', ADMIN_USER, {}, req);
  res.redirect('/admin/settings?msg=Password+changed+successfully');
});

// ---------------------------------------------------------------------------
// Reconciliation  GET+POST /admin/advertisers/:slug/reconcile
// ---------------------------------------------------------------------------

// Shared reconciliation processor — used by the admin route and the advertiser
// portal (Backlog #11). Creates a run, matches each CSV row to a conversion,
// counts matched/approved/rejected/unmatched/discrepancy, flags overturned
// conversions as disputed (Backlog #1), and writes the run summary.
function processReconcileRows(adv, rows, filename, req) {
  const runId = db.prepare(
    'INSERT INTO reconciliation_runs (advertiser_slug, filename, total_rows) VALUES (?, ?, ?)'
  ).run(adv.slug, filename, rows.length).lastInsertRowid;

  let matched = 0, approved = 0, rejected = 0, unmatched = 0, discrepancy = 0;
  const insertUnmatched = db.prepare(
    'INSERT INTO reconciliation_unmatched (run_id, click_id, raw_status, reason, issue) VALUES (?, ?, ?, ?, ?)'
  );

  for (const row of rows) {
    const click_id  = (row.click_id || row.clickid || row.click || '').trim();
    const txnId     = (row.transaction_id || row.transactionid || row.txn_id || '').trim();
    const rawStatus = (row.status || '').trim().toLowerCase();
    const reason    = (row.reason || row.note || row.notes || '').trim();
    const payout    = row.payout !== undefined && row.payout !== '' ? parseFloat(row.payout) : null;
    const idLabel   = click_id || txnId;

    if (!click_id && !txnId) { unmatched++; insertUnmatched.run(runId, '', rawStatus, reason, 'Missing click_id and transaction_id'); continue; }
    if (!['approved', 'rejected'].includes(rawStatus)) { unmatched++; insertUnmatched.run(runId, idLabel, rawStatus, reason, `Invalid status: "${rawStatus}"`); continue; }

    let conv = null;
    if (click_id) conv = db.prepare('SELECT id, status FROM conversions WHERE click_id = ? AND advertiser_slug = ?').get(click_id, adv.slug);
    if (!conv && txnId) conv = db.prepare('SELECT id, status FROM conversions WHERE transaction_id = ? AND advertiser_slug = ?').get(txnId, adv.slug);
    if (!conv) { unmatched++; insertUnmatched.run(runId, idLabel, rawStatus, reason, 'No matching click_id or transaction_id for this advertiser'); continue; }

    matched++;
    if (rawStatus === 'approved') approved++; else rejected++;

    const isDiscrepancy = (conv.status === 'approved' || conv.status === 'rejected') && conv.status !== rawStatus;
    if (isDiscrepancy) discrepancy++;
    const disputeSql = isDiscrepancy ? ", dispute_state='disputed'" : '';

    if (payout !== null && !isNaN(payout)) {
      db.prepare(`UPDATE conversions SET status=?, reason=?, reconciliation_run_id=?, payout=?${disputeSql} WHERE id=?`).run(rawStatus, reason, runId, payout, conv.id);
    } else {
      db.prepare(`UPDATE conversions SET status=?, reason=?, reconciliation_run_id=?${disputeSql} WHERE id=?`).run(rawStatus, reason, runId, conv.id);
    }
  }

  db.prepare('UPDATE reconciliation_runs SET matched=?, approved=?, rejected=?, unmatched=?, discrepancy=? WHERE id=?')
    .run(matched, approved, rejected, unmatched, discrepancy, runId);
  logAudit('reconciliation.uploaded', 'advertiser', adv.slug,
    { advertiser: adv.name, filename, total_rows: rows.length, matched, approved, rejected, unmatched, discrepancy }, req);
  return { runId, matched, approved, rejected, unmatched, discrepancy };
}

app.get('/admin/advertisers/:slug/reconcile', requireAdmin, (req, res) => {
  const adv = db.prepare('SELECT * FROM advertisers WHERE slug = ?').get(req.params.slug);
  if (!adv) return res.redirect('/admin?msg=Advertiser+not+found&ok=0');

  const runs = db.prepare(
    'SELECT * FROM reconciliation_runs WHERE advertiser_slug = ? ORDER BY uploaded_at DESC LIMIT 30'
  ).all(adv.slug);

  let runResult = null;
  if (req.query.run) {
    const run = db.prepare('SELECT * FROM reconciliation_runs WHERE id = ? AND advertiser_slug = ?')
                  .get(req.query.run, adv.slug);
    if (run) {
      const unmatched = db.prepare('SELECT * FROM reconciliation_unmatched WHERE run_id = ?').all(run.id);
      const rejected  = db.prepare(
        "SELECT click_id, reason, payout FROM conversions WHERE reconciliation_run_id = ? AND status = 'rejected'"
      ).all(run.id);
      // Backlog #1 — disputed conversions (advertiser overturned our decision) for this run,
      // with their dispute/adjustment state for manual resolution.
      const disputed = db.prepare(
        "SELECT id, click_id, status, reason, payout, currency, dispute_state, adjustment, adjustment_note FROM conversions WHERE reconciliation_run_id = ? AND dispute_state != 'none' ORDER BY id"
      ).all(run.id);
      // Backlog #1 — AppsFlyer flag breakdown across this advertiser's conversions.
      const flags = db.prepare(`SELECT
          SUM(CASE WHEN reason='mmp_attributed' THEN 1 ELSE 0 END) AS attributed,
          SUM(CASE WHEN reason='mmp_rejected'   THEN 1 ELSE 0 END) AS rejectedFlag,
          SUM(CASE WHEN reason='mmp_restricted' THEN 1 ELSE 0 END) AS restricted
        FROM conversions WHERE advertiser_slug = ?`).get(adv.slug);
      runResult = { run, unmatched, rejected, disputed, flags };
    }
  }

  res.send(renderReconcilePage({ adv, runs, runResult, csrfToken: req.session.csrfToken }));
});

app.post('/admin/advertisers/:slug/reconcile', requireAdmin, (req, res, next) => {
  csvUpload(req, res, err => {
    if (err) return res.redirect(`/admin/advertisers/${req.params.slug}/reconcile?msg=${encodeURIComponent(err.message)}&ok=0`);

    // CSRF check now that multer has populated req.body from the multipart form
    const bodyToken    = (req.body._csrf || '').trim();
    const sessionToken = req.session.csrfToken || '';
    if (!bodyToken || !sessionToken || bodyToken !== sessionToken) {
      return res.status(403).send('Invalid CSRF token');
    }

    const adv = db.prepare('SELECT * FROM advertisers WHERE slug = ?').get(req.params.slug);
    if (!adv) return res.redirect('/admin?msg=Advertiser+not+found&ok=0');
    if (!req.file) return res.redirect(`/admin/advertisers/${adv.slug}/reconcile?msg=No+file+uploaded&ok=0`);

    const rows     = parseCSV(req.file.buffer);
    const { runId } = processReconcileRows(adv, rows, req.file.originalname, req);
    res.redirect(`/admin/advertisers/${adv.slug}/reconcile?run=${runId}`);
  });
});

// ---------------------------------------------------------------------------
// Per-advertiser analytics  GET /admin/advertisers/:slug/analytics
// ---------------------------------------------------------------------------

app.get('/admin/advertisers/:slug/analytics', requireAdmin, (req, res) => {
  const adv = db.prepare('SELECT * FROM advertisers WHERE slug = ?').get(req.params.slug);
  if (!adv) return res.redirect('/admin?msg=Advertiser+not+found&ok=0');

  // Last 30 days — clicks and conversions
  const dailyClicks = db.prepare(`
    SELECT date(created_at) as day, COUNT(*) as n
    FROM clicks WHERE advertiser_slug = ? AND created_at >= date('now','-29 days')
    GROUP BY day ORDER BY day
  `).all(adv.slug);

  const dailyConv = db.prepare(`
    SELECT date(received_at) as day, COUNT(*) as n
    FROM conversions WHERE advertiser_slug = ? AND received_at >= date('now','-29 days')
    GROUP BY day ORDER BY day
  `).all(adv.slug);

  const geoBreakdown = db.prepare(`
    SELECT country, COUNT(*) as n FROM clicks
    WHERE advertiser_slug = ? AND country IS NOT NULL AND country != 'XX'
    GROUP BY country ORDER BY n DESC LIMIT 20
  `).all(adv.slug);

  const deviceBreakdown = db.prepare(`
    SELECT device_type, COUNT(*) as n FROM clicks
    WHERE advertiser_slug = ? AND device_type IS NOT NULL GROUP BY device_type ORDER BY n DESC
  `).all(adv.slug);

  const osBreakdown = db.prepare(`
    SELECT os, COUNT(*) as n FROM clicks
    WHERE advertiser_slug = ? AND os IS NOT NULL GROUP BY os ORDER BY n DESC
  `).all(adv.slug);

  const browserBreakdown = db.prepare(`
    SELECT browser, COUNT(*) as n FROM clicks
    WHERE advertiser_slug = ? AND browser IS NOT NULL GROUP BY browser ORDER BY n DESC
  `).all(adv.slug);

  const totalClicksAdv = db.prepare('SELECT COUNT(*) as n FROM clicks WHERE advertiser_slug = ?').get(adv.slug).n;
  const totalConvAdv   = db.prepare('SELECT COUNT(*) as n FROM conversions WHERE advertiser_slug = ?').get(adv.slug).n;

  const convStatus = db.prepare(`
    SELECT
      SUM(CASE WHEN status='pending'  THEN 1 ELSE 0 END) as pending,
      SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END) as approved,
      SUM(CASE WHEN status='rejected' THEN 1 ELSE 0 END) as rejected
    FROM conversions WHERE advertiser_slug = ?
  `).get(adv.slug);

  // Backlog #17 — sub-affiliate breakdown (clicks from clicks.af_sub1, conversions + payout from conversions.af_sub1)
  const subAffClicks = db.prepare("SELECT af_sub1, COUNT(*) AS clicks FROM clicks WHERE advertiser_slug = ? AND af_sub1 IS NOT NULL GROUP BY af_sub1").all(adv.slug);
  const subAffConv   = db.prepare("SELECT af_sub1, COUNT(*) AS conversions, COALESCE(SUM(payout),0) AS payout FROM conversions WHERE advertiser_slug = ? AND af_sub1 IS NOT NULL GROUP BY af_sub1").all(adv.slug);
  const subAffMap = {};
  for (const r of subAffClicks) subAffMap[r.af_sub1] = { af_sub1: r.af_sub1, clicks: r.clicks, conversions: 0, payout: 0 };
  for (const r of subAffConv) { subAffMap[r.af_sub1] = subAffMap[r.af_sub1] || { af_sub1: r.af_sub1, clicks: 0 }; subAffMap[r.af_sub1].conversions = r.conversions; subAffMap[r.af_sub1].payout = r.payout; }
  const subAffBreakdown = Object.values(subAffMap).sort((a, b) => b.conversions - a.conversions || b.clicks - a.clicks);

  res.send(renderAnalyticsPage({ adv, dailyClicks, dailyConv, geoBreakdown,
    deviceBreakdown, osBreakdown, browserBreakdown, totalClicksAdv, totalConvAdv, convStatus, subAffBreakdown }));
});

// ---------------------------------------------------------------------------
// REST API  GET /api/v1/stats  (X-API-Key: kom_live_...)
// ---------------------------------------------------------------------------

app.get('/api/v1/stats', requireApiKey, (req, res) => {
  const pub       = req.publisher;
  const thisMonth = new Date().toISOString().slice(0, 7);

  const totals = db.prepare(`
    SELECT COUNT(*) as total_conversions,
           COALESCE(SUM(CASE WHEN status='approved' THEN payout ELSE 0 END),0) as approved_earnings,
           COALESCE(SUM(CASE WHEN status='pending'  THEN payout ELSE 0 END),0) as pending_earnings,
           SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END) as approved_count,
           SUM(CASE WHEN status='pending'  THEN 1 ELSE 0 END) as pending_count,
           SUM(CASE WHEN status='rejected' THEN 1 ELSE 0 END) as rejected_count
    FROM conversions WHERE publisher = ?
  `).get(pub.username);

  const monthlyEarnings = db.prepare(`
    SELECT COALESCE(SUM(CASE WHEN status='approved' THEN payout ELSE 0 END),0) as approved
    FROM conversions WHERE publisher = ? AND strftime('%Y-%m', received_at) = ?
  `).get(pub.username, thisMonth).approved;

  const totalClicks = db.prepare(
    'SELECT COUNT(*) as n FROM clicks WHERE publisher = ?'
  ).get(pub.username).n;

  const byAdvertiser = db.prepare(`
    SELECT a.name as advertiser, a.slug as advertiser_slug,
           COUNT(DISTINCT c.click_id) as clicks,
           COUNT(cv.id) as conversions,
           COALESCE(SUM(CASE WHEN cv.status='approved' THEN cv.payout ELSE 0 END),0) as approved_payout,
           COALESCE(SUM(CASE WHEN cv.status='pending'  THEN cv.payout ELSE 0 END),0) as pending_payout
    FROM advertisers a
    LEFT JOIN clicks      c  ON c.advertiser_slug = a.slug AND c.publisher = ?
    LEFT JOIN conversions cv ON cv.click_id = c.click_id
    WHERE a.slug != 'legacy' AND (c.id IS NOT NULL OR cv.id IS NOT NULL)
    GROUP BY a.slug
    ORDER BY approved_payout DESC
  `).all(pub.username);

  res.json({
    publisher: pub.username,
    status:    pub.status,
    stats: {
      clicks: totalClicks,
      conversions: {
        total:    totals.total_conversions,
        approved: totals.approved_count,
        pending:  totals.pending_count,
        rejected: totals.rejected_count,
      },
      earnings: {
        approved:             +totals.approved_earnings.toFixed(2),
        pending:              +totals.pending_earnings.toFixed(2),
        this_month_approved:  +monthlyEarnings.toFixed(2),
      },
    },
    by_advertiser: byAdvertiser.map(r => ({
      advertiser:      r.advertiser,
      advertiser_slug: r.advertiser_slug,
      clicks:          r.clicks,
      conversions:     r.conversions,
      approved_payout: +r.approved_payout.toFixed(2),
      pending_payout:  +r.pending_payout.toFixed(2),
    })),
  });
});

// ---------------------------------------------------------------------------
// Audit log viewer
// ---------------------------------------------------------------------------

app.get('/admin/audit-log', requireAdmin, (req, res) => {
  const { action, from, to } = req.query;
  const conds = [], params = [];
  if (action) { conds.push('action = ?');                                params.push(action); }
  if (from)   { conds.push('created_at >= ?');                           params.push(from); }
  if (to)     { conds.push("created_at <= datetime(?, 'start of day', '+1 day')"); params.push(to); }
  const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';

  const logs = db.prepare(
    `SELECT * FROM audit_log ${where} ORDER BY created_at DESC LIMIT 500`
  ).all(...params);

  const actions = db.prepare('SELECT DISTINCT action FROM audit_log ORDER BY action').all().map(r => r.action);

  res.send(renderAuditLog({ logs, actions, filters: { action: action||'', from: from||'', to: to||'' } }));
});

// ---------------------------------------------------------------------------
// CSV export  GET /admin/export.csv[?advertiser=SLUG&month=YYYY-MM]
// ---------------------------------------------------------------------------

app.get('/admin/export.csv', requireAdmin, (req, res) => {
  const { advertiser, month } = req.query;
  const conds = [], params = [];
  if (advertiser) { conds.push('advertiser_slug = ?'); params.push(advertiser); }
  if (month)      { conds.push("strftime('%Y-%m',received_at) = ?"); params.push(month); }
  const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';

  const rows = db.prepare(
    `SELECT received_at,advertiser_slug,click_id,transaction_id,publisher,event,payout,currency,status,reason,af_sub1,af_sub2 FROM conversions ${where} ORDER BY received_at`
  ).all(...params);

  const parts = [advertiser, month].filter(Boolean);
  const filename = parts.length ? `conversions-${parts.join('-')}.csv` : 'conversions-all.csv';
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

  const q = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
  res.send([
    'received_at,advertiser,click_id,transaction_id,publisher,event,payout,currency,status,reason,af_sub1,af_sub2',
    ...rows.map(r => [r.received_at, r.advertiser_slug, r.click_id, r.transaction_id, r.publisher, r.event, r.payout, r.currency, r.status, r.reason, r.af_sub1, r.af_sub2].map(q).join(',')),
  ].join('\r\n'));
});

// ---------------------------------------------------------------------------
// Backlog #14/#16 — fraud review + publisher traffic-quality scoring
// ---------------------------------------------------------------------------

// Backlog #16 — on-the-fly traffic-quality score from the last 90 days of conversions.
function publisherQualityScore(publisher) {
  const r = db.prepare(`SELECT
      COUNT(*) AS total,
      SUM(CASE WHEN status='rejected' THEN 1 ELSE 0 END) AS rejected,
      SUM(CASE WHEN fraud_flag IS NOT NULL THEN 1 ELSE 0 END) AS fraud,
      SUM(CASE WHEN fraud_flag LIKE '%ctit%' THEN 1 ELSE 0 END) AS ctit
    FROM conversions WHERE publisher = ? AND received_at >= date('now','-90 days')`).get(publisher);
  const total = r.total || 0;
  if (total === 0) return { publisher, total: 0, rejection_rate: 0, fraud_rate: 0, ctit_anomaly_rate: 0, score: 100, grade: 'A' };
  const rejection_rate = r.rejected / total, fraud_rate = r.fraud / total, ctit_anomaly_rate = r.ctit / total;
  let score = 100 - (rejection_rate * 40) - (fraud_rate * 40) - (ctit_anomaly_rate * 20);
  score = Math.max(0, Math.min(100, Math.round(score)));
  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
  return { publisher, total, rejection_rate, fraud_rate, ctit_anomaly_rate, score, grade };
}

app.get('/admin/publisher-quality', requireAdmin, (req, res) => {
  const pubs = db.prepare('SELECT username FROM publishers ORDER BY username').all();
  const rows = pubs.map(p => publisherQualityScore(p.username)).sort((a, b) => a.score - b.score);
  res.send(renderPublisherQuality({ rows }));
});

app.get('/admin/fraud', requireAdmin, (req, res) => {
  const rows = db.prepare(`SELECT click_id, advertiser_slug,
      MAX(publisher) AS publisher,
      COUNT(*) AS n,
      GROUP_CONCAT(DISTINCT event) AS events,
      MAX(fraud_flag) AS fraud_flag,
      MAX(fraud_source) AS fraud_source,
      MAX(received_at) AS last_at
    FROM conversions
    WHERE fraud_flag IS NOT NULL OR fraud_source IS NOT NULL
    GROUP BY click_id, advertiser_slug
    ORDER BY last_at DESC LIMIT 500`).all();
  res.send(renderFraudPage({ rows }));
});

// ---------------------------------------------------------------------------
// Backlog #9 — Cohort / Retention reporting. Cohorts are keyed by media source
// (publisher), network, or campaign; retention is the day-gap between the click
// (D0) and each conversion, bucketed D0 / D1-7 / D8-14 / D15-28 / D28+. LTV is the
// approved payout per cohort. cohort_type splits a click's first conversion
// (acquisition) from later ones (re-engagement). CSV export via ?format=csv.
// ---------------------------------------------------------------------------
function cohortRows({ by, cohortType, advFilter }) {
  const dimExpr = by === 'network'  ? "COALESCE(NULLIF(cl.network,''),'(none)')"
                : by === 'campaign' ? "COALESCE(NULLIF(cl.campaign,''),'(none)')"
                : 'cv.publisher';
  const where = ['cl.click_id IS NOT NULL'];
  const params = [];
  if (advFilter) { where.push('cv.advertiser_slug = ?'); params.push(advFilter); }
  const base = `
    SELECT ${dimExpr} AS dim,
      CAST(julianday(date(cv.received_at)) - julianday(date(cl.created_at)) AS INTEGER) AS d,
      cv.payout AS payout, cv.status AS status,
      ROW_NUMBER() OVER (PARTITION BY cv.click_id ORDER BY cv.received_at, cv.id) AS rn
    FROM conversions cv JOIN clicks cl ON cl.click_id = cv.click_id
    WHERE ${where.join(' AND ')}`;
  const typeFilter = cohortType === 'acquisition' ? 'WHERE rn = 1'
                   : cohortType === 'reengagement' ? 'WHERE rn > 1' : '';
  return db.prepare(`
    SELECT dim,
      COUNT(*) AS conversions,
      SUM(CASE WHEN status='approved' THEN payout ELSE 0 END) AS ltv,
      SUM(CASE WHEN d<=0 THEN 1 ELSE 0 END) AS d0,
      SUM(CASE WHEN d BETWEEN 1 AND 7   THEN 1 ELSE 0 END) AS d1_7,
      SUM(CASE WHEN d BETWEEN 8 AND 14  THEN 1 ELSE 0 END) AS d8_14,
      SUM(CASE WHEN d BETWEEN 15 AND 28 THEN 1 ELSE 0 END) AS d15_28,
      SUM(CASE WHEN d > 28 THEN 1 ELSE 0 END) AS d28p
    FROM ( ${base} ) ${typeFilter}
    GROUP BY dim ORDER BY conversions DESC`).all(...params);
}

app.get('/admin/reports/cohort', requireAdmin, (req, res) => {
  const by = ['media_source', 'network', 'campaign'].includes(req.query.by) ? req.query.by : 'media_source';
  const cohortType = ['acquisition', 'reengagement'].includes(req.query.type) ? req.query.type : 'all';
  const advFilter = (req.query.advertiser || '').trim();
  const rows = cohortRows({ by, cohortType, advFilter });
  if (req.query.format === 'csv') {
    const q = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="cohort-${by}-${cohortType}.csv"`);
    return res.send([
      'media_source,conversions,ltv,D0,D1-7,D8-14,D15-28,D28+',
      ...rows.map(r => [r.dim, r.conversions, $(r.ltv), r.d0, r.d1_7, r.d8_14, r.d15_28, r.d28p].map(q).join(',')),
    ].join('\r\n'));
  }
  const advertisers = db.prepare("SELECT slug, name FROM advertisers WHERE slug != 'legacy' ORDER BY name").all();
  res.send(renderCohortReport({ rows, by, cohortType, advFilter, advertisers }));
});

// ---------------------------------------------------------------------------
// Backlog #10 — Pivot / grouped report. Flexible breakdown over up to two of:
// media source (publisher), sub-source (subpub), geo (country), campaign, date,
// advertiser. Metrics: conversions, approved, approved payout, revenue. CSV export.
// ---------------------------------------------------------------------------
const PIVOT_DIMS = {
  publisher:  { label: 'Media Source',  expr: 'cv.publisher' },
  subpub:     { label: 'Sub-source',    expr: "COALESCE(NULLIF(cl.subpub,''),'(none)')" },
  country:    { label: 'Geo',           expr: "COALESCE(NULLIF(cl.country,''),'(none)')" },
  campaign:   { label: 'Campaign',      expr: "COALESCE(NULLIF(cl.campaign,''),'(none)')" },
  date:       { label: 'Date',          expr: 'date(cv.received_at)' },
  advertiser: { label: 'Advertiser',    expr: 'cv.advertiser_slug' },
};
app.get('/admin/reports/pivot', requireAdmin, (req, res) => {
  const dim1 = PIVOT_DIMS[req.query.dim1] ? req.query.dim1 : 'publisher';
  const dim2 = (req.query.dim2 && PIVOT_DIMS[req.query.dim2] && req.query.dim2 !== dim1) ? req.query.dim2 : '';
  const sel = dim2 ? `${PIVOT_DIMS[dim1].expr} AS k1, ${PIVOT_DIMS[dim2].expr} AS k2` : `${PIVOT_DIMS[dim1].expr} AS k1`;
  const grp = dim2 ? 'k1, k2' : 'k1';
  const rows = db.prepare(`
    SELECT ${sel},
      COUNT(*) AS conversions,
      SUM(CASE WHEN cv.status='approved' THEN 1 ELSE 0 END) AS approved,
      SUM(CASE WHEN cv.status='approved' THEN cv.payout ELSE 0 END) AS payout,
      SUM(COALESCE(cv.revenue,0)) AS revenue
    FROM conversions cv LEFT JOIN clicks cl ON cl.click_id = cv.click_id
    GROUP BY ${grp} ORDER BY conversions DESC LIMIT 1000`).all();
  if (req.query.format === 'csv') {
    const q = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="pivot-${dim1}${dim2?'-'+dim2:''}.csv"`);
    const head = [PIVOT_DIMS[dim1].label, ...(dim2 ? [PIVOT_DIMS[dim2].label] : []), 'conversions', 'approved', 'payout', 'revenue'];
    return res.send([
      head.join(','),
      ...rows.map(r => [r.k1, ...(dim2 ? [r.k2] : []), r.conversions, r.approved, $(r.payout), $(r.revenue)].map(q).join(',')),
    ].join('\r\n'));
  }
  res.send(renderPivotReport({ rows, dim1, dim2 }));
});

// Backlog #11 — Advertiser Portal (separate from Admin). Advertisers log in with
// username = slug and an admin-set portal password; they get read-only access to
// their own conversions, analytics, tracking links, and can upload reconciliation
// CSVs — all scoped to their slug. No admin access.
// ===========================================================================
function requireAdvertiser(req, res, next) {
  const slug = req.session?.advSlug;
  if (!slug) return res.redirect('/advertiser/login');
  const now = Date.now();
  if (req.session.advLastActivity && now - req.session.advLastActivity > PUBLISHER_IDLE_MS) {
    return req.session.destroy(() => res.redirect('/advertiser/login?err=' + encodeURIComponent('Session expired')));
  }
  const adv = db.prepare('SELECT * FROM advertisers WHERE slug = ?').get(slug);
  if (!adv || !adv.portal_password_hash) {
    return req.session.destroy(() => res.redirect('/advertiser/login?err=Portal+access+disabled'));
  }
  req.session.advLastActivity = now;
  if (!req.session.csrfToken) req.session.csrfToken = generateCsrfToken();
  req.advertiser = adv;
  next();
}

app.get('/advertiser/login', (req, res) => {
  if (req.session?.advSlug) return res.redirect('/advertiser/dashboard');
  res.send(renderAdvLogin({ error: req.query.err || null }));
});

app.post('/advertiser/login', (req, res) => {
  if (checkLoginLockout(req, res, publisherLoginAttempts)) return;
  const slug = (req.body.username || '').trim().toLowerCase();
  const adv = slug ? db.prepare('SELECT * FROM advertisers WHERE slug = ?').get(slug) : null;
  if (!adv || !adv.portal_password_hash || !checkPassword(req.body.password || '', adv.portal_password_hash)) {
    recordLoginFailure(req.ip, publisherLoginAttempts);
    return res.send(renderAdvLogin({ error: 'Invalid advertiser slug or password' }));
  }
  req.session.regenerate(err => {
    if (err) return res.status(500).send('Session error');
    req.session.advSlug = adv.slug;
    req.session.save(saveErr => {
      if (saveErr) return res.status(500).send('Session error');
      recordLoginSuccess(req.ip, publisherLoginAttempts);
      logAudit('advertiser.portal_login', 'advertiser', adv.slug, {}, req);
      res.redirect('/advertiser/dashboard');
    });
  });
});

app.post('/advertiser/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/advertiser/login'));
});

app.get('/advertiser/dashboard', requireAdvertiser, (req, res) => {
  const adv = req.advertiser;
  const clicks = db.prepare('SELECT COUNT(*) n FROM clicks WHERE advertiser_slug = ?').get(adv.slug).n;
  const statusRows = db.prepare(`SELECT
      COUNT(*) total,
      SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END) approved,
      SUM(CASE WHEN status='pending'  THEN 1 ELSE 0 END) pending,
      SUM(CASE WHEN status='rejected' THEN 1 ELSE 0 END) rejected
    FROM conversions WHERE advertiser_slug = ?`).get(adv.slug);
  const payoutRows = db.prepare(`SELECT currency, COALESCE(SUM(CASE WHEN status='approved' THEN payout ELSE 0 END),0) approved
    FROM conversions WHERE advertiser_slug = ? GROUP BY currency`).all(adv.slug);
  const recent = db.prepare('SELECT * FROM conversions WHERE advertiser_slug = ? ORDER BY received_at DESC LIMIT 15').all(adv.slug);
  res.send(renderAdvDashboard({ adv, clicks, statusRows, payoutRows, recent }));
});

app.get('/advertiser/conversions', requireAdvertiser, (req, res) => {
  const adv = req.advertiser;
  const conversions = db.prepare('SELECT * FROM conversions WHERE advertiser_slug = ? ORDER BY received_at DESC LIMIT 500').all(adv.slug);
  res.send(renderAdvConversions({ adv, conversions }));
});

app.get('/advertiser/analytics', requireAdvertiser, (req, res) => {
  const adv = req.advertiser;
  const dailyClicks = db.prepare("SELECT date(created_at) day, COUNT(*) n FROM clicks WHERE advertiser_slug=? AND created_at>=date('now','-29 days') GROUP BY day ORDER BY day").all(adv.slug);
  const dailyConv   = db.prepare("SELECT date(received_at) day, COUNT(*) n FROM conversions WHERE advertiser_slug=? AND received_at>=date('now','-29 days') GROUP BY day ORDER BY day").all(adv.slug);
  const geo = db.prepare("SELECT country, COUNT(*) n FROM clicks WHERE advertiser_slug=? AND country IS NOT NULL AND country!='XX' GROUP BY country ORDER BY n DESC LIMIT 10").all(adv.slug);
  res.send(renderAdvAnalytics({ adv, dailyClicks, dailyConv, geo }));
});

app.get('/advertiser/tracking-links', requireAdvertiser, (req, res) => {
  const adv = req.advertiser;
  const pubs = db.prepare(`SELECT p.username FROM publisher_advertisers pa
    JOIN publishers p ON p.id = pa.publisher_id WHERE pa.advertiser_id = ? ORDER BY p.username`).all(adv.id);
  res.send(renderAdvTrackingLinks({ adv, pubs }));
});

app.get('/advertiser/reconcile', requireAdvertiser, (req, res) => {
  const adv = req.advertiser;
  const runs = db.prepare('SELECT * FROM reconciliation_runs WHERE advertiser_slug = ? ORDER BY uploaded_at DESC LIMIT 20').all(adv.slug);
  const flash = req.query.msg && req.query.ok !== '0' ? req.query.msg : null;
  const error = req.query.msg && req.query.ok === '0' ? req.query.msg : null;
  res.send(renderAdvReconcile({ adv, runs, csrfToken: req.session.csrfToken, flash, error }));
});

app.post('/advertiser/reconcile', requireAdvertiser, (req, res) => {
  csvUpload(req, res, err => {
    if (err) return res.redirect(`/advertiser/reconcile?msg=${encodeURIComponent(err.message)}&ok=0`);
    const bodyToken = (req.body._csrf || '').trim();
    if (!bodyToken || bodyToken !== (req.session.csrfToken || '')) return res.status(403).send('Invalid CSRF token');
    if (!req.file) return res.redirect('/advertiser/reconcile?msg=No+file+uploaded&ok=0');
    const rows = parseCSV(req.file.buffer);
    const r = processReconcileRows(req.advertiser, rows, req.file.originalname, req);
    res.redirect(`/advertiser/reconcile?msg=${encodeURIComponent(`Processed ${rows.length} rows — ${r.matched} matched, ${r.approved} approved, ${r.rejected} rejected, ${r.unmatched} unmatched`)}`);
  });
});

// HTML templates — shared helpers
// ---------------------------------------------------------------------------

const H   = s => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
// Server-side CSRF hidden field — rendered directly into the form HTML so it
// works even when client JS fails. The JS fallback in the admin shell only
// injects _csrf into forms that don't already have it, so this never doubles up.
const csrfField = token => `<input type="hidden" name="_csrf" value="${H(token)}">`;
const $   = n  => Number(n).toFixed(2);
const N   = n  => Number(n).toLocaleString();
const cvr = (cl, co) => cl > 0 ? ((co / cl) * 100).toFixed(1) + '%' : '—';

const VND_RATE = 25700;
const vnd  = usd => Math.round(Number(usd) * VND_RATE).toLocaleString('en-US') + ' ₫';
const usdVnd = (usd, style = '') => `$${$(usd)}<span style="font-size:11px;color:#6e6e73;margin-left:4px">(${vnd(usd)})</span>`;
// QA2 — format a native amount in its own currency (never converts/mixes currencies).
const fmtCur = (amt, currency = 'USD') => currency === 'VND'
  ? `${Math.round(Number(amt || 0)).toLocaleString('en-US')} ₫`
  : `$${$(amt || 0)}`;
// Render an array of {currency,total} rows as separate labelled amounts (e.g. "$10.00 · 1,375,000 ₫").
const fmtByCurrency = (rows) => {
  const nz = (rows || []).filter(r => Number(r.total) !== 0);
  if (nz.length === 0) return fmtCur(0, 'USD');
  return nz.map(r => fmtCur(r.total, r.currency)).join(' <span style="color:#9ca3af">·</span> ');
};

// Mobile off-canvas nav (QA fix): below 640px the fixed sidebar would otherwise
// fill the viewport and push content off-screen. The hamburger toggles a
// slide-in sidebar with a backdrop. Shared by the admin panel and publisher
// portal — pass the layout's own sidebar/topbar selectors.
function navResponsiveCss(sidebarSel, topbarSel) {
  return `
  .nav-burger{display:none;background:transparent;border:none;color:#c9d1d9;font-size:20px;line-height:1;cursor:pointer;padding:3px 8px;margin-right:2px;border-radius:5px;font-family:inherit}
  .nav-burger:hover{background:rgba(255,255,255,.08);color:#fff}
  .nav-backdrop{display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:35}
  @media (max-width:640px){
    ${topbarSel}{z-index:50}
    .nav-burger{display:inline-flex;align-items:center}
    ${sidebarSel}{position:fixed;top:50px;left:0;width:240px;max-width:82vw;height:calc(100vh - 50px);transform:translateX(-100%);transition:transform .25s ease;z-index:40;box-shadow:2px 0 14px rgba(0,0,0,.35)}
    ${sidebarSel}.open{transform:translateX(0)}
    .nav-backdrop.open{display:block}
    body.nav-open{overflow:hidden}
  }`;
}

// Generic toggle wiring keyed off data-attributes so it serves both layouts.
const NAV_TOGGLE_JS = `
(function(){
  var burger=document.querySelector('[data-nav-toggle]');
  var sidebar=document.querySelector('[data-nav-sidebar]');
  var backdrop=document.querySelector('[data-nav-backdrop]');
  if(!burger||!sidebar) return;
  function setOpen(open){
    sidebar.classList.toggle('open',open);
    if(backdrop) backdrop.classList.toggle('open',open);
    document.body.classList.toggle('nav-open',open);
    burger.setAttribute('aria-expanded',open?'true':'false');
  }
  burger.addEventListener('click',function(){setOpen(!sidebar.classList.contains('open'));});
  if(backdrop) backdrop.addEventListener('click',function(){setOpen(false);});
  sidebar.addEventListener('click',function(e){ if(e.target.closest('a')) setOpen(false); });
  window.addEventListener('resize',function(){ if(window.innerWidth>640) setOpen(false); });
  document.addEventListener('keydown',function(e){ if(e.key==='Escape') setOpen(false); });
})();
`;

const ADMIN_CSS = `
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  html,body{height:100%}
  body{font-family:'Inter',system-ui,-apple-system,sans-serif;background:#f5f7fa;color:#111827;font-size:14px}
  a{color:inherit;text-decoration:none}

  /* ── Shell ── */
  .adm-shell{display:flex;flex-direction:column;min-height:100vh}

  /* ── Sidebar ── */
  .adm-sidebar{width:216px;flex-shrink:0;background:#0a3d2d;display:flex;flex-direction:column;position:sticky;top:0;height:100vh;overflow-y:auto;z-index:20}
  .adm-sb-logo{padding:14px 14px 12px;border-bottom:1px solid rgba(255,255,255,.09);flex-shrink:0}
  .adm-sb-logo a{display:inline-flex;align-items:center;background:#fff;border-radius:7px;padding:4px 8px}
  /* ── Topbar ── */
  .adm-topbar{background:#0d1117;height:50px;display:flex;align-items:center;justify-content:space-between;padding:0 16px;flex-shrink:0;border-bottom:1px solid rgba(0,229,195,.18);position:sticky;top:0;z-index:30}
  .adm-brand{display:flex;align-items:center;gap:10px}
  .adm-logo-mark{width:28px;height:28px;background:rgba(0,229,195,.12);border:1px solid rgba(0,229,195,.4);border-radius:6px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
  .adm-brand-name{font-size:13px;font-weight:600;letter-spacing:.4px;color:#fff}
  .adm-brand-sub{font-size:9px;font-weight:500;letter-spacing:1px;color:rgba(255,255,255,.3);text-transform:uppercase;margin-top:1px}
  .adm-topbar-r{display:flex;align-items:center;gap:8px}
  .adm-badge{background:rgba(0,229,195,.15);color:#00e5c3;font-size:10px;font-weight:600;padding:2px 8px;border-radius:4px;letter-spacing:.4px}
  .adm-topbar-user{font-size:12px;color:#8b949e}
  .adm-sep{width:1px;height:18px;background:#30363d;margin:0 2px}
  .tbtn{background:transparent;border:1px solid #30363d;color:#8b949e;font-size:12px;padding:5px 11px;border-radius:5px;cursor:pointer;font-family:inherit;white-space:nowrap;display:inline-block}
  .tbtn:hover{border-color:#6e7681;color:#c9d1d9;text-decoration:none}
  .tbtn-cyan{background:#00e5c3;color:#0d1117;border-color:#00e5c3;font-weight:600}
  .tbtn-cyan:hover{background:#00c9aa;border-color:#00c9aa}
  .tbtn-logout{background:transparent;border:none;color:#8b949e;font-size:12px;padding:5px 11px;cursor:pointer;font-family:inherit;border-radius:5px}
  .tbtn-logout:hover{background:rgba(248,81,73,.15);color:#f85149}

  /* ── Body ── */
  .adm-body{display:flex;flex:1}

  /* ── Sidebar ── */
  .adm-sidebar{width:172px;background:#0d1117;border-right:1px solid rgba(0,229,195,.18);display:flex;flex-direction:column;flex-shrink:0;position:sticky;top:50px;height:calc(100vh - 50px);overflow-y:auto}
  .adm-sb-group{font-size:9px;font-weight:600;letter-spacing:.8px;text-transform:uppercase;color:rgba(255,255,255,.25);padding:16px 14px 5px}
  .adm-nav-a{display:flex;align-items:center;gap:8px;padding:7px 14px;color:#8b949e;font-size:13px;border-left:2px solid transparent;transition:background .1s}
  .adm-nav-a:hover{background:rgba(255,255,255,.05);color:#c9d1d9}
  .adm-nav-a.active{background:rgba(0,229,195,.1);color:#00e5c3;border-left-color:#00e5c3;font-weight:500}
  .adm-nav-a svg{opacity:.6;flex-shrink:0;width:14px;height:14px}
  .adm-nav-a.active svg{opacity:1}
  .adm-sb-foot{margin-top:auto;padding:12px 14px;border-top:1px solid rgba(255,255,255,.07)}

  /* ── Content area ── */
  .adm-content{flex:1;min-width:0;display:flex;flex-direction:column}
  .adm-header{background:#fff;border-bottom:1px solid #e2e6ea;padding:0 20px;min-height:44px;display:flex;align-items:center;justify-content:flex-end;gap:8px;flex-shrink:0}
  .hbtn{background:#00e5c3;color:#0d1117;padding:6px 13px;border-radius:5px;font-size:12px;font-weight:600;white-space:nowrap;border:none;cursor:pointer;display:inline-block;font-family:inherit}
  .hbtn:hover{background:#00c9aa}
  .hbtn.ghost{background:#f9fafb;color:#374151;border:1px solid #e2e6ea}
  .hbtn.ghost:hover{background:#f3f4f6}
  main{padding:18px 20px;flex:1}
  .flash{padding:10px 14px;border-radius:6px;margin-bottom:14px;font-size:13px;font-weight:500}
  .flash.success{background:#ecfdf5;color:#065f46;border:1px solid #6ee7b7}
  .flash.error{background:#fef2f2;color:#991b1b;border:1px solid #fca5a5}
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(148px,1fr));gap:8px;margin-bottom:16px}
  .card{background:#fff;border:1px solid #e2e6ea;border-radius:8px;padding:14px 16px}
  .card .lbl{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;color:#9ca3af;margin-bottom:6px}
  .card .val{font-size:22px;font-weight:600;color:#111827;line-height:1.1}
  .card .val.green{color:#0a7c5c}
  .card .val.amber{color:#92651a}
  section{background:#fff;border:1px solid #e2e6ea;border-radius:8px;margin-bottom:10px;overflow:hidden}
  .sh{padding:10px 16px;border-bottom:1px solid #f3f4f6;display:flex;align-items:center;justify-content:space-between;gap:8px}
  .sh h2{font-size:13px;font-weight:600;color:#111827}
  .sh .meta{font-size:11px;color:#9ca3af}
  .sh-r{display:flex;gap:6px;align-items:center}
  table{width:100%;border-collapse:collapse}
  th{background:#f9fafb;padding:8px 13px;text-align:left;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.4px;color:#6b7280;border-bottom:1px solid #f3f4f6;white-space:nowrap}
  td{padding:9px 13px;border-bottom:1px solid #f3f4f6;vertical-align:middle;font-size:13px;color:#111827}
  tr:last-child td{border-bottom:none}
  tr:hover td{background:#fafbfc}
  code{background:#f3f4f6;padding:2px 5px;border-radius:4px;font-size:11px;font-family:monospace}
  code.xs{font-size:10px;word-break:break-all}
  .badge{display:inline-flex;align-items:center;padding:2px 7px;border-radius:20px;font-size:11px;font-weight:500}
  .badge.active{background:#ecfdf5;color:#0a7c5c}
  .badge.paused{background:#fffbeb;color:#92651a}
  .badge.ev{background:#eff6ff;color:#1d4ed8}
  .badge.approved{background:#ecfdf5;color:#0a7c5c}
  .badge.pending{background:#fffbeb;color:#92651a}
  .badge.rejected{background:#fef2f2;color:#991b1b}
  .badge.duplicate{background:#f3e8ff;color:#6b21a8}
  .act{display:flex;gap:4px;flex-wrap:wrap}
  .btn{display:inline-flex;align-items:center;padding:4px 10px;border-radius:5px;font-size:11px;font-weight:500;cursor:pointer;border:1px solid transparent;white-space:nowrap;font-family:inherit}
  .btn-primary{background:#00e5c3;color:#0d1117;border-color:#00e5c3}
  .btn-primary:hover{background:#00c9aa}
  .btn-ghost{background:#f9fafb;color:#374151;border-color:#e2e6ea}
  .btn-ghost:hover{background:#f3f4f6}
  .btn-warn{background:#fffbeb;color:#92651a;border-color:#f5d87a}
  .btn-warn:hover{background:#fef9c3}
  .btn-danger{background:#fef2f2;color:#991b1b;border-color:#fca5a5}
  .btn-danger:hover{background:#fee2e2}
  .btn-lg{padding:7px 16px;font-size:13px;border-radius:6px}
  .empty{padding:32px;text-align:center;color:#9ca3af;font-size:13px}
  .fw{max-width:520px;margin:22px auto;padding:0 20px}
  .fw h2{font-size:17px;font-weight:600;margin-bottom:18px;color:#111827}
  .fg{margin-bottom:13px}
  .fg label{display:block;font-size:11px;font-weight:600;color:#6b7280;margin-bottom:4px;text-transform:uppercase;letter-spacing:.4px}
  .fg input,.fg select{width:100%;padding:7px 10px;border:1px solid #e2e6ea;border-radius:6px;font-size:13px;outline:none;background:#fff;font-family:inherit;color:#111827}
  .fg input:focus,.fg select:focus{border-color:#00e5c3;box-shadow:0 0 0 3px rgba(0,229,195,.12)}
  .fg small{display:block;margin-top:3px;color:#9ca3af;font-size:11px}
  .fg-row{display:grid;grid-template-columns:1fr 1fr;gap:10px}
  .form-err{background:#fef2f2;color:#991b1b;padding:8px 12px;border-radius:6px;font-size:12px;margin-bottom:12px;border:1px solid #fca5a5}
  .form-act{display:flex;gap:8px;margin-top:18px}
  .ubox{background:#f9fafb;border:1px solid #e2e6ea;border-radius:5px;padding:6px 38px 6px 10px;font-size:11px;word-break:break-all;color:#374151;font-family:monospace;cursor:pointer;position:relative}
  .ubox:hover{background:#f3f4f6}
  .ubox::after{content:'Copy';position:absolute;top:5px;right:8px;font-size:10px;color:#9ca3af;font-family:'Inter',sans-serif}
  ${navResponsiveCss('.adm-sidebar', '.adm-topbar')}
`;

const PUB_CSS = `
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
  html,body{height:100%}
  body{font-family:'Inter',system-ui,-apple-system,sans-serif;background:#f5f7fa;color:#111827;font-size:14px}
  a{color:inherit;text-decoration:none}
  .pub-shell{display:flex;flex-direction:column;min-height:100vh}
  .pub-topbar{background:#0d1117;height:50px;display:flex;align-items:center;justify-content:space-between;padding:0 16px;flex-shrink:0;border-bottom:1px solid rgba(0,229,195,.18);position:sticky;top:0;z-index:30}
  .pub-brand{display:flex;align-items:center;gap:10px}
  .pub-logo-mark{width:28px;height:28px;background:rgba(0,229,195,.12);border:1px solid rgba(0,229,195,.4);border-radius:6px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
  .pub-brand-name{font-size:13px;font-weight:600;letter-spacing:.4px;color:#fff}
  .pub-brand-sub{font-size:9px;font-weight:500;letter-spacing:1px;color:rgba(255,255,255,.3);text-transform:uppercase;margin-top:1px}
  .pub-topbar-r{display:flex;align-items:center;gap:10px}
  .pub-topbar-user{font-size:12px;color:#484f58}
  .pub-topbar-user strong{color:#00e5c3}
  .pub-logout{background:transparent;border:1px solid #30363d;color:#8b949e;font-size:12px;padding:5px 11px;border-radius:5px;cursor:pointer;font-family:inherit}
  .pub-logout:hover{background:rgba(248,81,73,.15);color:#f85149;border-color:#f85149}
  .pub-body{display:flex;flex:1}
  .pub-sidebar{width:172px;background:#0d1117;border-right:1px solid rgba(0,229,195,.18);display:flex;flex-direction:column;flex-shrink:0;position:sticky;top:50px;height:calc(100vh - 50px);overflow-y:auto}
  .pub-sb-group{font-size:9px;font-weight:600;letter-spacing:.8px;text-transform:uppercase;color:rgba(255,255,255,.25);padding:16px 14px 5px}
  .pub-nav-a{display:flex;align-items:center;gap:8px;padding:7px 14px;color:#8b949e;font-size:13px;border-left:2px solid transparent;transition:background .1s}
  .pub-nav-a:hover{background:rgba(255,255,255,.05);color:#c9d1d9}
  .pub-nav-a.active{background:rgba(0,229,195,.15);color:#ffffff;border-left-color:#00e5c3;font-weight:500}
  .pub-nav-a svg{opacity:.6;flex-shrink:0;width:14px;height:14px}
  .pub-nav-a.active svg{opacity:1}
  .pub-sb-foot{margin-top:auto;padding:12px 14px;border-top:1px solid rgba(255,255,255,.07)}
  .pub-avatar{width:28px;height:28px;background:rgba(0,229,195,.15);border:1px solid rgba(0,229,195,.3);border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:600;color:#00e5c3;flex-shrink:0}
  .pub-content{flex:1;min-width:0;display:flex;flex-direction:column}
  main{padding:18px 20px;flex:1}
  .flash{padding:10px 14px;border-radius:6px;margin-bottom:14px;font-size:13px;font-weight:500}
  .flash.success{background:#ecfdf5;color:#065f46;border:1px solid #6ee7b7}
  .flash.error{background:#fef2f2;color:#991b1b;border:1px solid #fca5a5}
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(148px,1fr));gap:8px;margin-bottom:16px}
  .card{background:#fff;border:1px solid #e2e6ea;border-radius:8px;padding:14px 16px}
  .card .lbl{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;color:#9ca3af;margin-bottom:6px}
  .card .val{font-size:22px;font-weight:600;color:#111827;line-height:1.1}
  .card .val.blue,.card .val.green{color:#0a7c5c}
  .card .val.amber{color:#92651a}
  .card.hero{background:linear-gradient(135deg,#f0fdf4 0%,#ecfdf5 100%);border:2px solid #6ee7b7;box-shadow:0 4px 12px rgba(15,110,86,.1);padding:18px 20px}
  .card.hero .lbl{color:#0a7c5c;font-weight:600}
  .card.hero .val{color:#0a7c5c;font-size:28px}
  section{background:#fff;border:1px solid #e2e6ea;border-radius:8px;margin-bottom:10px;overflow:hidden}
  .sh{padding:10px 16px;border-bottom:1px solid #f3f4f6;display:flex;align-items:center;justify-content:space-between;gap:8px}
  .sh h2{font-size:13px;font-weight:600;color:#111827}
  .sh .meta{font-size:11px;color:#9ca3af}
  table{width:100%;border-collapse:collapse}
  /* F17 — mobile: let wide tables scroll horizontally instead of overflowing */
  @media (max-width:640px){ .pub-content table, .pub-content .login-card table { display:block; max-width:100%; overflow-x:auto; white-space:nowrap } }
  th{background:#f9fafb;padding:8px 13px;text-align:left;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.4px;color:#6b7280;border-bottom:1px solid #f3f4f6;white-space:nowrap}
  td{padding:9px 13px;border-bottom:1px solid #f3f4f6;vertical-align:middle;font-size:13px;color:#111827}
  tr:last-child td{border-bottom:none}
  tr:hover td{background:#fafbfc}
  code{background:#f3f4f6;padding:2px 5px;border-radius:4px;font-size:11px;font-family:monospace}
  code.xs{font-size:10px;word-break:break-all}
  .badge{display:inline-flex;align-items:center;padding:2px 7px;border-radius:20px;font-size:11px;font-weight:500;background:#eff6ff;color:#1d4ed8}
  .badge.approved{background:#ecfdf5;color:#0a7c5c}
  .badge.pending{background:#fffbeb;color:#92651a}
  .badge.rejected{background:#fef2f2;color:#991b1b}
  .badge.duplicate{background:#f3e8ff;color:#6b21a8}
  .btn{display:inline-flex;align-items:center;padding:4px 10px;border-radius:5px;font-size:11px;font-weight:500;cursor:pointer;border:1px solid transparent;white-space:nowrap;font-family:inherit}
  .btn-ghost{background:#f9fafb;color:#374151;border-color:#e2e6ea}
  .btn-ghost:hover{background:#f3f4f6}
  .btn-primary{background:#00e5c3;color:#0d1117;border-color:#00e5c3}
  .btn-primary:hover{background:#00c9aa}
  .empty{padding:32px;text-align:center;color:#9ca3af;font-size:13px}
  /* Button loading / disabled states */
  .btn[disabled]{opacity:.6;cursor:not-allowed;pointer-events:none}
  .btn.loading::after{content:' ⏳';display:inline-block;animation:spin 1s linear infinite}
  @keyframes spin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}
  /* Marketplace campaign cards */
  .campaign-card{background:#fff;border:1px solid #e2e6ea;border-radius:8px;padding:16px;transition:all .2s}
  .campaign-card:hover{border-color:#00e5c3;box-shadow:0 4px 12px rgba(0,229,195,.15);transform:translateY(-2px)}
  .campaign-payout{font-size:18px;font-weight:700;color:#0a7c5c}
  .campaign-badge{background:rgba(0,229,195,.12);color:#0a7c5c;font-size:10px;font-weight:600;padding:3px 7px;border-radius:4px}
  .campaign-desc{font-size:12px;color:#6b7280;margin:12px 0;padding:12px 0;border-top:1px solid #f3f4f6;border-bottom:1px solid #f3f4f6}
  .campaign-apply{width:100%;background:#00e5c3;color:#0d1117;padding:10px;border:none;border-radius:6px;font-weight:600;cursor:pointer;font-family:inherit}
  .campaign-apply[disabled]{opacity:.6;cursor:default;background:#e2e6ea;color:#6b7280}
  /* Toast notifications */
  @keyframes slideIn{from{opacity:0;transform:translateY(-20px)}to{opacity:1;transform:translateY(0)}}
  .toast{position:fixed;top:20px;right:20px;background:#fff;border-radius:8px;padding:16px 20px;box-shadow:0 8px 24px rgba(0,0,0,.12);display:flex;align-items:center;gap:12px;z-index:50;animation:slideIn .3s ease-out;border-left:4px solid #10b981}
  .toast.success{border-left-color:#10b981}
  .toast.error{border-left-color:#ef4444}
  .toast-icon{font-size:20px;flex-shrink:0}
  .toast.success .toast-icon{color:#10b981}
  .toast.error .toast-icon{color:#ef4444}
  .toast-title{font-size:13px;font-weight:600;color:#111827}
  .toast-message{font-size:12px;color:#6b7280;margin-top:2px}
  .ubox{background:#f9fafb;border:1px solid #e2e6ea;border-radius:5px;padding:6px 38px 6px 10px;font-size:11px;word-break:break-all;color:#374151;font-family:monospace;cursor:pointer;position:relative;max-width:420px}
  .ubox:hover{background:#f3f4f6}
  .ubox::after{content:'Copy';position:absolute;top:5px;right:8px;font-size:10px;color:#9ca3af;font-family:'Inter',sans-serif}
  .fg{margin-bottom:13px}
  .fg label{display:block;font-size:11px;font-weight:600;color:#6b7280;margin-bottom:4px;text-transform:uppercase;letter-spacing:.4px}
  .fg input,.fg select{width:100%;padding:7px 10px;border:1px solid #e2e6ea;border-radius:6px;font-size:13px;outline:none;background:#fff;font-family:inherit;color:#111827}
  .fg input:focus{border-color:#00e5c3;box-shadow:0 0 0 3px rgba(0,229,195,.12)}
  /* Login pages */
  .login-page{background:#0d1117;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
  .login-card{background:#fff;border-radius:12px;padding:36px;width:100%;max-width:380px;box-shadow:0 8px 32px rgba(0,0,0,.4)}
  .login-logo-mark{width:36px;height:36px;background:rgba(0,229,195,.12);border:1px solid rgba(0,229,195,.4);border-radius:8px;display:flex;align-items:center;justify-content:center;margin:0 auto 12px}
  .login-title{font-size:17px;font-weight:600;color:#111827;text-align:center;margin-bottom:4px}
  .login-sub{font-size:13px;color:#6b7280;text-align:center;margin-bottom:22px}
  .login-err{background:#fef2f2;color:#991b1b;padding:9px 12px;border-radius:6px;font-size:12px;margin-bottom:14px;border:1px solid #fca5a5}
  .login-ok{background:#ecfdf5;color:#065f46;padding:9px 12px;border-radius:6px;font-size:12px;margin-bottom:14px;border:1px solid #6ee7b7}
  .login-fg{margin-bottom:12px}
  .login-fg label{display:block;font-size:11px;font-weight:600;color:#6b7280;margin-bottom:4px;text-transform:uppercase;letter-spacing:.4px}
  .login-fg input{width:100%;padding:9px 11px;border:1px solid #e2e6ea;border-radius:6px;font-size:14px;outline:none;font-family:inherit;color:#111827}
  .login-fg input:focus{border-color:#00e5c3;box-shadow:0 0 0 3px rgba(0,229,195,.12)}
  .login-btn{width:100%;padding:10px;background:#00e5c3;color:#0d1117;border:none;border-radius:6px;font-size:14px;font-weight:600;cursor:pointer;margin-top:8px;font-family:inherit}
  .login-btn:hover{background:#00c9aa}
  .login-link{text-align:center;font-size:12px;color:#6b7280;margin-top:16px}
  .login-link a{color:#00e5c3;font-weight:500}
  /* Register wide form */
  .register-wrap{background:#0d1117;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
  .register-card{background:#fff;border-radius:12px;padding:36px;width:100%;max-width:540px;box-shadow:0 8px 32px rgba(0,0,0,.4)}
  .register-grid-2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
  ${navResponsiveCss('.pub-sidebar', '.pub-topbar')}
`;

const CP_JS = `
function cp(el,url){
  navigator.clipboard.writeText(url)
    .then(()=>{const o=el.style.background;el.style.background='#d4edda';setTimeout(()=>el.style.background=o,700);})
    .catch(()=>prompt('Copy:',url));
}`;

// Publisher-portal client JS: toast notifications + CTA button loading state.
const PORTAL_JS = `
function showToast(message, type, duration){
  type = type || 'success'; duration = duration || 3000;
  var icon = type === 'success' ? '\\u2713' : '\\u2715';
  var t = document.createElement('div');
  t.className = 'toast ' + type;
  t.innerHTML = '<div class="toast-icon">' + icon + '</div>'
    + '<div class="toast-content"><div class="toast-title">' + (type === 'success' ? 'Success!' : 'Error')
    + '</div><div class="toast-message"></div></div>';
  t.querySelector('.toast-message').textContent = message;
  document.body.appendChild(t);
  setTimeout(function(){ t.remove(); }, duration);
}
// Show a loading state on a CTA submit button once its form submits (and wasn't cancelled).
document.addEventListener('submit', function(e){
  if (e.defaultPrevented || e.target.tagName !== 'FORM') return;
  var btn = e.target.querySelector('button[type="submit"], button:not([type])');
  if (!btn || btn.disabled) return;
  // Defer so the form serializes (and the button value is sent) before we disable it.
  setTimeout(function(){ btn.classList.add('loading'); btn.disabled = true; }, 0);
});`;

// I1 — global delegated UI behaviors. Replaces every inline on* handler with
// data-* attributes + delegated listeners, so 'unsafe-inline' can be dropped from
// the script CSP. Injected on every HTML page by the res.send wrapper above.
//   data-copy="text"            → click copies text to clipboard
//   data-copy-from="elementId"  → click copies that element's value/text
//   data-print                  → click triggers window.print()
//   data-toggle-visibility="id" → click toggles that input's password/text type
//   data-confirm="message"      → form submit asks confirm() first (cancel = block)
//   data-invoice-jump="pubId"   → form submit redirects to the invoice for its period
//   data-autosubmit             → checkbox change submits its form
//   data-autoslug               → input fills #slug with a slugified value
//   data-slugify                → input lowercases/strips itself to [a-z0-9_-]
const BEHAVIORS_JS = `
(function(){
  function copyText(text, el){
    if(navigator.clipboard && navigator.clipboard.writeText){
      navigator.clipboard.writeText(text).then(function(){
        if(el){var o=el.style.background;el.style.background='#d4edda';setTimeout(function(){el.style.background=o;},700);}
      }).catch(function(){window.prompt('Copy:',text);});
    } else { window.prompt('Copy:',text); }
  }
  document.addEventListener('click',function(e){
    var t=e.target;
    var cp=t.closest('[data-copy]');
    if(cp){ copyText(cp.getAttribute('data-copy'), cp); return; }
    var cf=t.closest('[data-copy-from]');
    if(cf){ var src=document.getElementById(cf.getAttribute('data-copy-from'));
      if(src){ copyText(src.value!=null?src.value:src.textContent, src); } return; }
    if(t.closest('[data-print]')){ window.print(); return; }
    var tg=t.closest('[data-toggle-visibility]');
    if(tg){ var inp=document.getElementById(tg.getAttribute('data-toggle-visibility'));
      if(inp){ inp.type=inp.type==='password'?'text':'password';
        tg.textContent=inp.type==='password'?'Show':'Hide'; } return; }
  });
  // Capture phase so a cancelled confirm preventDefaults before any submit-loading handler runs.
  document.addEventListener('submit',function(e){
    var f=e.target;
    if(f.hasAttribute&&f.hasAttribute('data-confirm')){
      if(!window.confirm(f.getAttribute('data-confirm'))){ e.preventDefault(); return; }
    }
    if(f.hasAttribute&&f.hasAttribute('data-invoice-jump')){
      e.preventDefault();
      var v=f.period&&f.period.value;
      if(v){ var ym=v.split('-'); window.location.href='/admin/publishers/'+f.getAttribute('data-invoice-jump')+'/invoice/'+ym[0]+'/'+ym[1]; }
    }
  }, true);
  document.addEventListener('change',function(e){
    if(e.target.matches&&e.target.matches('[data-autosubmit]')&&e.target.form){ e.target.form.submit(); }
  });
  document.addEventListener('input',function(e){
    var t=e.target; if(!t.matches) return;
    if(t.matches('[data-autoslug]')){ var s=document.getElementById('slug');
      if(s){ s.value=t.value.toLowerCase().trim().replace(/[^a-z0-9]+/g,'-').replace(/^-+|-+$/g,''); } }
    if(t.matches('[data-slugify]')){ t.value=t.value.toLowerCase().replace(/[^a-z0-9_-]/g,''); }
  });
})();`;

// ---------------------------------------------------------------------------
// Admin HTML templates
// ---------------------------------------------------------------------------

const SUN_ICON = `<svg width="14" height="14" viewBox="0 0 16 16" fill="#00e5c3"><circle cx="8" cy="8" r="3.5"/><path stroke="#00e5c3" stroke-width="1.3" stroke-linecap="round" d="M8 1v1.5M8 13.5V15M1 8h1.5M13.5 8H15M3.2 3.2l1 1M11.8 11.8l1 1M12.8 3.2l-1 1M4.2 11.8l-1 1"/></svg>`;

function adminSidebar() {
  const ic = (d) => `<svg width="14" height="14" fill="currentColor" viewBox="0 0 16 16">${d}</svg>`;
  const ICONS = {
    dashboard:   ic(`<rect x="1" y="1" width="6" height="6" rx="1"/><rect x="9" y="1" width="6" height="6" rx="1"/><rect x="1" y="9" width="6" height="6" rx="1"/><rect x="9" y="9" width="6" height="6" rx="1"/>`),
    advertisers: ic(`<path fill="none" stroke="currentColor" stroke-width="1.5" d="M8 2L2 6v7h4v-4h4v4h4V6L8 2z"/>`),
    publishers:  ic(`<circle cx="6" cy="5" r="2.5"/><path fill="none" stroke="currentColor" stroke-width="1.5" d="M1 14c0-3 2.3-5 5-5s5 2 5 5"/><circle cx="12.5" cy="5" r="2"/><path fill="none" stroke="currentColor" stroke-width="1.5" d="M12.5 10c1.8.3 3 1.5 3 3"/>`),
    invoices:    ic(`<path fill="none" stroke="currentColor" stroke-width="1.5" d="M4 1.5h6l3 3V14H3V2a.5.5 0 0 1 .5-.5zM9.5 1.5v3.5H13M5 8h6M5 11h4"/>`),
    analytics:   ic(`<rect x="1" y="9" width="3.5" height="5.5" rx=".5"/><rect x="6.2" y="5.5" width="3.5" height="9" rx=".5"/><rect x="11.5" y="2" width="3.5" height="12.5" rx=".5"/>`),
    auditlog:    ic(`<circle cx="8" cy="8" r="6.5" fill="none" stroke="currentColor" stroke-width="1.5"/><path stroke="currentColor" stroke-width="1.5" stroke-linecap="round" d="M8 4.5V8.2l2.5 1.5"/>`),
    settings:    ic(`<circle cx="8" cy="8" r="2.2" fill="none" stroke="currentColor" stroke-width="1.5"/><path stroke="currentColor" stroke-width="1.4" stroke-linecap="round" d="M8 1v1.5M8 13.5V15M1 8h1.5M13.5 8H15M3.2 3.2l1 1M11.8 11.8l1 1M12.8 3.2l-1 1M4.2 11.8l-1 1"/>`),
    postback:    ic(`<path fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" d="M3 6h8l-2-2M13 10H5l2 2"/>`),
    reports:     ic(`<path fill="none" stroke="currentColor" stroke-width="1.5" d="M3 2h7l3 3v9H3z"/><path stroke="currentColor" stroke-width="1.3" stroke-linecap="round" d="M5.5 8.5h5M5.5 11h3M5.5 6h2"/>`),
    fraud:       ic(`<path fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round" d="M8 1.5l5.5 2.2v4.1c0 3.4-2.3 5.6-5.5 6.7-3.2-1.1-5.5-3.3-5.5-6.7V3.7L8 1.5z"/><path stroke="currentColor" stroke-width="1.4" stroke-linecap="round" d="M8 5.5v3.2M8 10.8v.2"/>`),
    quality:     ic(`<path stroke="currentColor" stroke-width="1.5" fill="none" stroke-linecap="round" stroke-linejoin="round" d="M8 1.6l1.9 3.9 4.3.6-3.1 3 .7 4.3L8 11.3 4.3 13.4l.7-4.3-3.1-3 4.3-.6L8 1.6z"/>`),
  };
  const nav = (href, label, icon, paths) =>
    `<a href="${href}" class="adm-nav-a" data-paths="${paths||href}">${ICONS[icon]}<span>${label}</span></a>`;
  return `<aside class="adm-sidebar" id="adm-sidebar" data-nav-sidebar>
  <div class="adm-sb-group">OVERVIEW</div>
  ${nav('/admin',             'Dashboard',   'dashboard',   '/admin')}
  ${nav('/admin/analytics',   'Analytics',   'analytics',   '/admin/analytics')}
  <div class="adm-sb-group">MANAGEMENT</div>
  ${nav('/admin/advertisers', 'Advertisers', 'advertisers', '/admin/advertisers')}
  ${nav('/admin/publishers',  'Publishers',  'publishers',  '/admin/publishers')}
  ${nav('/admin/invoices',    'Invoices',    'invoices',    '/admin/invoices')}
  <div class="adm-sb-group">REPORTS</div>
  ${nav('/admin/reports/cohort','Cohort / Retention','reports','/admin/reports/cohort')}
  ${nav('/admin/reports/pivot', 'Pivot Export',      'reports','/admin/reports/pivot')}
  <div class="adm-sb-group">RISK</div>
  ${nav('/admin/fraud',            'Fraud Review',      'fraud',  '/admin/fraud')}
  ${nav('/admin/publisher-quality','Publisher Quality', 'quality','/admin/publisher-quality')}
  <div class="adm-sb-group">SYSTEM</div>
  ${nav('/admin/postback-log','Postback Log','postback',    '/admin/postback-log')}
  ${nav('/admin/audit-log',   'Audit log',   'auditlog',    '/admin/audit-log')}
  ${nav('/admin/settings',    'Settings',    'settings',    '/admin/settings')}
  <div class="adm-sb-foot">
    <a href="/health" target="_blank" rel="noopener noreferrer"
       style="display:flex;align-items:center;gap:7px;color:rgba(255,255,255,.35);font-size:11px">
      <span id="hlt" style="width:6px;height:6px;border-radius:50%;background:#3fb950;flex-shrink:0;transition:background .4s"></span>
      System healthy
    </a>
  </div>
</aside>`;
}

function adminLayout(title, body) {
  return `<!DOCTYPE html><html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${H(title)} — Komorebi Admin</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>${ADMIN_CSS}</style></head>
<body>
<div class="adm-shell">
  <header class="adm-topbar">
    <div class="adm-brand">
      <button class="nav-burger" type="button" data-nav-toggle aria-label="Toggle menu" aria-controls="adm-sidebar" aria-expanded="false">☰</button>
      <div class="adm-logo-mark">${SUN_ICON}</div>
      <div>
        <div class="adm-brand-name">KOMOREBI</div>
        <div class="adm-brand-sub">NETWORK</div>
      </div>
    </div>
    <div class="adm-topbar-r">
      <span class="adm-badge">ADMIN</span>
      <span class="adm-topbar-user">${H(ADMIN_USER)}</span>
      <div class="adm-sep"></div>
      <form method="POST" action="/admin/logout" style="display:inline">
        <button class="tbtn-logout">Log out</button>
      </form>
    </div>
  </header>
  <div class="adm-body">
    ${adminSidebar()}
    <div class="nav-backdrop" data-nav-backdrop></div>
    <div class="adm-content">
      ${body}
    </div>
  </div>
</div>
<script>
(function(){
  var tz=Intl.DateTimeFormat().resolvedOptions().timeZone;
  if(tz) document.cookie='tz='+encodeURIComponent(tz)+';path=/;max-age=31536000;SameSite=Lax';
  var loc=window.location.pathname;
  document.querySelectorAll('.adm-nav-a').forEach(function(a){
    var paths=(a.getAttribute('data-paths')||'').split(',');
    var match=paths.some(function(p){
      p=p.trim();
      return p==='/admin'?loc===p:loc===p||loc.startsWith(p+'/');
    });
    if(match) a.classList.add('active');
  });
  fetch('/health').then(function(r){return r.json();}).then(function(d){
    var dot=document.getElementById('hlt');
    if(dot){dot.style.background=d.status==='ok'?'#3fb950':'#f85149';
      dot.title='Uptime: '+Math.floor(d.uptime)+'s';}
  }).catch(function(){var dot=document.getElementById('hlt');if(dot)dot.style.background='#f85149';});
  // CSRF: auto-inject _csrf hidden field into all POST forms
  function getCsrf(){var m=document.cookie.match(/(?:^|;\s*)_csrf=([^;]+)/);return m?decodeURIComponent(m[1]):'';}
  function injectCsrf(f){
    if(f.method.toUpperCase()==='POST'&&!f.querySelector('input[name="_csrf"]')){
      var inp=document.createElement('input');
      inp.type='hidden';inp.name='_csrf';inp.value=getCsrf();
      f.appendChild(inp);
    }
  }
  // Cover normal submit button clicks
  document.addEventListener('submit',function(e){
    if(e.target.tagName==='FORM') injectCsrf(e.target);
  },true);
  // Cover programmatic form.submit() calls (e.g. the data-autosubmit checkbox handler)
  var _origSubmit=HTMLFormElement.prototype.submit;
  HTMLFormElement.prototype.submit=function(){injectCsrf(this);_origSubmit.call(this);};
})();
${NAV_TOGGLE_JS}
</script>
</body></html>`;
}

function adminHeader(extra = '') {
  return extra
    ? `<div class="adm-header">${extra}</div>`
    : '';
}

function flashHtml(flash) {
  return flash ? `<div class="flash ${flash.type}">${H(flash.text)}</div>` : '';
}

function renderAdminLogin(errorMsg) {
  const LOGIN_CSS = `
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Inter',system-ui,sans-serif;background:#0d1117;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
    .card{background:#fff;border-radius:12px;padding:36px;width:100%;max-width:360px;box-shadow:0 8px 32px rgba(0,0,0,.5)}
    .mark{width:36px;height:36px;background:rgba(0,229,195,.12);border:1px solid rgba(0,229,195,.4);border-radius:8px;display:flex;align-items:center;justify-content:center;margin:0 auto 14px}
    h1{font-size:17px;font-weight:600;color:#111827;text-align:center;margin-bottom:4px}
    p{font-size:13px;color:#6b7280;text-align:center;margin-bottom:22px}
    .err{background:#fef2f2;color:#991b1b;padding:9px 12px;border-radius:6px;font-size:12px;margin-bottom:14px;border:1px solid #fca5a5}
    label{display:block;font-size:11px;font-weight:600;color:#6b7280;margin-bottom:4px;text-transform:uppercase;letter-spacing:.4px}
    input{width:100%;padding:9px 11px;border:1px solid #e2e6ea;border-radius:6px;font-size:14px;outline:none;font-family:inherit;color:#111827;margin-bottom:12px}
    input:focus{border-color:#00e5c3;box-shadow:0 0 0 3px rgba(0,229,195,.12)}
    button{width:100%;padding:10px;background:#00e5c3;color:#0d1117;border:none;border-radius:6px;font-size:14px;font-weight:600;cursor:pointer;margin-top:4px;font-family:inherit}
    button:hover{background:#00c9aa}
  `;
  const sunSvg = `<svg width="16" height="16" viewBox="0 0 16 16" fill="#00e5c3"><circle cx="8" cy="8" r="3.5"/><path stroke="#00e5c3" stroke-width="1.3" stroke-linecap="round" d="M8 1v1.5M8 13.5V15M1 8h1.5M13.5 8H15M3.2 3.2l1 1M11.8 11.8l1 1M12.8 3.2l-1 1M4.2 11.8l-1 1"/></svg>`;
  return `<!DOCTYPE html><html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Login — Komorebi</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>${LOGIN_CSS}</style></head>
<body>
<div class="card">
  <div class="mark">${sunSvg}</div>
  <h1>KOMOREBI</h1>
  <p>Sign in to the admin panel</p>
  ${errorMsg ? `<div class="err">${H(errorMsg)}</div>` : ''}
  <form method="POST" action="/admin/login">
    <label>Username</label>
    <input type="text" name="username" required autofocus autocomplete="username">
    <label>Password</label>
    <input type="password" name="password" required autocomplete="current-password">
    <button type="submit">Sign in</button>
  </form>
</div>
</body></html>`;
}

// Backlog #15 — format CTIT seconds as "3s" / "2h 14m" / "5d"
function fmtCtit(s) {
  if (s == null) return '—';
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
  return `${Math.floor(s / 86400)}d`;
}
function renderAdminDashboard({ totalClicks, totalConversions,
  approvedByCurrency = [], pendingByCurrency = [], monthlyByCurrency = [],
  thisMonth, advStats, pubStats, recent, flash, publisherCount, fraudFilter = '',
  topCountries = [], deviceSplit = [], osSplit = [], globalConvStatus = {}, csrfToken = '' }) {

  const advRows = advStats.filter(a => a.slug !== 'legacy' || a.clicks > 0).map(a => {
    const trackUrl   = `${BASE_URL}/track/${a.slug}?pub=PUBLISHER_NAME`;
    const postbkUrl  = `${BASE_URL}/postback/${a.slug}?click_id=CLICK_ID&event=sale&loan_amount=AMOUNT&revenue=REVENUE`;
    const isLegacy   = a.slug === 'legacy';
    return `<tr>
      <td>
        <strong>${H(a.name)}</strong>
        ${isLegacy ? '' : `<div style="margin-top:5px">
          <div class="ubox" data-copy="${H(trackUrl)}">/track/${H(a.slug)}?pub=PUBLISHER_NAME</div>
        </div>`}
      </td>
      <td><span class="badge ${a.status}">${a.status}</span></td>
      <td>${N(a.clicks)}</td><td>${N(a.conversions)}</td>
      <td>
        <div>${fmtCur(a.approved_payout, a.currency)} <span style="font-size:10px;color:#2e7d32">approved</span></div>
        ${a.pending_count > 0 ? `<div style="font-size:11px;color:#f57f17">${N(a.pending_count)} pending</div>` : ''}
      </td>
      <td>${fmtCur(a.revenue, a.currency)}</td>
      <td>${fmtCur(a.revenue - a.payout, a.currency)}<div style="font-size:10px;color:#6e6e73">${a.revenue>0?(((a.revenue-a.payout)/a.revenue*100).toFixed(1)+'%'):'—'}</div></td>
      <td>${a.monthly_conversion_cap != null
        ? `<span style="${a.cap_used >= a.monthly_conversion_cap ? 'color:#c62828;font-weight:600' : (a.cap_used >= a.monthly_conversion_cap*0.8 ? 'color:#f57f17' : '')}">${N(a.cap_used)}/${N(a.monthly_conversion_cap)}</span>`
        : '<span style="color:#8e8e93">—</span>'}</td>
      <td>${cvr(a.clicks,a.conversions)}</td>
      <td><div class="ubox" data-copy="${H(postbkUrl)}" style="max-width:200px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis">/postback/${H(a.slug)}?click_id=…</div></td>
      <td><div class="act">
        ${isLegacy ? '' : `<a href="/admin/advertisers/${H(a.slug)}/edit" class="btn btn-ghost">Edit</a>`}
        ${isLegacy ? '' : `<a href="/admin/advertisers/${H(a.slug)}/analytics" class="btn btn-ghost">Analytics</a>`}
        ${isLegacy ? '' : `<a href="/admin/advertisers/${H(a.slug)}/reconcile" class="btn btn-primary">Reconcile</a>`}
        ${isLegacy ? '' : `<form method="POST" action="/admin/advertisers/${H(a.slug)}/toggle" style="display:inline">${csrfField(csrfToken)}
          <button class="btn ${a.status==='active'?'btn-warn':'btn-ghost'}">${a.status==='active'?'Pause':'Activate'}</button></form>`}
        ${isLegacy ? '' : `<form method="POST" action="/admin/advertisers/${H(a.slug)}/delete" style="display:inline"
          data-confirm="Delete ${H(a.name)}? Historical data is kept.">${csrfField(csrfToken)}
          <button class="btn btn-danger">Delete</button></form>`}
        <a href="/admin/export.csv?advertiser=${H(a.slug)}" class="btn btn-ghost">CSV</a>
      </div></td>
    </tr>`;
  }).join('');

  const pubRows = pubStats.map(r => {
    const adv = advStats.find(a => a.slug === r.advertiser_slug);
    return `<tr>
      <td>${H(adv?.name||r.advertiser_slug)}</td>
      <td><code>${H(r.publisher)}</code></td>
      <td>${N(r.clicks)}</td><td>${N(r.conversions)}</td>
      <td>${fmtCur(r.payout, r.currency)}</td>
      <td>${fmtCur(r.revenue, r.currency)}</td>
      <td>${fmtCur(r.revenue - r.payout, r.currency)}<div style="font-size:10px;color:#6e6e73">${r.revenue>0?(((r.revenue-r.payout)/r.revenue*100).toFixed(1)+'%'):'—'}</div></td>
      <td>${cvr(r.clicks,r.conversions)}</td>
      <td><a href="/admin/export.csv?advertiser=${H(r.advertiser_slug)}&month=${thisMonth}" class="btn btn-ghost">CSV</a></td>
    </tr>`;
  }).join('');

  const recentRows = recent.map(r => {
    const adv = advStats.find(a => a.slug === r.advertiser_slug);
    const st = r.status || 'pending';
    // F15 — duplicates get a badge + an inline override back to pending/approved.
    const statusCell = st === 'duplicate'
      ? `<span class="badge duplicate" title="${H(r.reason||'duplicate_user')}">duplicate</span>
         <form method="POST" action="/admin/conversions/${r.id}/status" style="display:inline-flex;gap:3px;margin-top:3px">${csrfField(csrfToken)}
           <select name="status" style="font-size:10px;padding:1px 3px"><option value="pending">pending</option><option value="approved">approved</option></select>
           <button class="btn btn-ghost" style="font-size:10px;padding:1px 6px">Override</button>
         </form>`
      : `<span class="badge ${H(st)}">${H(st)}</span>`;
    const ctitFlagged = (r.fraud_flag || '').includes('ctit');
    return `<tr>
      <td>${H(r.received_at)}</td><td>${H(adv?.name||r.advertiser_slug)}</td>
      <td><code>${H(r.publisher)}</code></td>
      <td><code class="xs">${H(r.click_id)}</code></td>
      <td><span class="badge ev">${H(r.event)}</span></td>
      <td${ctitFlagged ? ' style="color:#c62828;font-weight:600"' : ''}>${fmtCtit(r.ctit_seconds)}</td>
      <td>${r.af_sub1 ? `<code class="xs">${H(r.af_sub1)}</code>` : ''}</td>
      <td>$${$(r.payout)}</td>
      <td>${statusCell}</td>
      <td>${fraudBadge(r.fraud_flag, r.fraud_source)}</td>
    </tr>`;
  }).join('');

  const body = `
${adminHeader(`<a href="/admin/marketplace" class="hbtn ghost">Marketplace</a>
  <a href="/admin/export.csv" class="hbtn ghost">Export All</a>
  <a href="/admin/advertisers/new" class="hbtn">+ Advertiser</a>`)}
<main>
${flashHtml(flash)}
<div class="cards">
  <div class="card"><div class="lbl">Total Clicks</div><div class="val">${N(totalClicks)}</div></div>
  <div class="card"><div class="lbl">Total Conversions</div><div class="val">${N(totalConversions)}</div></div>
  <div class="card"><div class="lbl">Approved Payout</div><div class="val green" style="font-size:18px">${fmtByCurrency(approvedByCurrency)}</div></div>
  <div class="card"><div class="lbl">Pending Payout</div><div class="val" style="color:#f57f17;font-size:18px">${fmtByCurrency(pendingByCurrency)}</div></div>
  <div class="card"><div class="lbl">Approved This Month</div><div class="val green" style="font-size:18px">${fmtByCurrency(monthlyByCurrency)}</div></div>
  <div class="card"><div class="lbl">Active Publishers</div><div class="val"><a href="/admin/publishers" style="text-decoration:none">${N(publisherCount)}</a></div></div>
</div>

<section>
  <div class="sh"><h2>Advertisers</h2>
    <div class="sh-r"><span class="meta">Click any URL to copy</span>
      <a href="/admin/advertisers/new" class="btn btn-primary">+ New</a></div>
  </div>
  ${advStats.filter(a=>a.slug!=='legacy'||a.clicks>0).length===0
    ? '<div class="empty">No advertisers yet. <a href="/admin/advertisers/new">Create one.</a></div>'
    : `<table><thead><tr><th>Advertiser / Tracking URL</th><th>Status</th><th>Clicks</th>
        <th>Conv</th><th>Payout</th><th>Revenue</th><th>Margin</th><th>Cap (mo)</th><th>CVR</th><th>Postback URL</th><th>Actions</th></tr></thead>
        <tbody>${advRows}</tbody></table>`}
</section>

<section>
  <div class="sh"><h2>Publisher Performance</h2><span class="meta">Top 100 by payout</span></div>
  ${pubRows.length===0 ? '<div class="empty">No data yet.</div>'
    : `<table><thead><tr><th>Advertiser</th><th>Publisher</th><th>Clicks</th><th>Conv</th><th>Payout</th><th>Revenue</th><th>Margin</th><th>CVR</th><th></th></tr></thead>
        <tbody>${pubRows}</tbody></table>`}
</section>

${(topCountries.length || deviceSplit.length) ? `
<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;margin-bottom:20px">

  <section style="margin-bottom:0">
    <div class="sh"><h2>Top Countries</h2><span class="meta">by clicks</span></div>
    ${topCountries.length === 0
      ? '<div class="empty" style="padding:20px">No geo data yet</div>'
      : (() => {
          const max = topCountries[0].n || 1;
          return `<div style="padding:10px 16px">${topCountries.map(r => {
            const pct = Math.round((r.n / max) * 100);
            return `<div style="margin-bottom:10px">
              <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:3px">
                <span><strong>${H(r.country)}</strong> <span style="color:#6e6e73;font-size:11px">${H(countryName(r.country))}</span></span>
                <span style="color:#6e6e73">${N(r.n)}</span>
              </div>
              <div style="background:#f0f0f0;border-radius:3px;height:5px">
                <div style="width:${pct}%;background:#0071e3;border-radius:3px;height:5px"></div>
              </div>
            </div>`;
          }).join('')}</div>`;
        })()}
  </section>

  <section style="margin-bottom:0">
    <div class="sh"><h2>Device Split</h2><span class="meta">mobile / desktop / tablet</span></div>
    <div style="padding:14px 16px">
      ${(() => {
          const total = deviceSplit.reduce((s, r) => s + r.n, 0) || 1;
          const order = ['mobile', 'desktop', 'tablet'];
          const colors = { mobile: '#0071e3', desktop: '#2e7d32', tablet: '#f57f17' };
          const rows = order.map(d => {
            const row = deviceSplit.find(r => r.device_type === d);
            const n   = row?.n || 0;
            const pct = Math.round((n / total) * 100);
            return { d, n, pct };
          });
          const barParts = rows.map(r =>
            r.pct > 0 ? `<div style="width:${r.pct}%;background:${colors[r.d]};height:100%;display:inline-block;vertical-align:top"></div>` : ''
          ).join('');
          return `<div style="background:#f0f0f0;border-radius:4px;height:10px;overflow:hidden;margin-bottom:14px">${barParts}</div>
            ${rows.map(r => `<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:7px">
              <span style="display:flex;align-items:center;gap:6px;font-size:12px">
                <span style="width:8px;height:8px;border-radius:50%;background:${colors[r.d]};display:inline-block"></span>
                ${r.d[0].toUpperCase() + r.d.slice(1)}
              </span>
              <span style="font-size:12px;color:#6e6e73">${N(r.n)} &nbsp;<strong>${r.pct}%</strong></span>
            </div>`).join('')}`;
      })()}
    </div>
  </section>

  <section style="margin-bottom:0">
    <div class="sh"><h2>Android vs iOS</h2><span class="meta">mobile OS split</span></div>
    <div style="padding:14px 16px">
      ${(() => {
          const android = osSplit.find(r => r.os === 'Android')?.n || 0;
          const ios     = osSplit.find(r => r.os === 'iOS')?.n     || 0;
          const total   = (android + ios) || 1;
          const aPct    = Math.round((android / total) * 100);
          const iPct    = 100 - aPct;
          return `<div style="background:#f0f0f0;border-radius:4px;height:10px;overflow:hidden;margin-bottom:14px">
            <div style="width:${aPct}%;background:#2e7d32;height:100%;display:inline-block;vertical-align:top"></div>
            <div style="width:${iPct}%;background:#0071e3;height:100%;display:inline-block;vertical-align:top"></div>
          </div>
          ${[['Android','#2e7d32',android,aPct],['iOS','#0071e3',ios,iPct]].map(([name,color,n,pct]) => `
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:7px">
              <span style="display:flex;align-items:center;gap:6px;font-size:12px">
                <span style="width:8px;height:8px;border-radius:50%;background:${color};display:inline-block"></span>
                ${name}
              </span>
              <span style="font-size:12px;color:#6e6e73">${N(n)} &nbsp;<strong>${pct}%</strong></span>
            </div>`).join('')}
          ${android + ios === 0 ? '<div style="color:#6e6e73;font-size:12px;margin-top:8px">No mobile data yet</div>' : ''}`;
      })()}
    </div>
  </section>

</div>` : ''}

<section>
  <div class="sh"><h2>Conversion Funnel</h2><span class="meta">all advertisers · all time</span></div>
  <div style="padding:20px 28px">
    ${funnelSvg([
      { label: 'Clicks',      value: totalClicks,                       color: '#0071e3' },
      { label: 'Conversions', value: totalConversions,                  color: '#7c3aed' },
      { label: 'Approved',    value: globalConvStatus.approved || 0,    color: '#2e7d32' },
      { label: 'Pending',     value: globalConvStatus.pending  || 0,    color: '#f57f17' },
      { label: 'Rejected',    value: globalConvStatus.rejected || 0,    color: '#c62828' },
    ])}
  </div>
</section>

<section>
  <div class="sh"><h2>Recent Conversions</h2>
    <div class="sh-r"><span class="meta">Last 50</span>
      <form method="GET" action="/admin" style="display:inline">
        <select name="fraud" onchange="this.form.submit()" style="font-size:12px;padding:4px 8px;border:1px solid #d2d2d7;border-radius:6px">
          ${[['', 'All conversions'], ['flagged', 'Flagged only'], ['duplicate_click_id', 'Duplicate click_id'], ['ctit', 'CTIT anomaly'], ['protect360', 'Protect360']].map(([v, l]) => `<option value="${v}" ${fraudFilter === v ? 'selected' : ''}>${l}</option>`).join('')}
        </select>
      </form>
      <a href="/admin/export.csv" class="btn btn-ghost">All CSV</a>
      <a href="/admin/export.csv?month=${thisMonth}" class="btn btn-ghost">${thisMonth} CSV</a></div>
  </div>
  ${recentRows.length===0 ? '<div class="empty">No conversions match.</div>'
    : `<table><thead><tr><th>Received</th><th>Advertiser</th><th>Publisher</th><th>Click ID</th><th>Event</th><th>CTIT</th><th>Sub-Aff</th><th>Payout</th><th>Status</th><th>Fraud</th></tr></thead>
        <tbody>${recentRows}</tbody></table>`}
</section>
</main><script>${CP_JS}</script>`;

  return adminLayout('Dashboard', body);
}

function renderAdvList({ advStats, flash, csrfToken = '' }) {
  const rows = advStats.filter(a => a.slug !== 'legacy' || a.clicks > 0).map(a => {
    const trackUrl  = `${BASE_URL}/track/${a.slug}?pub=PUBLISHER_NAME`;
    const postbkUrl = `${BASE_URL}/postback/${a.slug}?click_id=CLICK_ID&event=sale&loan_amount=AMOUNT&revenue=REVENUE`;
    const isLegacy  = a.slug === 'legacy';
    return `<tr>
      <td>
        <strong>${H(a.name)}</strong>
        ${isLegacy ? '' : `<div style="margin-top:5px"><div class="ubox" data-copy="${H(trackUrl)}">/track/${H(a.slug)}?pub=PUBLISHER_NAME</div></div>`}
      </td>
      <td><span class="badge ${a.status}">${a.status}</span></td>
      <td>${N(a.clicks)}</td>
      <td>${N(a.conversions)}</td>
      <td>
        <div>$${$(a.approved_payout)} <span style="font-size:10px;color:#2e7d32">approved</span></div>
        ${a.pending_count > 0 ? `<div style="font-size:11px;color:#f57f17">${N(a.pending_count)} pending</div>` : ''}
      </td>
      <td>${cvr(a.clicks, a.conversions)}</td>
      <td>
        ${isLegacy ? '' : `<div class="ubox" data-copy="${H(postbkUrl)}" style="max-width:200px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis">/postback/${H(a.slug)}?click_id=…</div>`}
      </td>
      <td><div class="act">
        ${isLegacy ? '' : `<a href="/admin/advertisers/${H(a.slug)}/edit" class="btn btn-ghost">Edit</a>`}
        ${isLegacy ? '' : `<a href="/admin/advertisers/${H(a.slug)}/analytics" class="btn btn-ghost">Analytics</a>`}
        ${isLegacy ? '' : `<a href="/admin/advertisers/${H(a.slug)}/reconcile" class="btn btn-primary">Reconcile</a>`}
        ${isLegacy ? '' : `<form method="POST" action="/admin/advertisers/${H(a.slug)}/toggle" style="display:inline">${csrfField(csrfToken)}
          <button class="btn ${a.status==='active'?'btn-warn':'btn-ghost'}">${a.status==='active'?'Pause':'Activate'}</button></form>`}
        ${isLegacy ? '' : `<form method="POST" action="/admin/advertisers/${H(a.slug)}/delete" style="display:inline"
          data-confirm="Delete ${H(a.name)}? Historical data is kept.">${csrfField(csrfToken)}
          <button class="btn btn-danger">Delete</button></form>`}
        <a href="/admin/export.csv?advertiser=${H(a.slug)}" class="btn btn-ghost">CSV</a>
      </div></td>
    </tr>`;
  }).join('');

  const body = `${adminHeader('<a href="/admin/advertisers/new" class="hbtn">+ New Advertiser</a>')}
<main>
${flashHtml(flash)}
<section>
  <div class="sh"><h2>Advertisers</h2>
    <div class="sh-r"><span class="meta">Click any URL to copy</span>
      <a href="/admin/advertisers/new" class="btn btn-primary">+ New</a></div>
  </div>
  ${rows.length === 0
    ? '<div class="empty">No advertisers yet. <a href="/admin/advertisers/new">Create one.</a></div>'
    : `<table><thead><tr>
        <th>Advertiser / Tracking URL</th><th>Status</th><th>Clicks</th>
        <th>Conv</th><th>Payout</th><th>CVR</th><th>Postback URL</th><th>Actions</th>
      </tr></thead><tbody>${rows}</tbody></table>`}
</section>
</main><script>${CP_JS}</script>`;

  return adminLayout('Advertisers', body);
}

function renderMmpSync({ adv, logs, csrfToken = '', flash, error }) {
  const rows = logs.map(l => {
    let errCount = 0; try { errCount = l.errors ? JSON.parse(l.errors).length : 0; } catch { errCount = l.errors ? 1 : 0; }
    return `<tr>
      <td style="white-space:nowrap;font-size:11px">${H((l.synced_at||'').slice(0,16))}</td>
      <td><span class="badge ${l.status==='success'?'active':'rejected'}">${H(l.status)}</span></td>
      <td>${N(l.events_pulled)}</td>
      <td>${N(l.matched)}</td>
      <td style="color:#2e7d32">${N(l.auto_approved)}</td>
      <td style="color:#c62828">${N(l.auto_rejected)}</td>
      <td style="color:#92651a">${l.flagged ? N(l.flagged) : '—'}</td>
      <td>${errCount ? `<span title="${H((l.errors||'').slice(0,300))}" style="color:#f57f17">${errCount} issue(s)</span>` : '—'}</td>
    </tr>`;
  }).join('');

  const body = `${adminHeader(`<a href="/admin/advertisers/${H(adv.slug)}/edit" class="hbtn ghost">← Edit advertiser</a>`)}
<main><div class="fw">
  <h2>MMP Sync — ${H(adv.name)}</h2>
  ${flash ? `<div class="flash success">${H(flash)}</div>` : ''}
  ${error ? `<div class="form-err">${H(error)}</div>` : ''}
  <p style="font-size:12px;color:#6e6e73;margin-bottom:12px">Pulls the last 24h of AppsFlyer in-app events and auto-approves non-organic (attributed) / auto-rejects organic conversions matched by <code>click_id</code>. Events with <code>media_source = restricted</code> (attributed to a privacy-restricted network, not your affiliate) are left <strong>pending and flagged</strong> for manual review. Manual trigger only.</p>
  <div class="callout" style="background:#fff8e1;border:1px solid #ffc107;border-radius:8px;padding:10px 12px;margin-bottom:14px;font-size:12px;color:#92651a">
    <strong>Matching requirement:</strong> our <code>click_id</code> must be passed as AppsFlyer's <code>customer_user_id</code> in your tracking link (the sync matches on AppsFlyer's <code>customer_user_id</code>, falling back to <code>appsflyer_id</code>). Attribution is read from <code>media_source</code> (organic ⇒ rejected).
  </div>
  <form method="POST" action="/admin/advertisers/${H(adv.slug)}/mmp-sync/run" style="margin-bottom:18px"
        data-confirm="Run a manual AppsFlyer sync now?">${csrfField(csrfToken)}
    <button class="btn btn-primary"${adv.mmp_type==='appsflyer'?'':' disabled'}>Run Sync Now</button>
    ${adv.mmp_type==='appsflyer' ? '' : '<small style="margin-left:8px;color:#8e8e93">Set MMP Type to AppsFlyer first.</small>'}
  </form>
  ${logs.length === 0
    ? '<div class="empty">No sync runs yet.</div>'
    : `<table><thead><tr><th>When</th><th>Status</th><th>Pulled</th><th>Matched</th><th>Approved</th><th>Rejected</th><th>Flagged</th><th>Issues</th></tr></thead>
        <tbody>${rows}</tbody></table>`}
</div></main>`;
  return adminLayout(`MMP Sync — ${adv.name}`, body);
}

function renderAdvForm({ title, action, adv = {}, error, csrfToken = '', goals = [], eventMappings = [], flash, capUsed = null, hasMmpToken = false, hasPortalPw = false }) {
  const isEdit = action.includes('/update');
  const statusOpts = ['active','paused'].map(s =>
    `<option value="${s}" ${(adv.status||'active')===s?'selected':''}>${s[0].toUpperCase()+s.slice(1)}</option>`
  ).join('');

  const goalsSection = !isEdit ? '' : `
  <div style="margin-top:28px">
    <h2 style="font-size:16px;margin-bottom:4px">Conversion Goals</h2>
    <p style="font-size:12px;color:#6e6e73;margin-bottom:12px">Define multiple payable events. A postback's <code>event</code> is matched against a goal's event token to choose the payout; if none match, the default payout above applies. A per-publisher payout override still takes precedence.</p>
    ${goals.length === 0 ? '<div class="empty" style="margin-bottom:14px">No goals defined — the default payout applies to every conversion.</div>' : `
    <table style="margin-bottom:16px"><thead><tr>
      <th>Name</th><th>Event Token</th><th>Payout</th><th>Status</th><th>Description</th><th></th>
    </tr></thead><tbody>
    ${goals.map(g => `<tr>
      <td><strong>${H(g.name)}</strong></td>
      <td><code class="xs">${H(g.event_token)}</code></td>
      <td>${g.payout_type === 'percent' ? `${H(g.payout)}% of loan` : `$${$(g.payout)}`}</td>
      <td><span class="badge ${g.status==='active'?'active':'paused'}">${H(g.status)}</span></td>
      <td style="font-size:11px;color:#6e6e73">${H(g.description||'—')}</td>
      <td><form method="POST" action="/admin/advertisers/${H(adv.slug)}/goals/${H(g.id)}/delete" style="display:inline"
            data-confirm="Delete goal ${H(g.name)}?">${csrfField(csrfToken)}
            <button class="btn btn-danger">Delete</button></form></td>
    </tr>`).join('')}
    </tbody></table>`}
    <form method="POST" action="/admin/advertisers/${H(adv.slug)}/goals"
          style="display:grid;grid-template-columns:1fr 1fr .7fr .8fr 1.4fr auto;gap:8px;align-items:end;background:#f5f5f7;padding:14px;border-radius:10px">${csrfField(csrfToken)}
      <div class="fg" style="margin:0"><label>Goal Name</label><input type="text" name="name" required placeholder="e.g. First Deposit"></div>
      <div class="fg" style="margin:0"><label>Event Token</label><input type="text" name="event_token" required placeholder="e.g. ftd"></div>
      <div class="fg" style="margin:0"><label>Payout</label><input type="number" name="payout" step="0.01" min="0" value="0" required></div>
      <div class="fg" style="margin:0"><label>Type</label>
        <select name="payout_type"><option value="fixed">Fixed $</option><option value="percent">Percent %</option></select></div>
      <div class="fg" style="margin:0"><label>Description</label><input type="text" name="description" placeholder="optional"></div>
      <button type="submit" class="btn btn-primary">Add Goal</button>
    </form>
  </div>`;

// Backlog #7 — event name mapping (advertiser SDK event → Komorebi event value)
  const eventMapSection = !isEdit ? '' : `
  <div style="margin-top:28px">
    <h2 style="font-size:16px;margin-bottom:4px">Event Name Mapping <span style="font-size:11px;color:#6e6e73">(Backlog #7)</span></h2>
    <p style="font-size:12px;color:#6e6e73;margin-bottom:12px">Map the advertiser's SDK event names (e.g. <code>deposit_Trade_succeeded</code>, <code>af_purchase</code>) to the Komorebi event value used for goal/payout matching. Prevents event mismatch in reconciliation.</p>
    ${eventMappings.length === 0 ? '<div class="empty" style="margin-bottom:14px">No event mappings — incoming event names are used as-is.</div>' : `
    <table style="margin-bottom:16px"><thead><tr><th>Advertiser Event (source)</th><th>Komorebi Event (mapped)</th><th></th></tr></thead><tbody>
    ${eventMappings.map(m => `<tr>
      <td><code class="xs">${H(m.source_event)}</code></td>
      <td><code class="xs">${H(m.mapped_event)}</code></td>
      <td><form method="POST" action="/admin/advertisers/${H(adv.slug)}/event-mappings/${H(m.id)}/delete" style="display:inline" data-confirm="Delete mapping ${H(m.source_event)}?">${csrfField(csrfToken)}<button class="btn btn-danger">Delete</button></form></td>
    </tr>`).join('')}
    </tbody></table>`}
    <form method="POST" action="/admin/advertisers/${H(adv.slug)}/event-mappings" style="display:grid;grid-template-columns:1fr 1fr auto;gap:8px;align-items:end;background:#f5f5f7;padding:14px;border-radius:10px">${csrfField(csrfToken)}
      <div class="fg" style="margin:0"><label>Advertiser Event</label><input type="text" name="source_event" required placeholder="e.g. af_purchase"></div>
      <div class="fg" style="margin:0"><label>Komorebi Event</label><input type="text" name="mapped_event" required placeholder="e.g. sale"></div>
      <button type="submit" class="btn btn-primary">Add Mapping</button>
    </form>
  </div>`;

  
// Backlog #5 — partner-link template + copy-paste AppsFlyer setup block. The template
  // maps Komorebi's click_id into AppsFlyer's customer_user_id and standard sub-params.
  const trackUrl = `${BASE_URL}/track/${H(adv.slug||'SLUG')}?pub=PUBLISHER`;
  const defaultTemplate =
    `${BASE_URL}/track/${adv.slug||'SLUG'}?pub={publisher}&customer_user_id={click_id}&af_siteid={af_siteid}&af_sub1={af_sub1}&af_sub2={af_sub2}&af_sub3={af_sub3}&af_sub4={af_sub4}&af_sub5={af_sub5}&af_c_id={af_c_id}&clickid={click_id}`;
  const tpl = adv.partner_link_template || defaultTemplate;
  const partnerLinkSection = !isEdit ? '' : `
  <div style="margin-top:28px">
    <h2 style="font-size:16px;margin-bottom:4px">Partner-Link Template <span style="font-size:11px;color:#6e6e73">(Backlog #5)</span></h2>
    <p style="font-size:12px;color:#6e6e73;margin-bottom:12px">Macro template handed to the advertiser for AppsFlyer onboarding. <code>{click_id}</code> auto-injects as <code>customer_user_id</code> (the reconciliation match key). Also maps <code>af_siteid</code>, <code>af_sub1-5</code>, <code>af_c_id</code>, <code>clickid</code>.</p>
    <form method="POST" action="/admin/advertisers/${H(adv.slug)}/partner-link" style="margin-bottom:14px">${csrfField(csrfToken)}
      <textarea name="partner_link_template" rows="3" style="width:100%;padding:8px 10px;border:1px solid #d2d2d7;border-radius:7px;font-family:monospace;font-size:12px;resize:vertical">${H(tpl)}</textarea>
      <div style="margin-top:8px"><button class="btn btn-primary">Save Template</button></div>
    </form>
    <div style="background:#f5f5f7;border-radius:8px;padding:14px 16px;font-size:12px;line-height:1.7">
      <strong>Copy-paste AppsFlyer setup block</strong> — give this to the advertiser:
      <div class="ubox" data-copy="${H(tpl)}" style="margin-top:8px;word-break:break-all">${H(tpl)}</div>
      <div style="margin-top:8px;color:#6e6e73">Base tracking URL: <code>${trackUrl}</code> · Match key: <code>customer_user_id = click_id</code> · App ID: <code>${H(adv.mmp_app_id||'(set in MMP section)')}</code></div>
    </div>
  </div>`;

  

  // Backlog #8 — postback test tool + HMAC doc links
  const pbToolsSection = !isEdit ? '' : `
  <div style="margin-top:28px">
    <h2 style="font-size:16px;margin-bottom:4px">Integration Tools</h2>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      <a href="/admin/advertisers/${H(adv.slug)}/postback-test" class="btn btn-ghost">Postback Test Tool &rarr;</a>
      <a href="/docs#hmac" target="_blank" class="btn btn-ghost">HMAC Signing Docs &rarr;</a>
    </div>
  </div>`;

  // Backlog #11 — advertiser portal access (admin sets the portal password)
  const portalSection = !isEdit ? '' : `
  <div style="margin-top:28px">
    <h2 style="font-size:16px;margin-bottom:4px">Advertiser Portal Access <span style="font-size:11px;color:#6e6e73">(Backlog #11)</span></h2>
    <fieldset style="border:1px solid #e0e0e0;border-radius:10px;padding:14px 16px">
      <p style="font-size:12px;color:#6e6e73;margin:0 0 10px">Give the advertiser read-only portal access (login at <code>/advertiser/login</code>, username <code>${H(adv.slug)}</code>): conversions, analytics, tracking links, and CSV reconciliation upload &mdash; no admin access.</p>
      <form method="POST" action="/admin/advertisers/${H(adv.slug)}/portal-password" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">${csrfField(csrfToken)}
        <input type="password" name="portal_password" autocomplete="new-password" placeholder="${hasPortalPw ? '\u2022\u2022\u2022\u2022\u2022\u2022\u2022 (set) \u2014 enter to change' : 'set a portal password'}" style="flex:1;min-width:220px;font-family:monospace;font-size:12px;padding:8px 10px;border:1px solid #d2d2d7;border-radius:7px">
        <button class="btn btn-primary">${hasPortalPw ? 'Update' : 'Enable'} Portal</button>
        ${hasPortalPw ? `<button class="btn btn-danger" formaction="/admin/advertisers/${H(adv.slug)}/portal-password" name="portal_password" value="">Disable</button>` : ''}
      </form>
    </fieldset>
  </div>`;

  const body = `${adminHeader()}
<main><div class="fw">
  <h2>${H(title)}</h2>
  ${flash ? `<div class="flash success">${H(flash)}</div>` : ''}
  ${error ? `<div class="form-err">${H(error)}</div>` : ''}
  <form method="POST" action="${H(action)}">${csrfField(csrfToken)}
    <div class="fg"><label>Advertiser Name *</label>
      <input type="text" name="name" value="${H(adv.name||'')}" required
             ${isEdit?'':'data-autoslug'}></div>
    ${isEdit ? '' : `<div class="fg"><label>Slug (used in URLs) *</label>
      <input type="text" name="slug" id="slug" value="${H(adv.slug||'')}"
             pattern="[a-z0-9-]+" required placeholder="e.g. acbs, shb-finance">
      <small>Lowercase letters, numbers, hyphens. Cannot be changed after creation.</small></div>`}
    <div class="fg"><label>Offer URL *</label>
      <input type="url" name="offer_url" value="${H(adv.offer_url||'')}" placeholder="https://…" required>
      <small>A <code>click_id</code> param will be appended automatically.</small></div>
    <div class="fg-row">
      <div class="fg"><label>Default Payout</label>
        <input type="number" name="payout_amount" value="${H(adv.payout_amount||'0')}" step="0.01" min="0">
        <small>Dollar amount when type is Fixed; percent of <code>loan_amount</code> when Percent.</small></div>
      <div class="fg"><label>Payout Type</label>
        <select name="payout_type">
          <option value="fixed"   ${(adv.payout_type||'fixed')==='fixed'  ?'selected':''}>Fixed $</option>
          <option value="percent" ${(adv.payout_type||'fixed')==='percent'?'selected':''}>Percent %</option>
        </select></div>
      <div class="fg"><label>Status</label><select name="status">${statusOpts}</select></div>
    </div>
    <div class="fg"><label>Click Lookback / Attribution Window (days)</label>
      <input type="number" name="click_lookback_window" value="${H(adv.click_lookback_window ?? 90)}" step="1" min="1" style="max-width:160px">
      <small>Postbacks for clicks older than this are rejected (HTTP 410). <strong>Set this to match the advertiser's AppsFlyer attribution window exactly</strong> (AppsFlyer default is 90 days) — a misaligned window rejects valid postbacks and causes reconciliation disputes.</small></div>
    <fieldset style="border:1px solid #e0e0e0;border-radius:10px;padding:14px 16px;margin-bottom:14px">
      <legend style="font-size:12px;font-weight:600;padding:0 6px">Reporting — Timezone &amp; Currency</legend>
      <p style="font-size:12px;color:#6e6e73;margin:0 0 10px">Must match the advertiser's AppsFlyer app <strong>timezone</strong> and <strong>currency</strong> exactly — mismatches are the #1 cause of reconciliation disputes. Reconciliation timestamps for this advertiser are displayed in the timezone below.</p>
      <div class="fg-row">
        <div class="fg"><label>Timezone (IANA)</label>
          <input type="text" name="timezone" value="${H(adv.timezone||'')}" placeholder="e.g. Asia/Ho_Chi_Minh (blank = platform default)" list="tzlist">
          <datalist id="tzlist">
            <option value="Asia/Ho_Chi_Minh"><option value="Asia/Bangkok"><option value="Asia/Singapore"><option value="Asia/Jakarta">
            <option value="Asia/Manila"><option value="Asia/Kolkata"><option value="Asia/Dubai"><option value="Europe/London">
            <option value="America/New_York"><option value="America/Los_Angeles"><option value="UTC">
          </datalist>
          <small>AppsFlyer app timezone. Blank falls back to ${H(FALLBACK_TZ)}.</small></div>
        <div class="fg"><label>Default Currency</label>
          <select name="currency">
            ${['USD','VND','THB','SGD','IDR','PHP','INR','EUR','GBP','AED'].map(c =>
              `<option value="${c}" ${(adv.currency||'USD')===c?'selected':''}>${c}</option>`).join('')}
          </select>
          <small>AppsFlyer app reporting currency.</small></div>
      </div>
    </fieldset>
    <div class="fg-row">
      <div class="fg"><label>Monthly Conversion Cap</label>
        <input type="number" name="monthly_conversion_cap" value="${adv.monthly_conversion_cap ?? ''}" step="1" min="0" placeholder="unlimited" style="max-width:160px">
        <small>Hard ceiling on approved conversions per UTC month — blank = unlimited. At the cap the advertiser auto-pauses and postbacks are rejected (HTTP 429).${isEdit && adv.monthly_conversion_cap != null ? ` <strong>Used this month: ${capUsed ?? 0} / ${adv.monthly_conversion_cap}</strong>` : ''}</small></div>
      ${isEdit ? `<div class="fg"><label>Reset Month Count</label>
        <input type="month" name="cap_reset_month" value="${H(adv.cap_reset_month||'')}">
        <small>Change this to reset the current month's cap count and re-activate if auto-paused.</small></div>` : ''}
    </div>
    <fieldset style="border:1px solid #e0e0e0;border-radius:10px;padding:14px 16px;margin-bottom:14px">
      <legend style="font-size:12px;font-weight:600;padding:0 6px">Marketplace</legend>
      <div class="fg"><label style="display:flex;align-items:center;gap:8px;font-weight:500">
        <input type="checkbox" name="is_public" value="1" ${adv.is_public ? 'checked' : ''} style="width:auto;margin:0"> List on the public marketplace</label>
        <small>Publishers can browse this campaign at /marketplace and apply to run it.</small></div>
      <div class="fg-row">
        <div class="fg"><label>Category</label><input type="text" name="category" value="${H(adv.category||'')}" placeholder="e.g. Loans, Finance"></div>
        <div class="fg"><label>Countries Allowed</label><input type="text" name="countries_allowed" value="${H(adv.countries_allowed||'')}" placeholder="e.g. VN, TH (display only)"></div>
      </div>
      <div class="fg"><label>Description</label>
        <textarea name="description" rows="2" style="width:100%;padding:8px 10px;border:1px solid #d2d2d7;border-radius:7px;font-size:13px;resize:vertical">${H(adv.description||'')}</textarea></div>
    </fieldset>
    <fieldset style="border:1px solid #e0e0e0;border-radius:10px;padding:14px 16px;margin-bottom:14px">
      <legend style="font-size:12px;font-weight:600;padding:0 6px">Postback Security</legend>
      <div class="fg"><label>HMAC Postback Secret</label>
        <div style="display:flex;gap:8px;align-items:center">
          <input type="text" id="pbsecret" name="postback_secret" value="${H(adv.postback_secret||'')}"
                 placeholder="blank = no signature required" style="flex:1;font-family:monospace;font-size:12px">
          <button type="button" class="btn btn-ghost" data-copy-from="pbsecret">Copy</button>
        </div>
        <small>If set, postbacks must include <code>&amp;sig=HMAC_SHA256(secret, click_id+event+payout)</code> as a hex digest, or they are rejected (403). Leave blank to accept unsigned postbacks (backward compatible).</small></div>
    </fieldset>
    <fieldset style="border:1px solid #e0e0e0;border-radius:10px;padding:14px 16px;margin-bottom:14px">
      <legend style="font-size:12px;font-weight:600;padding:0 6px">MMP Integration (AppsFlyer / Adjust)</legend>
      <div class="fg-row">
        <div class="fg"><label>MMP Type</label>
          <select name="mmp_type">
            <option value="none"      ${(adv.mmp_type||'none')==='none'      ?'selected':''}>None</option>
            <option value="appsflyer" ${(adv.mmp_type||'none')==='appsflyer' ?'selected':''}>AppsFlyer</option>
            <option value="adjust"    ${(adv.mmp_type||'none')==='adjust'    ?'selected':''}>Adjust</option>
          </select>
          <small>AppsFlyer reconciles via Komorebi's pull sync (needs App ID + API Token). Adjust is push-based (real-time S2S postbacks) — App ID/Token are not required; see the <a href="/docs#adjust" target="_blank">Adjust postback docs</a>.</small></div>
        <div class="fg"><label>App ID</label>
          <input type="text" name="mmp_app_id" value="${H(adv.mmp_app_id||'')}" placeholder="e.g. id123456789 or com.app"></div>
      </div>
      <div class="fg"><label>API Token</label>
        <div style="display:flex;gap:8px;align-items:center">
          <input type="password" id="mmptoken" name="mmp_api_token" value=""
                 placeholder="${hasMmpToken ? '••••••• (saved) — leave blank to keep' : 'AppsFlyer API token'}" autocomplete="new-password" style="flex:1;font-family:monospace;font-size:12px">
          <button type="button" class="btn btn-ghost" data-toggle-visibility="mmptoken">Show</button>
        </div>
        <small>${hasMmpToken ? 'A token is saved. Enter a new value only to replace it; leave blank to keep the current one. ' : ''}Stored ${mmpKey() ? 'encrypted (AES-256-GCM)' : '<strong style="color:#c62828">in plaintext — set MMP_ENCRYPTION_KEY</strong>'}. Used to pull in-app events from AppsFlyer.</small></div>
      ${isEdit ? `<div style="display:flex;gap:8px;margin-top:6px">
        <button type="submit" formaction="/admin/advertisers/${H(adv.slug)}/mmp-test" formmethod="POST" class="btn btn-ghost">Test Connection</button>
        <a href="/admin/advertisers/${H(adv.slug)}/mmp-sync" class="btn btn-ghost">Sync Dashboard →</a>
      </div>
      <small style="display:block;margin-top:6px;color:#8e8e93">Save credentials before testing — the test uses the saved token.</small>` : ''}
    </fieldset>
    ${isEdit && adv.slug ? `
    <div class="fg"><label>Tracking URL format</label>
      <div class="ubox" data-copy="${H(BASE_URL)}/track/${H(adv.slug)}?pub=PUBLISHER_NAME">
        ${H(BASE_URL)}/track/${H(adv.slug)}?pub=PUBLISHER_NAME</div></div>
    <div class="fg"><label>Postback URL format</label>
      <div class="ubox" data-copy="${H(BASE_URL)}/postback/${H(adv.slug)}?click_id=CLICK_ID&event=sale&loan_amount=AMOUNT&revenue=REVENUE">
        ${H(BASE_URL)}/postback/${H(adv.slug)}?click_id=CLICK_ID&amp;event=sale&amp;loan_amount=AMOUNT&amp;revenue=REVENUE</div></div>` : ''}
    <div class="form-act">
      <button type="submit" class="btn btn-primary btn-lg">Save Advertiser</button>
      <a href="/admin" class="btn btn-ghost btn-lg">Cancel</a>
    </div>
  </form>
  ${goalsSection}
  ${eventMapSection}
  ${partnerLinkSection}
  ${pbToolsSection}
  ${portalSection}
</div></main>
<script>
function autoSlug(n){const s=document.getElementById('slug');if(s)s.value=n.value.toLowerCase().trim().replace(/[^a-z0-9]+/g,'-').replace(/^-+|-+$/g,'');}
${CP_JS}
</script>`;

  return adminLayout(title, body);
}

function renderPubList({ publishers, pending = [], flash, csrfToken = '' }) {
  const pendingRows = pending.map(p => `<tr style="background:#fffbf0">
    <td>
      <strong>${H(p.username)}</strong>
      ${p.email    ? `<div style="font-size:11px;color:#6e6e73;margin-top:2px">${H(p.email)}</div>` : ''}
      ${p.company  ? `<div style="font-size:11px;color:#8e8e93">${H(p.company)}</div>` : ''}
      ${p.website  ? `<div style="font-size:11px">${/^https?:\/\//i.test(p.website)
        ? `<a href="${H(p.website)}" target="_blank" rel="noopener noreferrer" style="color:#0071e3">${H(p.website.replace(/^https?:\/\//,''))}</a>`
        : H(p.website)}</div>` : ''}
      ${p.traffic_sources ? `<div style="margin-top:4px">${p.traffic_sources.split(',').map(s => `<span style="background:#f5f5f7;border:1px solid #e0e0e0;border-radius:4px;padding:1px 6px;font-size:10px;margin-right:3px">${H(s)}</span>`).join('')}</div>` : ''}
    </td>
    <td><span class="badge pending">Pending</span></td>
    <td style="color:#8e8e93;font-size:11px">${H(p.created_at?.slice(0,10)||'')}</td>
    <td>
      <div class="act">
        <form method="POST" action="/admin/publishers/${p.id}/approve" style="display:inline">${csrfField(csrfToken)}
          <button class="btn btn-primary">Approve</button>
        </form>
        <form method="POST" action="/admin/publishers/${p.id}/reject" style="display:inline"
              data-confirm="Reject application from ${H(p.username)}?">${csrfField(csrfToken)}
          <button class="btn btn-danger">Reject</button>
        </form>
        <form method="POST" action="/admin/publishers/${p.id}/delete" style="display:inline"
              data-confirm="Permanently delete application from ${H(p.username)}?">${csrfField(csrfToken)}
          <button class="btn btn-ghost">Delete</button>
        </form>
      </div>
    </td>
  </tr>`).join('');

  const rows = publishers.map(p => {
    const keySuffix = p.api_key_suffix || (p.api_key ? p.api_key.slice(-8) : null);
    const keyBadge = p.api_key_hash
      ? `<code style="font-size:10px;color:#2e7d32">…${H(keySuffix || '')}</code>`
      : `<span style="font-size:10px;color:#c62828">revoked</span>`;
    const qs = publisherQualityScore(p.username);  // Backlog #16 — traffic-quality badge
    return `<tr>
    <td>
      <strong>${H(p.username)}</strong> ${qualityBadge(qs.score, qs.grade)}
      ${p.email   ? `<div style="font-size:11px;color:#6e6e73;margin-top:1px">${H(p.email)}</div>` : ''}
      ${p.company ? `<div style="font-size:11px;color:#8e8e93">${H(p.company)}</div>` : ''}
      <div style="margin-top:3px">API key: ${keyBadge}</div>
      ${p.postback_url ? `<div style="margin-top:2px"><code style="font-size:10px;color:#6e6e73">${H(p.postback_url.slice(0,50))}${p.postback_url.length>50?'…':''}</code></div>` : ''}
    </td>
    <td><span class="badge ${p.status}">${p.status}</span></td>
    <td>${N(p.clicks)}</td><td>${N(p.conversions)}</td>
    <td>$${$(p.payout)}</td>
    <td><small style="color:#8e8e93">${H(p.created_at?.slice(0,10)||'')}</small></td>
    <td><div class="act">
      <a href="/admin/publishers/${p.id}/edit" class="btn btn-ghost">Edit</a>
      <a href="/admin/publishers/${p.id}/payments" class="btn btn-ghost">Payments</a>
      <a href="/admin/publishers/${p.id}/postback-log" class="btn btn-ghost">S2S Log</a>
      <form data-invoice-jump="${p.id}" style="display:inline-flex;gap:3px;vertical-align:middle">
        <input type="month" name="period" value="${new Date().toISOString().slice(0,7)}" style="padding:4px 7px;border:1px solid #d2d2d7;border-radius:6px;font-size:11px;height:27px">
        <button type="submit" class="btn btn-ghost">Invoice</button>
      </form>
      <form method="POST" action="/admin/publishers/${p.id}/regenerate-key" style="display:inline"
            data-confirm="Regenerate API key for ${H(p.username)}? The old key stops working immediately.">${csrfField(csrfToken)}
        <button class="btn btn-ghost">↻ Key</button>
      </form>
      ${p.api_key_hash ? `<form method="POST" action="/admin/publishers/${p.id}/revoke-key" style="display:inline"
            data-confirm="Revoke API key for ${H(p.username)}?">${csrfField(csrfToken)}
        <button class="btn btn-danger">Revoke Key</button>
      </form>` : ''}
      <form method="POST" action="/admin/publishers/${p.id}/toggle" style="display:inline">${csrfField(csrfToken)}
        <button class="btn ${p.status==='active'?'btn-warn':'btn-ghost'}">${p.status==='active'?'Pause':'Activate'}</button>
      </form>
      <form method="POST" action="/admin/publishers/${p.id}/delete" style="display:inline"
            data-confirm="Delete publisher ${H(p.username)}?">${csrfField(csrfToken)}
        <button class="btn btn-danger">Delete</button>
      </form>
    </div></td>
  </tr>`;
  }).join('');

  const body = `${adminHeader(`<a href="/admin/invoices" class="hbtn ghost">Invoices</a>
    <a href="/admin/publishers/new" class="hbtn">+ New Publisher</a>`)}
<main>
${flashHtml(flash)}

${pending.length > 0 ? `
<section style="border:2px solid #f57f17;margin-bottom:20px">
  <div class="sh" style="background:#fffbf0">
    <h2 style="color:#e65100">Pending Applications <span style="background:#f57f17;color:#fff;border-radius:20px;padding:1px 9px;font-size:11px;margin-left:6px">${pending.length}</span></h2>
    <span class="meta">Review and approve or reject each applicant</span>
  </div>
  <table><thead><tr><th>Applicant</th><th>Status</th><th>Applied</th><th>Actions</th></tr></thead>
    <tbody>${pendingRows}</tbody></table>
</section>` : ''}

<section>
  <div class="sh"><h2>Publisher Accounts</h2>
    <div class="sh-r">
      <a href="/admin/invoices" class="btn btn-ghost">All Invoices</a>
      <a href="/admin/publishers/new" class="btn btn-primary">+ New Publisher</a></div>
  </div>
  ${publishers.length===0
    ? '<div class="empty">No publisher accounts yet. <a href="/admin/publishers/new">Create one.</a></div>'
    : `<table><thead><tr><th>Username / Contact</th><th>Status</th><th>Clicks</th><th>Conv</th><th>Payout</th><th>Created</th><th>Actions</th></tr></thead>
        <tbody>${rows}</tbody></table>`}
</section>
</main>`;

  return adminLayout('Publishers', body);
}

// ---------------------------------------------------------------------------
// Invoice list
// ---------------------------------------------------------------------------

function renderInvoiceList({ invoices, flash }) {
  const MONTHS = ['','January','February','March','April','May','June',
                  'July','August','September','October','November','December'];

  const statusBadge = s => ({
    draft: '<span class="badge pending">Draft</span>',
    sent:  '<span class="badge ev">Sent</span>',
    paid:  '<span class="badge approved">Paid</span>',
  }[s] || `<span class="badge">${H(s)}</span>`);

  const invNum = inv => `INV-${inv.year}${String(inv.month).padStart(2,'0')}-${String(inv.id).padStart(4,'0')}`;

  const rows = invoices.map(inv => `<tr>
    <td><code style="font-size:11px">${invNum(inv)}</code></td>
    <td><strong>${H(inv.publisher_name)}</strong></td>
    <td>${MONTHS[inv.month]} ${inv.year}</td>
    <td>$${$(inv.total_amount)} <span style="font-size:10px;color:#9ca3af">USD</span></td>
    <td>${statusBadge(inv.status)}</td>
    <td style="font-size:11px;color:#8e8e93">${H(inv.created_at.slice(0,10))}</td>
    <td>
      <a href="/admin/publishers/${H(inv.publisher_id)}/invoice/${inv.year}/${inv.month}" class="btn btn-ghost">View</a>
    </td>
  </tr>`).join('');

  const body = `${adminHeader('<a href="/admin/publishers" class="hbtn ghost">← Publishers</a>')}
<main>
${flashHtml(flash)}
<section>
  <div class="sh"><h2>Invoices</h2><span class="meta">${invoices.length} total</span></div>
  ${invoices.length === 0
    ? '<div class="empty">No invoices yet. Generate one from the <a href="/admin/publishers">Publishers</a> page.</div>'
    : `<table><thead><tr>
        <th>Invoice #</th><th>Publisher</th><th>Period</th><th>Amount</th><th>Status</th><th>Created</th><th></th>
      </tr></thead><tbody>${rows}</tbody></table>`}
</section>
</main>`;

  return adminLayout('Invoices', body);
}

// ---------------------------------------------------------------------------
// Invoice detail (printable)
// ---------------------------------------------------------------------------

function renderInvoice({ inv, pub, lines, totalsByCurrency = [], flash, csrfToken = '' }) {
  const MONTHS = ['','January','February','March','April','May','June',
                  'July','August','September','October','November','December'];

  const invNum  = `INV-${inv.year}${String(inv.month).padStart(2,'0')}-${String(inv.id).padStart(4,'0')}`;
  const period  = `${MONTHS[inv.month]} ${inv.year}`;

  const statusColor = { draft: '#f57f17', sent: '#1565c0', paid: '#2e7d32' };
  const statusLabel = { draft: 'DRAFT', sent: 'SENT', paid: 'PAID' };
  const nextStatus  = { draft: 'sent', sent: 'paid', paid: 'draft' };
  const nextLabel   = { draft: 'Mark as Sent', sent: 'Mark as Paid', paid: 'Revert to Draft' };

  const lineRows = lines.map(l => `<tr>
    <td style="color:#6e6e73;font-size:11px">${H(l.received_at.slice(0,10))}</td>
    <td>${H(l.adv_name || l.advertiser_slug)}</td>
    <td style="font-size:11px"><span style="background:#e3f2fd;color:#1565c0;padding:2px 6px;border-radius:10px;font-size:10px;font-weight:700;text-transform:uppercase">${H(l.event)}</span></td>
    <td style="font-family:monospace;font-size:11px;color:#6e6e73">${H(l.click_id)}</td>
    <td style="text-align:right;font-weight:600">${fmtCur(l.payout, l.currency)}</td>
  </tr>`).join('');

  const INVOICE_CSS = `
    @media print {
      .no-print { display: none !important; }
      body { background: #fff !important; }
      .inv-card { box-shadow: none !important; }
    }
    .inv-card { background:#fff; max-width:820px; margin:30px auto; padding:48px 56px;
                border-radius:12px; box-shadow:0 2px 16px rgba(0,0,0,.1); font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; }
    .inv-header { display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:40px; }
    .inv-brand { font-size:22px; font-weight:800; color:#1d1d1f; letter-spacing:-.5px; }
    .inv-brand small { display:block; font-size:12px; font-weight:400; color:#6e6e73; margin-top:3px; }
    .inv-meta { text-align:right; }
    .inv-num { font-size:20px; font-weight:700; color:#1d1d1f; }
    .inv-status { display:inline-block; margin-top:6px; padding:3px 12px; border-radius:20px; font-size:11px; font-weight:800; letter-spacing:.8px; }
    .inv-parties { display:grid; grid-template-columns:1fr 1fr; gap:32px; margin-bottom:36px; padding-bottom:28px; border-bottom:1px solid #f0f0f0; }
    .inv-party-label { font-size:10px; font-weight:700; text-transform:uppercase; letter-spacing:.6px; color:#8e8e93; margin-bottom:6px; }
    .inv-party-name { font-size:15px; font-weight:700; color:#1d1d1f; }
    .inv-party-sub { font-size:12px; color:#6e6e73; margin-top:3px; }
    table.inv-lines { width:100%; border-collapse:collapse; margin-bottom:0; }
    table.inv-lines th { background:#f5f5f7; padding:9px 14px; text-align:left; font-size:10px; font-weight:700; text-transform:uppercase; letter-spacing:.5px; color:#6e6e73; border-bottom:2px solid #e8e8ed; }
    table.inv-lines td { padding:10px 14px; border-bottom:1px solid #f5f5f7; font-size:13px; vertical-align:middle; }
    table.inv-lines tr:last-child td { border-bottom:none; }
    .inv-total-row { display:flex; justify-content:flex-end; padding:16px 14px 0; border-top:2px solid #1d1d1f; margin-top:2px; }
    .inv-total-label { font-size:14px; font-weight:700; margin-right:48px; }
    .inv-total-val { font-size:22px; font-weight:800; color:#2e7d32; }
    .inv-notes { margin-top:32px; padding-top:24px; border-top:1px solid #f0f0f0; font-size:12px; color:#6e6e73; white-space:pre-wrap; }
    .inv-empty { text-align:center; padding:36px; color:#8e8e93; font-size:13px; }
  `;

  const adminControls = `
<div class="no-print" style="max-width:820px;margin:16px auto 0;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
  ${flashHtml(flash)}
  <form method="POST" action="/admin/invoices/${H(inv.id)}/status" style="display:inline">${csrfField(csrfToken)}
    <input type="hidden" name="status" value="${H(nextStatus[inv.status] || 'draft')}">
    <button class="btn btn-primary btn-lg">${H(nextLabel[inv.status] || 'Update Status')}</button>
  </form>
  <form method="POST" action="/admin/publishers/${H(pub.id)}/invoice/${inv.year}/${inv.month}/regenerate" style="display:inline">${csrfField(csrfToken)}
    <button class="btn btn-ghost btn-lg">↻ Recalculate</button>
  </form>
  <button class="btn btn-ghost btn-lg" data-print>Print / Save PDF</button>
  <a href="/admin/invoices" class="btn btn-ghost btn-lg">← All Invoices</a>
</div>
<div class="no-print" style="max-width:820px;margin:12px auto 0">
  <form method="POST" action="/admin/publishers/${H(pub.id)}/invoice/${inv.year}/${inv.month}/notes" style="display:flex;gap:8px;align-items:flex-start">${csrfField(csrfToken)}
    <textarea name="notes" rows="2" placeholder="Notes (payment terms, bank details, etc.) — visible on invoice"
              style="flex:1;padding:8px 10px;border:1px solid #d2d2d7;border-radius:7px;font-size:12px;resize:vertical">${H(inv.notes)}</textarea>
    <button type="submit" class="btn btn-ghost">Save Notes</button>
  </form>
</div>`;

  const body = `
<style>${INVOICE_CSS}</style>
${adminControls}

<div class="inv-card">

  <div class="inv-header">
    <div>
      <div class="inv-brand">Komorebi Media<small>Affiliate Network</small></div>
    </div>
    <div class="inv-meta">
      <div class="inv-num">${H(invNum)}</div>
      <div class="inv-status" style="background:${statusColor[inv.status] || '#6e6e73'}22;color:${statusColor[inv.status] || '#6e6e73'}">${H(statusLabel[inv.status] || inv.status.toUpperCase())}</div>
      <div style="font-size:12px;color:#6e6e73;margin-top:8px">Period: <strong>${H(period)}</strong></div>
      <div style="font-size:11px;color:#aaa;margin-top:3px">Generated ${H(inv.created_at.slice(0,10))}</div>
    </div>
  </div>

  <div class="inv-parties">
    <div>
      <div class="inv-party-label">From</div>
      <div class="inv-party-name">Komorebi Media</div>
      <div class="inv-party-sub">chi@komorebimedia.com</div>
    </div>
    <div>
      <div class="inv-party-label">Publisher</div>
      <div class="inv-party-name">${H(pub.username)}</div>
      <div class="inv-party-sub">Invoice for approved conversions · ${H(period)}</div>
    </div>
  </div>

  ${lines.length === 0
    ? `<div class="inv-empty">No approved conversions recorded for ${H(period)}.</div>`
    : `<table class="inv-lines">
        <thead><tr>
          <th>Date</th><th>Advertiser</th><th>Event</th><th>Click ID</th><th style="text-align:right">Payout</th>
        </tr></thead>
        <tbody>${lineRows}</tbody>
      </table>
      <div class="inv-total-row">
        <span class="inv-total-label">Total Due</span>
        <span class="inv-total-val">${(totalsByCurrency.length ? totalsByCurrency : [{currency:'USD',total:0}]).map(t => fmtCur(t.total, t.currency)).join(' &nbsp;·&nbsp; ')}</span>
      </div>`}

  ${inv.notes ? `<div class="inv-notes">${H(inv.notes)}</div>` : ''}

</div>`;

  return adminLayout(`Invoice ${invNum}`, body);
}

function renderPaymentsPage({ pub, payments, totalPaid, approvedBalance, approvedByCurrency = [], flash, csrfToken = '' }) {
  const methods  = ['Wire Transfer', 'PayPal', 'USDT', 'Bank Transfer', 'Other'];
  const minPay   = pub.minimum_payout ?? 50;
  const balance  = approvedBalance - totalPaid;
  const rows     = payments.map(p => `<tr>
    <td>${H(p.paid_at)}</td>
    <td><strong style="color:#0F6E56">$${$(p.amount_usd)}</strong> <span style="font-size:11px;color:#6e6e73">(${vnd(p.amount_usd)})</span></td>
    <td>${H(p.method)}</td>
    <td style="font-size:11px;color:#6e6e73">${H(p.notes)}</td>
  </tr>`).join('');

  const body = `${adminHeader(`<a href="/admin/publishers/${H(pub.id)}/edit" class="hbtn ghost">Edit Publisher</a>
    <a href="/admin/publishers" class="hbtn ghost">← Publishers</a>`)}
<main>
${flash ? `<div class="flash ${flash.type}">${H(flash.text)}</div>` : ''}

<div class="cards" style="margin-bottom:20px">
  <div class="card"><div class="lbl">Publisher</div><div class="val" style="font-size:18px">${H(pub.username)}</div></div>
  <div class="card"><div class="lbl">Approved Earnings</div><div class="val green" style="font-size:18px">${fmtByCurrency(approvedByCurrency)}</div></div>
  <div class="card"><div class="lbl">Total Paid Out (USD)</div><div class="val">$${$(totalPaid)}</div></div>
  <div class="card"><div class="lbl">Outstanding Balance</div><div class="val ${balance>0?'green':''}" style="${balance<0?'color:#c62828':''}">$${$(balance)}</div></div>
  <div class="card"><div class="lbl">Minimum Payout</div><div class="val" style="font-size:18px">$${$(minPay)}</div></div>
</div>

<section style="margin-bottom:20px">
  <div class="sh"><h2>Record New Payment</h2></div>
  <div style="padding:20px 24px">
    <form method="POST" action="/admin/publishers/${H(pub.id)}/payments"
          style="display:grid;grid-template-columns:130px 160px 1fr 1fr auto;gap:10px;align-items:end">${csrfField(csrfToken)}
      <div class="fg" style="margin:0">
        <label>Date *</label>
        <input type="date" name="paid_at" value="${new Date().toISOString().slice(0,10)}" required>
      </div>
      <div class="fg" style="margin:0">
        <label>Amount (USD) *</label>
        <input type="number" name="amount_usd" step="0.01" min="0.01" placeholder="e.g. 150.00" required>
      </div>
      <div class="fg" style="margin:0">
        <label>Method</label>
        <select name="method">
          ${methods.map(m => `<option>${m}</option>`).join('')}
        </select>
      </div>
      <div class="fg" style="margin:0">
        <label>Notes</label>
        <input type="text" name="notes" placeholder="Transaction ID, reference, etc.">
      </div>
      <button type="submit" class="btn btn-primary btn-lg" style="white-space:nowrap">Record Payment</button>
    </form>
  </div>
</section>

<section>
  <div class="sh">
    <h2>Payment History — ${H(pub.username)}</h2>
    ${payments.length > 0 ? `<span class="meta">Total: <strong>$${$(totalPaid)}</strong> (${vnd(totalPaid)})</span>` : ''}
  </div>
  ${payments.length === 0
    ? '<div class="empty">No payments recorded yet.</div>'
    : `<table><thead><tr><th>Date Paid</th><th>Amount</th><th>Method</th><th>Notes</th></tr></thead>
        <tbody>${rows}</tbody></table>`}
</section>
</main>`;

  return adminLayout(`Payments — ${pub.username}`, body);
}

function renderSmartLinks({ pub, rules, advertisers, csrfToken = '', flash, error }) {
  const smartUrl = `${publisherBase(pub)}/go/${encodeURIComponent(pub.username)}`;
  const ruleRows = rules.map(r => `<tr>
    <td>${r.priority}</td>
    <td><strong>${H(r.adv_name)}</strong> <span style="color:#8e8e93;font-size:11px">${H(r.adv_slug)}</span></td>
    <td>${H(r.country)}</td>
    <td>${H(r.device_type)}</td>
    <td><form method="POST" action="/admin/publishers/${H(pub.id)}/smart-links/${H(r.id)}/delete" style="display:inline"
          data-confirm="Delete this rule?">${csrfField(csrfToken)}
          <button class="btn btn-danger">Delete</button></form></td>
  </tr>`).join('');

  const body = `${adminHeader('<a href="/admin/publishers" class="hbtn ghost">← Publishers</a>')}
<main><div class="fw">
  <h2>Smart Links — ${H(pub.username)}</h2>
  ${flash ? `<div class="flash success">${H(flash)}</div>` : ''}
  ${error ? `<div class="form-err">${H(error)}</div>` : ''}
  <p style="font-size:12px;color:#6e6e73;margin-bottom:8px">Smart link (geo/device routed):</p>
  <div class="ubox" data-copy="${H(smartUrl)}" style="margin-bottom:20px">${H(smartUrl)}</div>
  <p style="font-size:12px;color:#6e6e73;margin-bottom:12px">Rules are evaluated by priority (lowest number first). <code>*</code> matches any country/device. Country accepts comma-separated ISO codes (e.g. <code>VN,TH</code>). If no rule matches, traffic falls back to the publisher's first active assigned advertiser.</p>
  ${rules.length === 0 ? '<div class="empty" style="margin-bottom:14px">No rules yet — all traffic uses the fallback advertiser.</div>' : `
  <table style="margin-bottom:16px"><thead><tr><th>Priority</th><th>Advertiser</th><th>Country</th><th>Device</th><th></th></tr></thead>
    <tbody>${ruleRows}</tbody></table>`}
  <form method="POST" action="/admin/publishers/${H(pub.id)}/smart-links"
        style="display:grid;grid-template-columns:2fr 1.2fr 1fr .8fr auto;gap:8px;align-items:end;background:#f5f5f7;padding:14px;border-radius:10px">${csrfField(csrfToken)}
    <div class="fg" style="margin:0"><label>Advertiser</label>
      <select name="advertiser_id" required>${advertisers.map(a => `<option value="${H(a.id)}">${H(a.name)}</option>`).join('')}</select></div>
    <div class="fg" style="margin:0"><label>Country (ISO, comma, or *)</label><input type="text" name="country" value="*" placeholder="* or VN,TH"></div>
    <div class="fg" style="margin:0"><label>Device</label>
      <select name="device_type"><option value="*">Any</option><option value="mobile">Mobile</option><option value="desktop">Desktop</option><option value="tablet">Tablet</option></select></div>
    <div class="fg" style="margin:0"><label>Priority</label><input type="number" name="priority" value="100" step="1"></div>
    <button type="submit" class="btn btn-primary">Add Rule</button>
  </form>
  <div style="margin-top:20px"><a href="/admin/publishers/${H(pub.id)}/edit" class="btn btn-ghost">← Back to publisher</a></div>
</div></main>
<script>${CP_JS}</script>`;
  return adminLayout(`Smart Links — ${pub.username}`, body);
}

function renderMarketplace({ campaigns, loggedIn, assignedIds, pendingIds, flash }) {
  const cards = campaigns.map(a => {
    const assigned = assignedIds.has(a.id);
    const pending  = pendingIds.has(a.id);
    const payoutBig  = a.payout_type === 'percent' ? `${H(a.payout_amount)}%` : `$${$(a.payout_amount)}`;
    const payoutUnit = a.payout_type === 'percent' ? 'of loan amount' : 'per conversion';
    const action = assigned
      ? `<button class="campaign-apply" disabled>✓ Already running</button>`
      : pending
        ? `<button class="campaign-apply" disabled>Application pending</button>`
        : `<form method="POST" action="/marketplace/apply" style="margin:0">
             <input type="hidden" name="advertiser_id" value="${H(a.id)}">
             <button type="submit" class="campaign-apply">Apply to Campaign${loggedIn ? '' : ' — log in'}</button>
           </form>`;
    return `<div class="campaign-card">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:8px">
        <div>
          <div style="font-size:14px;font-weight:600">${H(a.name)}</div>
          <div class="campaign-payout" style="margin-top:4px">${payoutBig}</div>
          <div style="font-size:10px;color:#9ca3af">${payoutUnit}</div>
        </div>
        <div class="campaign-badge">${H(a.category || 'CPA')}</div>
      </div>
      ${a.description ? `<div class="campaign-desc">${H(a.description)}</div>` : '<div style="margin:12px 0"></div>'}
      <div style="font-size:11px;color:#6b7280;margin-bottom:12px">Countries: ${a.countries_allowed ? H(a.countries_allowed) : 'All'}</div>
      ${action}
    </div>`;
  }).join('');

  const body = `
<main style="max-width:1000px;margin:0 auto;padding:24px 20px">
  <h1 style="font-size:22px;margin-bottom:4px">Affiliate Marketplace</h1>
  <p style="color:#6e6e73;font-size:13px;margin-bottom:20px">Browse available campaigns and apply to run them.${loggedIn ? '' : ' <a href="/publisher/login?next=%2Fmarketplace">Log in</a> to apply.'}</p>
  ${flash ? `<div class="login-ok mp-flash" style="margin-bottom:16px">${H(flash)}</div>` : ''}
  ${campaigns.length === 0
    ? '<div class="empty">No public campaigns available right now.</div>'
    : `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:16px">${cards}</div>`}
  <div style="margin-top:24px"><a href="${loggedIn ? '/publisher/dashboard' : '/publisher/login'}" class="btn btn-ghost">← ${loggedIn ? 'Dashboard' : 'Publisher login'}</a></div>
</main>
<script>document.addEventListener('DOMContentLoaded',function(){
  // Stash a toast message when an Apply form is submitted; shown after the redirect.
  document.querySelectorAll('form[action="/marketplace/apply"]').forEach(function(f){
    f.addEventListener('submit',function(){ try{ localStorage.setItem('mp_toast','Application submitted — pending review'); }catch(e){} });
  });
  // Consume any stashed toast on load (and hide the duplicate server banner).
  try {
    var m = localStorage.getItem('mp_toast');
    if (m) { localStorage.removeItem('mp_toast'); showToast(m,'success');
      var fl = document.querySelector('.mp-flash'); if (fl) fl.style.display='none'; }
  } catch(e){}
});</script>`;
  return pubLayout('Marketplace', body);
}

function renderAdminMarketplace({ pending, csrfToken = '', flash }) {
  const rows = pending.map(p => `<tr>
    <td>${H((p.applied_at||'').slice(0,16))}</td>
    <td><code>${H(p.username)}</code></td>
    <td><strong>${H(p.adv_name)}</strong> <span style="color:#8e8e93;font-size:11px">${H(p.adv_slug)}</span></td>
    <td>${N(p.active_publishers || 0)}</td>
    <td>$${$(p.total_paid || 0)}</td>
    <td>${p.approval_rate == null ? '—%' : p.approval_rate.toFixed(1) + '%'}</td>
    <td><div class="act">
      <form method="POST" action="/admin/marketplace/${H(p.id)}/approve" style="display:inline">${csrfField(csrfToken)}
        <button class="btn btn-primary">Approve</button></form>
      <form method="POST" action="/admin/marketplace/${H(p.id)}/reject" style="display:inline"
            data-confirm="Reject ${H(p.username)} → ${H(p.adv_name)}?">${csrfField(csrfToken)}
        <button class="btn btn-danger">Reject</button></form>
    </div></td>
  </tr>`).join('');

  const body = `${adminHeader('<a href="/admin/publishers" class="hbtn ghost">← Publishers</a>')}
<main>
  <section>
    <div class="sh"><h2>Marketplace Applications</h2><span class="meta">${pending.length} pending</span></div>
    ${flash ? `<div class="flash success">${H(flash)}</div>` : ''}
    <p style="font-size:11px;color:#8e8e93;margin:0 0 10px">Per-advertiser stats (active publishers / total approved payout / approval rate) are aggregate figures shown to help your decision.</p>
    ${pending.length === 0
      ? '<div class="empty">No pending applications.</div>'
      : `<table><thead><tr><th>Applied</th><th>Publisher</th><th>Campaign</th><th>Active Pubs</th><th>Total Paid</th><th>Approval</th><th>Actions</th></tr></thead><tbody>${rows}</tbody></table>`}
  </section>
</main>`;
  return adminLayout('Marketplace Applications', body);
}

function renderPubForm({ title, action, pub = {}, error, flash, csrfToken = '',
  assignments = [], allAdvertisers = [], resetLink = null, newApiKey = null }) {
  const isEdit = action.includes('/update');
  const keySuffix = pub.api_key_suffix || (pub.api_key ? pub.api_key.slice(-8) : null);
  const statusOpts = ['active','paused'].map(s =>
    `<option value="${s}" ${(pub.status||'active')===s?'selected':''}>${s[0].toUpperCase()+s.slice(1)}</option>`
  ).join('');

  const assignedIds = new Set(assignments.map(a => a.advertiser_id));
  const unassigned  = allAdvertisers.filter(a => !assignedIds.has(a.id));

  const assignmentSection = !isEdit ? '' : `
  <div style="margin-top:28px">
    <h2 style="font-size:16px;margin-bottom:4px">Advertiser Assignments</h2>
    <p style="font-size:12px;color:#6e6e73;margin-bottom:12px">This publisher only sees assigned advertisers, and postbacks are only accepted for these pairs. Optional: override the payout (otherwise the goal/advertiser default applies), restrict to a date window, or cap conversions per calendar month — postbacks outside the window or over the cap are rejected.</p>
    ${assignments.length === 0 ? '<div class="empty" style="margin-bottom:14px">No advertisers assigned yet.</div>' : `
    <table style="margin-bottom:16px"><thead><tr>
      <th>Advertiser</th><th>Payout Override</th><th>Valid From</th><th>Valid Until</th><th>Monthly Cap</th><th></th>
    </tr></thead><tbody>
    ${assignments.map(a => `<tr>
      <td><strong>${H(a.name)}</strong> <span style="color:#8e8e93;font-size:11px">${H(a.slug)}</span></td>
      <td>${a.payout_override != null ? '$'+$(a.payout_override) : '<span style="color:#8e8e93">default</span>'}</td>
      <td>${H(a.valid_from || '—')}</td>
      <td>${H(a.valid_until || '—')}</td>
      <td>${a.monthly_cap != null ? N(a.monthly_cap) : '—'}</td>
      <td><form method="POST" action="/admin/publishers/${H(pub.id)}/unassign" style="display:inline"
            data-confirm="Unassign ${H(a.name)} from ${H(pub.username)}?">${csrfField(csrfToken)}
            <input type="hidden" name="advertiser_id" value="${H(a.advertiser_id)}">
            <button class="btn btn-danger">Unassign</button></form></td>
    </tr>`).join('')}
    </tbody></table>`}
    ${unassigned.length === 0 ? '<p style="font-size:12px;color:#8e8e93">All advertisers are assigned.</p>' : `
    <form method="POST" action="/admin/publishers/${H(pub.id)}/assign"
          style="display:grid;grid-template-columns:1.5fr 1fr 1fr 1fr 1fr auto;gap:8px;align-items:end;background:#f5f5f7;padding:14px;border-radius:10px">${csrfField(csrfToken)}
      <div class="fg" style="margin:0"><label>Advertiser</label>
        <select name="advertiser_id" required>${unassigned.map(a => `<option value="${H(a.id)}">${H(a.name)}</option>`).join('')}</select></div>
      <div class="fg" style="margin:0"><label>Payout Override ($)</label>
        <input type="number" name="payout_override" step="0.01" min="0" placeholder="default"></div>
      <div class="fg" style="margin:0"><label>Valid From</label><input type="date" name="valid_from"></div>
      <div class="fg" style="margin:0"><label>Valid Until</label><input type="date" name="valid_until"></div>
      <div class="fg" style="margin:0"><label>Monthly Cap</label><input type="number" name="monthly_cap" min="0" placeholder="none"></div>
      <button type="submit" class="btn btn-primary">Assign</button>
    </form>`}
  </div>`;

  const resetSection = !isEdit ? '' : `
  <div style="margin-top:28px">
    <h2 style="font-size:16px;margin-bottom:4px">Password Reset</h2>
    <p style="font-size:12px;color:#6e6e73;margin-bottom:12px">Set a new password using the field above, or generate a 24-hour self-service reset link to share with the publisher (useful when email isn't configured).</p>
    ${resetLink ? `<div style="background:#fff8e1;border:1px solid #ffc107;border-radius:8px;padding:12px 14px;margin-bottom:12px">
      <div style="font-size:12px;font-weight:600;margin-bottom:6px">Active reset link — expires ${H(resetLink.expires)} UTC:</div>
      <div class="ubox" data-copy="${H(resetLink.url)}" style="font-size:11px;word-break:break-all">${H(resetLink.url)}</div>
    </div>` : ''}
    <form method="POST" action="/admin/publishers/${H(pub.id)}/reset-link" style="display:inline">${csrfField(csrfToken)}
      <button class="btn btn-ghost">Generate reset link</button>
    </form>
  </div>`;

  const body = `${adminHeader('<a href="/admin/publishers" class="hbtn ghost">← Publishers</a>')}
<main><div class="fw">
  <h2>${H(title)}</h2>
  ${flash   ? `<div class="flash success">${H(flash.text)}</div>` : ''}
  ${error   ? `<div class="form-err">${H(error)}</div>` : ''}
  <form method="POST" action="${H(action)}">${csrfField(csrfToken)}
    ${isEdit
      ? `<div class="fg"><label>Username</label>
          <input type="text" value="${H(pub.username||'')}" disabled style="background:#f5f5f7;color:#6e6e73">
          <small>Username cannot be changed. It is used as the <code>pub=</code> identifier in tracking URLs.</small></div>`
      : `<div class="fg"><label>Username *</label>
          <input type="text" name="username" value="${H(pub.username||'')}" required
                 pattern="[a-z0-9_-]+" placeholder="e.g. clickon, partner-xyz" autocomplete="off">
          <small>Lowercase letters, numbers, hyphens, underscores. This becomes their tracking ID.</small></div>`}
    <div class="fg"><label>${isEdit ? 'New Password' : 'Password *'}</label>
      <input type="password" name="password" ${isEdit?'':'required'} minlength="8"
             placeholder="${isEdit?'Leave blank to keep current password':'Min. 8 characters'}" autocomplete="new-password">
      ${isEdit?'<small>Leave blank to keep the current password.</small>':''}</div>
    <div class="fg"><label>Status</label><select name="status">${statusOpts}</select></div>
    <div class="fg"><label>Minimum Payout (USD)</label>
      <input type="number" name="minimum_payout" value="${H(pub.minimum_payout ?? 50)}" step="0.01" min="0" style="max-width:160px">
      <small>Publisher cannot request payment until approved balance reaches this threshold.</small>
    </div>
    <div class="fg"><label>S2S Postback URL</label>
      <input type="text" name="postback_url" value="${H(pub.postback_url||'')}"
             placeholder="https://partner.com/postback?cid={click_id}&payout={payout}&event={event}">
      <small>Macros: <code>{click_id}</code> <code>{payout}</code> <code>{event}</code> <code>{advertiser}</code> — fired on every conversion. Up to 3 attempts with 5-min retry on failure.</small>
    </div>
    <div class="fg"><label>Custom Tracking Domain <span style="font-size:11px;color:#6e6e73">(Backlog #12)</span></label>
      <input type="text" name="custom_domain" value="${H(pub.custom_domain||'')}" placeholder="e.g. go.partner.com (blank = platform default)">
      <small>Branded domain for this publisher's tracking links. Point a CNAME at the Komorebi host; links are generated against it (e.g. <code>https://${H(pub.custom_domain||'go.partner.com')}/track/SLUG?pub=${H(pub.username||'PUB')}</code>). Enter the bare host, no scheme or path.</small>
    </div>
    ${isEdit ? `<div class="fg"><label>API Key</label>
      ${newApiKey ? `<div style="background:#fff8e1;border:1px solid #ffc107;border-radius:8px;padding:10px 12px;margin-bottom:8px">
            <div style="font-size:11px;font-weight:600;margin-bottom:6px">New API key — copy it now; it will not be shown again.</div>
            <div style="display:flex;gap:8px;align-items:center">
              <input type="text" id="newKeyInput" value="${H(newApiKey)}" readonly
                     style="font-family:monospace;font-size:12px;flex:1;background:#fff;color:#1d1d1f">
              <button type="button" class="btn btn-ghost" data-copy="${H(newApiKey)}">Copy</button>
            </div>
          </div>` : ''}
      ${pub.api_key_hash
        ? `${newApiKey ? '' : `<div style="display:flex;gap:8px;align-items:center;margin-bottom:8px">
            <input type="text" value="••••••••••• (saved)" readonly disabled
                   style="font-family:monospace;font-size:12px;flex:1;background:#f5f5f7;color:#6e6e73">
            ${keySuffix ? `<code style="font-size:11px;color:#2e7d32">…${H(keySuffix)}</code>` : ''}
          </div>`}
          <div style="display:flex;gap:8px">
            <form method="POST" action="/admin/publishers/${H(pub.id)}/regenerate-key" style="display:inline"
                  data-confirm="Regenerate API key? The current key stops working immediately.">${csrfField(csrfToken)}
              <button class="btn btn-warn">↻ Regenerate Key</button>
            </form>
            <form method="POST" action="/admin/publishers/${H(pub.id)}/revoke-key" style="display:inline"
                  data-confirm="Revoke this API key? The publisher will lose API access until a new key is generated.">${csrfField(csrfToken)}
              <button class="btn btn-danger">Revoke Key</button>
            </form>
          </div>`
        : `<div style="color:#c62828;font-size:13px;margin-bottom:8px">API key is revoked — publisher cannot use key auth.</div>
           <form method="POST" action="/admin/publishers/${H(pub.id)}/regenerate-key" style="display:inline">${csrfField(csrfToken)}
             <button class="btn btn-primary">Generate New Key</button>
           </form>`}
      <small style="display:block;margin-top:8px">The full key is shown only once, at generation. Only the last 8 characters are stored for reference. Use <code>X-API-Key: kom_live_...</code> for REST API access.</small>
    </div>` : ''}
    ${isEdit ? `<div class="fg"><label>Their Tracking URLs</label>
      <small style="display:block;margin-bottom:8px">One link per active advertiser — pre-filled with their username.</small>
      ${db.prepare("SELECT slug,name FROM advertisers WHERE status='active' AND slug!='legacy' ORDER BY name").all()
        .map(a => {
          const url = `${publisherBase(pub)}/track/${a.slug}?pub=${encodeURIComponent(pub.username||'')}`;
          return `<div style="margin-bottom:6px">
            <div style="font-size:10px;color:#6e6e73;margin-bottom:2px">${H(a.name)}</div>
            <div class="ubox" data-copy="${H(url)}">${H(url)}</div>
          </div>`;
        }).join('')}
    </div>` : ''}
    <div class="form-act">
      <button type="submit" class="btn btn-primary btn-lg">${isEdit?'Save Changes':'Create Publisher'}</button>
      ${isEdit ? `<a href="/admin/publishers/${H(pub.id)}/payments" class="btn btn-ghost btn-lg">Payment History</a>` : ''}
      ${isEdit ? `<a href="/admin/publishers/${H(pub.id)}/smart-links" class="btn btn-ghost btn-lg">Smart Links</a>` : ''}
      <a href="/admin/publishers" class="btn btn-ghost btn-lg">Cancel</a>
    </div>
  </form>
  ${assignmentSection}
  ${resetSection}
</div></main>
<script>${CP_JS}</script>`;

  return adminLayout(title, body);
}

function renderAuditLog({ logs, actions, filters }) {
  const ACTION_COLOR = {
    'admin.login.failed':     'rejected',
    'admin.login.success':    'active',
    'advertiser.deleted':     'rejected',
    'publisher.deleted':      'rejected',
    'reconciliation.uploaded':'ev',
    'settings.changed':       'ev',
    's2s_postback.updated':   'ev',
  };
  const actionColor = a => ACTION_COLOR[a] || (a.endsWith('.created') ? 'approved' : a.endsWith('.toggled') ? 'pending' : '');

  const actionOpts = ['', ...actions].map(a =>
    `<option value="${H(a)}" ${filters.action === a ? 'selected' : ''}>${a || 'All actions'}</option>`
  ).join('');

  const rows = logs.map(l => {
    let detail = '';
    try {
      const d = JSON.parse(l.detail || '{}');
      detail = Object.entries(d)
        .filter(([, v]) => v !== null && v !== '' && v !== false)
        .map(([k, v]) => `<span style="color:#6e6e73">${H(k)}:</span> ${H(String(v))}`)
        .join(' &nbsp;·&nbsp; ');
    } catch { detail = H(l.detail || ''); }

    const rowTz    = validTz(l.timezone) || FALLBACK_TZ;
    const localTs  = formatInTz(l.created_at, rowTz);
    return `<tr>
      <td style="white-space:nowrap;font-size:11px;color:#6e6e73">
        ${H(localTs)}
        <div style="font-size:9px;color:#aaa;margin-top:2px">${H(rowTz)}</div>
      </td>
      <td><span class="badge ${actionColor(l.action)}" style="white-space:nowrap">${H(l.action)}</span></td>
      <td style="font-size:12px">${H(l.entity_type || '')}</td>
      <td><code style="font-size:11px">${H(l.entity_id || '')}</code></td>
      <td style="font-size:11px;max-width:380px">${detail}</td>
      <td style="font-size:11px;font-family:monospace;color:#8e8e93">${H(l.ip_address || '')}</td>
    </tr>`;
  }).join('');

  const body = `${adminHeader()}
<main>
<section>
  <div class="sh"><h2>Audit Log</h2>
    <span class="meta">Last 500 entries · ${logs.length} shown</span>
  </div>
  <div style="padding:14px 20px;background:#fafafa;border-bottom:1px solid #f0f0f0">
    <form method="GET" action="/admin/audit-log"
          style="display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap">
      <div>
        <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.4px;color:#6e6e73;margin-bottom:4px">Action</div>
        <select name="action" style="padding:7px 10px;border:1px solid #d2d2d7;border-radius:7px;font-size:12px;background:#fff">
          ${actionOpts}
        </select>
      </div>
      <div>
        <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.4px;color:#6e6e73;margin-bottom:4px">From</div>
        <input type="date" name="from" value="${H(filters.from)}"
               style="padding:7px 10px;border:1px solid #d2d2d7;border-radius:7px;font-size:12px">
      </div>
      <div>
        <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.4px;color:#6e6e73;margin-bottom:4px">To</div>
        <input type="date" name="to" value="${H(filters.to)}"
               style="padding:7px 10px;border:1px solid #d2d2d7;border-radius:7px;font-size:12px">
      </div>
      <button type="submit" class="btn btn-primary">Filter</button>
      <a href="/admin/audit-log" class="btn btn-ghost">Clear</a>
    </form>
  </div>
  ${logs.length === 0
    ? '<div class="empty">No audit entries match the current filter.</div>'
    : `<table><thead><tr>
        <th>Timestamp</th><th>Action</th><th>Entity</th><th>ID</th><th>Detail</th><th>IP</th>
      </tr></thead><tbody>${rows}</tbody></table>`}
</section>
</main>`;

  return adminLayout('Audit Log', body);
}

function renderSettingsPage({ flash, csrfToken = '' }) {
  const emailOn      = getSetting('email_notifications')   === 'true';
  const summaryOn    = getSetting('daily_summary')         === 'true';
  const webhookOn    = getSetting('webhook_notifications') === 'true';
  const webhookSumOn = getSetting('webhook_daily_summary') === 'true';
  const gmailOk      = !!(GMAIL_USER && GMAIL_PASS);
  const tgOk         = telegramOk();
  const slOk         = slackOk();

  const dot  = ok => `<span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:${ok?'#2e7d32':'#c62828'}"></span>`;
  const pill = (ok, yes, no) => `<span style="font-size:13px;font-weight:600">${ok ? yes : no}</span>`;

  const toggle = (name, checked, label, hint) => `
    <label style="display:flex;align-items:center;gap:12px;cursor:pointer;padding:14px 0;border-bottom:1px solid #f0f0f0">
      <div style="position:relative;display:inline-block;width:42px;height:24px;flex-shrink:0">
        <input type="checkbox" name="${name}" ${checked ? 'checked' : ''} data-autosubmit
               style="opacity:0;width:0;height:0;position:absolute">
        <span style="position:absolute;inset:0;background:${checked ? '#0071e3' : '#d2d2d7'};border-radius:24px;transition:.2s"></span>
        <span style="position:absolute;top:3px;left:${checked ? '21px' : '3px'};width:18px;height:18px;background:#fff;border-radius:50%;transition:.2s"></span>
      </div>
      <div>
        <div style="font-size:14px;font-weight:600">${label}</div>
        <div style="font-size:12px;color:#6e6e73;margin-top:2px">${hint}</div>
      </div>
    </label>`;

  const body = `${adminHeader()}
<main><div class="fw" style="max-width:600px">
  <h2>Settings</h2>
  ${flashHtml(flash)}

  <section style="margin-bottom:24px">
    <div class="sh"><h2>Gmail Configuration</h2></div>
    <div style="padding:16px 20px">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px">
        ${dot(gmailOk)} ${pill(gmailOk, 'Configured', 'Not configured')}
        ${gmailOk ? `<span style="font-size:12px;color:#6e6e73">Sending as ${GMAIL_USER} → ${ADMIN_EMAIL}</span>` : ''}
      </div>
      ${!gmailOk ? `<div style="background:#fff8e1;border-radius:8px;padding:12px 14px;font-size:12px;color:#f57f17;margin-bottom:12px">
        Set <code>GMAIL_USER</code> and <code>GMAIL_PASS</code> environment variables to enable email.<br>
        Use a Gmail App Password — generate one at
        <a href="https://myaccount.google.com/apppasswords" target="_blank" rel="noopener noreferrer" style="color:#0071e3">myaccount.google.com/apppasswords</a>.
      </div>` : ''}
      <form method="POST" action="/admin/settings/test-email" style="display:inline">${csrfField(csrfToken)}
        <button class="btn btn-ghost" ${!gmailOk ? 'disabled' : ''}>Send Test Email</button>
      </form>
    </div>
  </section>

  <section style="margin-bottom:24px">
    <div class="sh"><h2>Telegram</h2></div>
    <div style="padding:16px 20px">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px">
        ${dot(tgOk)} ${pill(tgOk, 'Configured', 'Not configured')}
        ${tgOk ? `<span style="font-size:12px;color:#6e6e73">Chat ID: <code>${TELEGRAM_CHAT}</code></span>` : ''}
      </div>
      ${!tgOk ? `<div style="background:#fff8e1;border-radius:8px;padding:12px 14px;font-size:12px;color:#f57f17;margin-bottom:12px">
        Set <code>TELEGRAM_BOT_TOKEN</code> and <code>TELEGRAM_CHAT_ID</code> environment variables.<br>
        Create a bot via <a href="https://t.me/BotFather" target="_blank" rel="noopener noreferrer" style="color:#0071e3">@BotFather</a>, then add it to your channel and get the chat ID.
      </div>` : ''}
      <form method="POST" action="/admin/settings/test-telegram" style="display:inline">${csrfField(csrfToken)}
        <button class="btn btn-ghost" ${!tgOk ? 'disabled' : ''}>Send Test Message</button>
      </form>
    </div>
  </section>

  <section style="margin-bottom:24px">
    <div class="sh"><h2>Slack</h2></div>
    <div style="padding:16px 20px">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px">
        ${dot(slOk)} ${pill(slOk, 'Configured', 'Not configured')}
        ${slOk ? `<span style="font-size:12px;color:#6e6e73">Webhook URL configured</span>` : ''}
      </div>
      ${!slOk ? `<div style="background:#fff8e1;border-radius:8px;padding:12px 14px;font-size:12px;color:#f57f17;margin-bottom:12px">
        Set <code>SLACK_WEBHOOK_URL</code> environment variable.<br>
        Create an Incoming Webhook at your Slack workspace app settings.
      </div>` : ''}
      <form method="POST" action="/admin/settings/test-slack" style="display:inline">${csrfField(csrfToken)}
        <button class="btn btn-ghost" ${!slOk ? 'disabled' : ''}>Send Test Message</button>
      </form>
    </div>
  </section>

  <section>
    <div class="sh"><h2>Notification Preferences</h2></div>
    <div style="padding:0 20px">
      <form method="POST" action="/admin/settings" id="settings-form">${csrfField(csrfToken)}
        ${toggle('email_notifications', emailOn,
          'Per-conversion email',
          `Send an email to ${ADMIN_EMAIL} whenever a new conversion is recorded`)}
        ${toggle('daily_summary', summaryOn,
          'Daily summary email',
          'Sent at 8:00 AM Singapore time with the previous day\'s totals, by advertiser and publisher')}
        ${toggle('webhook_notifications', webhookOn,
          'Per-conversion webhook',
          'Send a Telegram/Slack message whenever a new conversion is recorded (requires webhook configured above)')}
        ${toggle('webhook_daily_summary', webhookSumOn,
          'Daily summary webhook',
          'Send daily totals at 8:00 AM Singapore time via Telegram/Slack')}
        <div style="padding:16px 0">
          <button type="submit" class="btn btn-primary btn-lg">Save Settings</button>
          <span style="font-size:12px;color:#6e6e73;margin-left:12px">Toggles auto-save — clicking a toggle saves immediately</span>
        </div>
      </form>
    </div>
  </section>

  <section style="margin-bottom:24px">
    <div class="sh"><h2>Change Admin Password</h2></div>
    <div style="padding:16px 20px">
      <form method="POST" action="/admin/settings/password" style="max-width:340px">
        <input type="hidden" name="_csrf" value="${H(csrfToken)}">
        <div style="margin-bottom:14px">
          <label style="display:block;font-size:13px;font-weight:600;margin-bottom:5px">Current Password</label>
          <input type="password" name="current_password" required autocomplete="current-password"
                 style="width:100%;padding:8px 10px;border:1px solid #d2d2d7;border-radius:7px;font-size:14px;font-family:inherit">
        </div>
        <div style="margin-bottom:14px">
          <label style="display:block;font-size:13px;font-weight:600;margin-bottom:5px">New Password</label>
          <input type="password" name="new_password" required minlength="8" autocomplete="new-password"
                 style="width:100%;padding:8px 10px;border:1px solid #d2d2d7;border-radius:7px;font-size:14px;font-family:inherit">
          <div style="font-size:12px;color:#6e6e73;margin-top:4px">Minimum 8 characters</div>
        </div>
        <div style="margin-bottom:18px">
          <label style="display:block;font-size:13px;font-weight:600;margin-bottom:5px">Confirm New Password</label>
          <input type="password" name="confirm_password" required minlength="8" autocomplete="new-password"
                 style="width:100%;padding:8px 10px;border:1px solid #d2d2d7;border-radius:7px;font-size:14px;font-family:inherit">
        </div>
        <button type="submit" class="btn btn-primary">Change Password</button>
      </form>
      <p style="font-size:12px;color:#6e6e73;margin-top:12px">
        Password is persisted to <code>.env</code> in the project directory and takes effect immediately.
      </p>
    </div>
  </section>
</div></main>`;

  return adminLayout('Settings', body);
}

function renderReconcilePage({ adv, runs, runResult, csrfToken = '' }) {
  const advTz = validTz(adv.timezone) || FALLBACK_TZ;
  const resultHtml = runResult ? (() => {
    const { run, unmatched, rejected, disputed = [], flags = {} } = runResult;
    const matchRate = run.total_rows > 0 ? Math.round((run.matched / run.total_rows) * 100) : 0;
    const discrepancy = run.discrepancy || 0;
    const unmatchedRows = unmatched.map(r => `<tr>
      <td><code class="xs">${H(r.click_id||'—')}</code></td>
      <td>${H(r.raw_status)}</td>
      <td>${H(r.reason)}</td>
      <td style="color:#c62828">${H(r.issue)}</td>
    </tr>`).join('');
    const rejectedRows = rejected.map(r => `<tr>
      <td><code class="xs">${H(r.click_id)}</code></td>
      <td>$${$(r.payout)}</td>
      <td>${H(r.reason||'—')}</td>
    </tr>`).join('');

    const disputeOpt = (cur) => ['none','disputed','resolved'].map(s =>
      `<option value="${s}" ${cur===s?'selected':''}>${s[0].toUpperCase()+s.slice(1)}</option>`).join('');
    const disputedRows = disputed.map(c => `<tr>
      <td><code class="xs">${H(c.click_id)}</code></td>
      <td><span class="badge ${c.status==='approved'?'active':'paused'}">${H(c.status)}</span></td>
      <td>${H(c.reason||'—')}</td>
      <td>${fmtCur(c.payout, c.currency)}</td>
      <td>
        <form method="POST" action="/admin/conversions/${H(c.id)}/dispute" style="display:flex;gap:6px;align-items:center;flex-wrap:wrap">${csrfField(csrfToken)}
          <select name="dispute_state" style="padding:4px 6px;font-size:12px">${disputeOpt(c.dispute_state)}</select>
          <input type="number" name="adjustment" value="${c.adjustment ?? ''}" step="0.01" placeholder="adj." style="width:90px;padding:4px 6px;font-size:12px">
          <input type="text" name="adjustment_note" value="${H(c.adjustment_note||'')}" placeholder="note" style="width:140px;padding:4px 6px;font-size:12px">
          <button class="btn btn-ghost" style="padding:4px 10px;font-size:12px">Save</button>
        </form>
      </td>
    </tr>`).join('');

    const flagTotal = (flags.attributed||0) + (flags.rejectedFlag||0) + (flags.restricted||0);

    return `
    <section style="border:2px solid #0071e3">
      <div class="sh"><h2>Reconciliation Report — Run #${run.id} · ${H(run.filename)}</h2>
        <span class="meta">${H(formatInTz(run.uploaded_at, advTz))} · ${H(advTz)}</span></div>
      <div style="padding:8px 20px 0;font-size:12px;color:#6e6e73">Match key: <code>click_id</code> ↔ AppsFlyer <code>customer_user_id</code> · Currency <strong>${H(adv.currency||'USD')}</strong></div>
      <div class="cards" style="padding:16px 20px 4px;margin-bottom:0">
        <div class="card"><div class="lbl">Total Rows</div><div class="val">${N(run.total_rows)}</div></div>
        <div class="card"><div class="lbl">Matched</div><div class="val">${N(run.matched)} <small style="font-size:12px;color:#6e6e73">(${matchRate}%)</small></div></div>
        <div class="card"><div class="lbl">Approved</div><div class="val green">${N(run.approved)}</div></div>
        <div class="card"><div class="lbl">Rejected</div><div class="val" style="color:#c62828">${N(run.rejected)}</div></div>
        <div class="card"><div class="lbl">Unmatched</div><div class="val" style="color:#f57f17">${N(run.unmatched)}</div></div>
        <div class="card"><div class="lbl">Discrepancies</div><div class="val" style="color:${discrepancy>0?'#c62828':'#1d1d1f'}">${N(discrepancy)}</div></div>
      </div>
      ${flagTotal > 0 ? `
      <div style="padding:4px 20px 16px">
        <h3 style="font-size:13px;font-weight:600;margin-bottom:8px">AppsFlyer Attribution Flags <small style="font-weight:400;color:#6e6e73">(this advertiser)</small></h3>
        <div style="display:flex;gap:10px;flex-wrap:wrap;font-size:12px">
          <span class="badge active">Attributed: ${N(flags.attributed||0)}</span>
          <span class="badge paused">Rejected / organic: ${N(flags.rejectedFlag||0)}</span>
          <span class="badge" style="background:#fff3e0;color:#e65100">Restricted (review): ${N(flags.restricted||0)}</span>
        </div>
      </div>` : ''}
      ${disputed.length > 0 ? `
      <div style="padding:0 20px 16px">
        <h3 style="font-size:13px;font-weight:600;margin-bottom:8px">Disputed / Discrepant Conversions (${disputed.length})</h3>
        <p style="font-size:11px;color:#6e6e73;margin-bottom:8px">The advertiser's decision overturned ours. Set a dispute state and an optional payout adjustment (e.g. a clawback) per conversion.</p>
        <table><thead><tr><th>Click ID</th><th>Status</th><th>Reason</th><th>Payout</th><th>Dispute / Adjustment</th></tr></thead>
        <tbody>${disputedRows}</tbody></table>
      </div>` : ''}
      ${rejected.length > 0 ? `
      <div style="padding:0 20px 16px">
        <h3 style="font-size:13px;font-weight:600;margin-bottom:8px">Rejected Conversions (${rejected.length})</h3>
        <table><thead><tr><th>Click ID</th><th>Payout</th><th>Reason</th></tr></thead>
        <tbody>${rejectedRows}</tbody></table>
      </div>` : ''}
      ${unmatched.length > 0 ? `
      <div style="padding:0 20px 16px">
        <h3 style="font-size:13px;font-weight:600;margin-bottom:8px">Unmatched Rows (${unmatched.length})</h3>
        <table><thead><tr><th>Click ID</th><th>Status in CSV</th><th>Reason</th><th>Issue</th></tr></thead>
        <tbody>${unmatchedRows}</tbody></table>
      </div>` : ''}
    </section>`;
  })() : '';

  const historyRows = runs.map(r => `<tr>
    <td>${H(formatInTz(r.uploaded_at, advTz))}</td>
    <td>${H(r.filename)}</td>
    <td>${N(r.total_rows)}</td>
    <td>${N(r.matched)}</td>
    <td><span style="color:#2e7d32;font-weight:600">${N(r.approved)}</span></td>
    <td><span style="color:#c62828">${N(r.rejected)}</span></td>
    <td><span style="color:#f57f17">${N(r.unmatched)}</span></td>
    <td><span style="color:${(r.discrepancy||0)>0?'#c62828':'#6e6e73'}">${N(r.discrepancy||0)}</span></td>
    <td><a href="/admin/advertisers/${H(adv.slug)}/reconcile?run=${r.id}" class="btn btn-ghost">View</a></td>
  </tr>`).join('');

  const body = `
${adminHeader(`<a href="/admin" class="hbtn ghost">← Dashboard</a>`)}
<main>
${resultHtml}
<section>
  <div class="sh">
    <h2>Upload Reconciliation File — ${H(adv.name)}</h2>
  </div>
  <div style="padding:20px 24px">
    <div style="background:#f5f5f7;border-radius:8px;padding:14px 16px;margin-bottom:20px;font-size:12px;line-height:1.6">
      <strong>Expected CSV format:</strong><br>
      <code>click_id,transaction_id,status,reason,payout</code><br>
      <code>abc-123-def,,approved,,15.00</code><br>
      <code>,TXN-789,approved,,20.00</code><br>
      <code>xyz-456-ghi,,rejected,Duplicate application,</code><br><br>
      <strong>Columns:</strong> <code>click_id</code> OR <code>transaction_id</code> (at least one required — matched by click_id first, then transaction_id) · <code>status</code>: <code>approved</code> or <code>rejected</code> (required) · <code>reason</code> (optional) · <code>payout</code> override (optional)
    </div>
    <form method="POST" action="/admin/advertisers/${H(adv.slug)}/reconcile" enctype="multipart/form-data">${csrfField(csrfToken)}
      <div class="fg" style="max-width:440px">
        <label>CSV File *</label>
        <input type="file" name="csv_file" accept=".csv,.txt" required
               style="padding:6px;border:1px solid #d2d2d7;border-radius:7px;width:100%">
      </div>
      <button type="submit" class="btn btn-primary btn-lg">Upload &amp; Process</button>
    </form>
  </div>
</section>

<section>
  <div class="sh"><h2>Reconciliation History</h2><span class="meta">Last 30 runs</span></div>
  ${runs.length === 0 ? '<div class="empty">No reconciliation runs yet.</div>' : `
  <table><thead><tr>
    <th>Date</th><th>Filename</th><th>Total Rows</th><th>Matched</th>
    <th>Approved</th><th>Rejected</th><th>Unmatched</th><th>Discrepancy</th><th></th>
  </tr></thead><tbody>${historyRows}</tbody></table>`}
</section>
</main>`;

  return adminLayout(`Reconcile — ${adv.name}`, body);
}

function renderPostbackLog({ pub, logs, stats }) {
  const rows = logs.map(l => {
    const statusClass = l.success ? 'active' : 'paused';
    const statusText  = l.success ? `${l.http_status} OK` : (l.http_status ? `${l.http_status} Error` : 'Failed');
    return `<tr>
      <td>${H(l.fired_at)}</td>
      <td><code class="xs">${H(l.click_id)}</code></td>
      <td style="font-size:11px;max-width:340px;word-break:break-all">${H(l.url)}</td>
      <td><span class="badge ${statusClass}">${statusText}</span></td>
      <td style="text-align:center">${l.attempt}</td>
      <td style="font-size:11px;color:#c62828">${H(l.error||'')}</td>
    </tr>`;
  }).join('');

  const body = `${adminHeader(`<a href="/admin/publishers/${H(pub.id)}/edit" class="hbtn ghost">Edit Publisher</a>
    <a href="/admin/publishers" class="hbtn ghost">← Publishers</a>`)}
<main>
<div class="cards" style="margin-bottom:20px">
  <div class="card"><div class="lbl">Total Fired</div><div class="val">${N(stats?.total||0)}</div></div>
  <div class="card"><div class="lbl">Succeeded</div><div class="val green">${N(stats?.succeeded||0)}</div></div>
  <div class="card"><div class="lbl">Failed</div><div class="val" style="color:#c62828">${N(stats?.failed||0)}</div></div>
  <div class="card"><div class="lbl">Success Rate</div><div class="val">${stats?.total ? Math.round((stats.succeeded/stats.total)*100) : 0}%</div></div>
</div>
<section>
  <div class="sh">
    <h2>S2S Postback Log — <code>${H(pub.username)}</code></h2>
    <span class="meta">Last 200 attempts</span>
  </div>
  ${pub.postback_url
    ? `<div style="padding:10px 20px;background:#f5f5f7;border-bottom:1px solid #f0f0f0;font-size:11px">
        <strong>URL template:</strong> <code>${H(pub.postback_url)}</code></div>`
    : `<div class="empty" style="padding:16px 20px;text-align:left;font-size:13px">
        No S2S postback URL configured for this publisher.
        <a href="/admin/publishers/${H(pub.id)}/edit">Set one →</a></div>`}
  ${logs.length===0
    ? '<div class="empty">No postback attempts yet.</div>'
    : `<table><thead><tr>
        <th>Fired At</th><th>Click ID</th><th>URL Fired</th><th>Status</th><th style="text-align:center">Attempt</th><th>Error</th>
      </tr></thead><tbody>${rows}</tbody></table>`}
</section>
</main>`;

  return adminLayout(`S2S Log — ${pub.username}`, body);
}

// Backlog #2 — global postback delivery log (sent + received) with filters + dup flags
function renderGlobalPostbackLog({ dir, status, q, rows, stats, dupCount, dupSet }) {
  const tab = (d, label) => `<a href="/admin/postback-log?dir=${d}${status!=='all'?`&status=${status}`:''}${q?`&q=${encodeURIComponent(q)}`:''}"
    class="btn ${dir===d?'btn-primary':'btn-ghost'}" style="margin-right:6px">${label}</a>`;
  const statusPill = (s, label) => `<a href="/admin/postback-log?dir=${dir}${s!=='all'?`&status=${s}`:''}${q?`&q=${encodeURIComponent(q)}`:''}"
    class="btn ${status===s?'btn-primary':'btn-ghost'}" style="margin-right:6px;padding:5px 10px;font-size:12px">${label}</a>`;

  const sentRows = rows.map(l => {
    const dup = dupSet.has(l.click_id);
    const ok  = l.success;
    return `<tr${dup?' style="background:#fffbf0"':''}>
      <td>${H(l.ts)}</td>
      <td>${H(l.publisher)}</td>
      <td><code class="xs">${H(l.click_id)}</code>${dup?' <span class="badge" style="background:#fff3e0;color:#e65100">dup</span>':''}</td>
      <td style="font-size:11px;max-width:320px;word-break:break-all">${H(l.url)}</td>
      <td><span class="badge ${ok?'active':'paused'}">${ok ? `${l.http_status} OK` : (l.http_status?`${l.http_status} Err`:'Failed')}</span></td>
      <td style="text-align:center">${l.attempt}</td>
      <td style="font-size:11px;color:#c62828">${H(l.error||'')}</td>
    </tr>`;
  }).join('');

  const recvRows = rows.map(l => {
    const dup = dupSet.has(l.click_id);
    const cls = l.status === 'approved' ? 'active' : (l.status === 'pending' ? '' : 'paused');
    return `<tr${dup?' style="background:#fffbf0"':''}>
      <td>${H(l.ts)}</td>
      <td>${H(l.publisher)}</td>
      <td>${H(l.advertiser_slug)}</td>
      <td><code class="xs">${H(l.click_id)}</code>${dup?' <span class="badge" style="background:#fff3e0;color:#e65100">dup</span>':''}</td>
      <td>${H(l.event)}</td>
      <td><span class="badge ${cls}">${H(l.status)}</span></td>
      <td style="font-size:11px;color:#6e6e73">${H(l.reason||'')}</td>
    </tr>`;
  }).join('');

  const table = dir === 'received'
    ? `<table><thead><tr><th>Received At</th><th>Publisher</th><th>Advertiser</th><th>Click ID</th><th>Event</th><th>Status</th><th>Reason</th></tr></thead><tbody>${recvRows}</tbody></table>`
    : `<table><thead><tr><th>Fired At</th><th>Publisher</th><th>Click ID</th><th>URL Fired</th><th>Status</th><th style="text-align:center">Attempt</th><th>Error</th></tr></thead><tbody>${sentRows}</tbody></table>`;

  const body = `${adminHeader()}
<main>
<div class="cards" style="margin-bottom:16px">
  <div class="card"><div class="lbl">Total ${dir==='received'?'Received':'Sent'}</div><div class="val">${N(stats?.total||0)}</div></div>
  <div class="card"><div class="lbl">${dir==='received'?'Approved':'Succeeded'}</div><div class="val green">${N(stats?.succeeded||0)}</div></div>
  <div class="card"><div class="lbl">${dir==='received'?'Rejected/Dup':'Failed'}</div><div class="val" style="color:#c62828">${N(stats?.failed||0)}</div></div>
  <div class="card"><div class="lbl">Duplicate click_ids</div><div class="val" style="color:${dupCount>0?'#e65100':'#1d1d1f'}">${N(dupCount||0)}</div></div>
</div>
<section>
  <div class="sh"><h2>Postback Delivery Log</h2><span class="meta">Last ${N(rows.length)} ${dir==='received'?'received':'sent'} · compare against AppsFlyer Postbacks raw report</span></div>
  <div style="padding:14px 20px;border-bottom:1px solid #f0f0f0">
    <div style="margin-bottom:10px">${tab('sent','Sent (S2S → publisher)')}${tab('received','Received (← advertiser/MMP)')}</div>
    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      ${statusPill('all','All')}${statusPill('ok',dir==='received'?'Approved':'Success')}${statusPill('fail',dir==='received'?'Rejected':'Failed')}
      <form method="GET" action="/admin/postback-log" style="display:flex;gap:6px;margin-left:auto">
        <input type="hidden" name="dir" value="${H(dir)}"><input type="hidden" name="status" value="${H(status)}">
        <input type="text" name="q" value="${H(q)}" placeholder="search click_id / publisher" style="padding:6px 10px;border:1px solid #d2d2d7;border-radius:7px;font-size:13px;width:240px">
        <button class="btn btn-ghost">Search</button>
        ${q?`<a href="/admin/postback-log?dir=${H(dir)}" class="btn btn-ghost">Clear</a>`:''}
      </form>
    </div>
  </div>
  ${rows.length===0 ? '<div class="empty">No postback records match.</div>' : table}
</section>
</main>`;
  return adminLayout('Postback Delivery Log', body);
}

// ---------------------------------------------------------------------------
// Backlog #8 — admin postback test tool
function renderPostbackTest({ adv, csrfToken = '', prefillClick = '', result }) {
  const resultHtml = result ? `
    <section style="border:2px solid ${result.ok ? '#2e7d32' : '#c62828'};margin-top:20px">
      <div class="sh"><h2>Test Result — HTTP ${result.status}${result.ok ? ' ✓' : ' ✗'}</h2></div>
      <div style="padding:16px 20px">
        <div style="font-size:12px;color:#6e6e73;margin-bottom:6px">Request URL (HMAC signature included when a secret is set):</div>
        <div class="ubox" data-copy="${H(result.url)}" style="word-break:break-all;margin-bottom:12px">${H(result.url)}</div>
        <div style="font-size:12px;color:#6e6e73;margin-bottom:6px">Response body:</div>
        <pre style="background:#1d1d1f;color:#e8e8ed;padding:12px 14px;border-radius:8px;font-size:12px;overflow:auto;white-space:pre-wrap">${H(result.body || '(empty)')}</pre>
      </div>
    </section>` : '';

  const body = `${adminHeader(`<a href="/admin/advertisers/${H(adv.slug)}/edit" class="hbtn ghost">← Edit advertiser</a>`)}
<main>
<section>
  <div class="sh"><h2>Postback Test Tool — ${H(adv.name)}</h2><span class="meta">${H(adv.slug)}</span></div>
  <div style="padding:20px 24px">
    <p style="font-size:12px;color:#6e6e73;margin-bottom:16px">Fire a test postback to <code>/postback/${H(adv.slug)}</code>. ${adv.postback_secret ? 'This advertiser has an HMAC secret — the request is signed automatically.' : 'No HMAC secret set — the request is unsigned.'} The click_id must belong to an existing click for this advertiser.</p>
    <form method="POST" action="/admin/advertisers/${H(adv.slug)}/postback-test">${csrfField(csrfToken)}
      <div class="fg"><label>Click ID *</label>
        <input type="text" name="click_id" value="${H(prefillClick)}" required placeholder="existing click_id" style="font-family:monospace"></div>
      <div class="fg-row">
        <div class="fg"><label>Event</label><input type="text" name="event" value="sale"></div>
        <div class="fg"><label>Payout (optional)</label><input type="number" name="payout" step="0.01" placeholder="advertiser default"></div>
        <div class="fg"><label>Loan Amount (optional)</label><input type="number" name="loan_amount" step="0.01" placeholder="for percent payouts"></div>
      </div>
      <button type="submit" class="btn btn-primary btn-lg">Send Test Postback</button>
    </form>
  </div>
</section>
${resultHtml}
</main>
<script>${CP_JS}</script>`;
  return adminLayout(`Postback Test — ${adv.name}`, body);
}

// Backlog #9 — cohort / retention report view
function renderCohortReport({ rows, by, cohortType, advFilter, advertisers }) {
  const byTab = (v, label) => `<a href="/admin/reports/cohort?by=${v}${cohortType!=='all'?`&type=${cohortType}`:''}${advFilter?`&advertiser=${encodeURIComponent(advFilter)}`:''}" class="btn ${by===v?'btn-primary':'btn-ghost'}" style="margin-right:6px">${label}</a>`;
  const typeTab = (v, label) => `<a href="/admin/reports/cohort?by=${by}${v!=='all'?`&type=${v}`:''}${advFilter?`&advertiser=${encodeURIComponent(advFilter)}`:''}" class="btn ${cohortType===v?'btn-primary':'btn-ghost'}" style="margin-right:6px;padding:5px 10px;font-size:12px">${label}</a>`;
  const csvHref = `/admin/reports/cohort?by=${by}&type=${cohortType}${advFilter?`&advertiser=${encodeURIComponent(advFilter)}`:''}&format=csv`;
  const tableRows = rows.map(r => `<tr>
    <td><strong>${H(r.dim||'(none)')}</strong></td>
    <td>${N(r.conversions)}</td>
    <td>$${$(r.ltv)}</td>
    <td>${N(r.d0)}</td><td>${N(r.d1_7)}</td><td>${N(r.d8_14)}</td><td>${N(r.d15_28)}</td><td>${N(r.d28p)}</td>
  </tr>`).join('');
  const body = `${adminHeader(`<a href="${csvHref}" class="hbtn">Export CSV</a>`)}
<main>
<section>
  <div class="sh"><h2>Cohort / Retention Report</h2><span class="meta">Retention by days from click · LTV = approved payout</span></div>
  <div style="padding:14px 20px;border-bottom:1px solid #f0f0f0">
    <div style="margin-bottom:8px;font-size:11px;color:#6e6e73">GROUP BY</div>
    <div style="margin-bottom:12px">${byTab('media_source','Media Source')}${byTab('network','Network')}${byTab('campaign','Campaign')}</div>
    <div style="margin-bottom:8px;font-size:11px;color:#6e6e73">COHORT TYPE</div>
    <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
      ${typeTab('all','All')}${typeTab('acquisition','Acquisition (first)')}${typeTab('reengagement','Re-engagement (repeat)')}
      <form method="GET" action="/admin/reports/cohort" style="margin-left:auto;display:flex;gap:6px">
        <input type="hidden" name="by" value="${H(by)}"><input type="hidden" name="type" value="${H(cohortType)}">
        <select name="advertiser" onchange="this.form.submit()" style="padding:6px 10px;border:1px solid #d2d2d7;border-radius:7px;font-size:13px">
          <option value="">All advertisers</option>
          ${advertisers.map(a => `<option value="${H(a.slug)}" ${advFilter===a.slug?'selected':''}>${H(a.name)}</option>`).join('')}
        </select>
      </form>
    </div>
  </div>
  ${rows.length===0 ? '<div class="empty">No conversion data for this cohort.</div>' : `
  <table><thead><tr>
    <th>Media Source</th><th>Conversions</th><th>LTV</th><th>D0</th><th>D1-7</th><th>D8-14</th><th>D15-28</th><th>D28+</th>
  </tr></thead><tbody>${tableRows}</tbody></table>`}
</section>
</main>`;
  return adminLayout('Cohort Report', body);
}

// Backlog #10 — pivot / grouped report view
function renderPivotReport({ rows, dim1, dim2 }) {
  const dimSelect = (name, current, allowNone) => `<select name="${name}" onchange="this.form.submit()" style="padding:6px 10px;border:1px solid #d2d2d7;border-radius:7px;font-size:13px">
    ${allowNone ? `<option value="">— none —</option>` : ''}
    ${Object.entries(PIVOT_DIMS).map(([k, v]) => `<option value="${k}" ${current===k?'selected':''}>${v.label}</option>`).join('')}
  </select>`;
  const csvHref = `/admin/reports/pivot?dim1=${dim1}${dim2?`&dim2=${dim2}`:''}&format=csv`;
  const head = `<th>${H(PIVOT_DIMS[dim1].label)}</th>${dim2?`<th>${H(PIVOT_DIMS[dim2].label)}</th>`:''}<th>Conversions</th><th>Approved</th><th>Payout</th><th>Revenue</th>`;
  const tableRows = rows.map(r => `<tr>
    <td><strong>${H(r.k1||'(none)')}</strong></td>${dim2?`<td>${H(r.k2||'(none)')}</td>`:''}
    <td>${N(r.conversions)}</td><td>${N(r.approved)}</td><td>$${$(r.payout)}</td><td>$${$(r.revenue)}</td>
  </tr>`).join('');
  const body = `${adminHeader(`<a href="${csvHref}" class="hbtn">Export CSV</a>`)}
<main>
<section>
  <div class="sh"><h2>Pivot / Grouped Report</h2><span class="meta">Conversion breakdown · payout &amp; revenue are approved-only</span></div>
  <div style="padding:14px 20px;border-bottom:1px solid #f0f0f0">
    <form method="GET" action="/admin/reports/pivot" style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
      <span style="font-size:12px;color:#6e6e73">Break down by</span>
      ${dimSelect('dim1', dim1, false)}
      <span style="font-size:12px;color:#6e6e73">then</span>
      ${dimSelect('dim2', dim2, true)}
      <noscript><button class="btn btn-ghost">Apply</button></noscript>
    </form>
    <p style="font-size:11px;color:#6e6e73;margin-top:8px">Tip: export to CSV for scheduled/emailed delivery. (A nightly emailed export can be wired to this endpoint via cron — see ops notes.)</p>
  </div>
  ${rows.length===0 ? '<div class="empty">No conversion data.</div>' : `
  <table><thead><tr>${head}</tr></thead><tbody>${tableRows}</tbody></table>`}
</section>
</main>`;
  return adminLayout('Pivot Report', body);
}

// Backlog #16 — publisher traffic-quality scoreboard
const GRADE_COLOR = { A: '#2e7d32', B: '#00897b', C: '#f9a825', D: '#ef6c00', F: '#c62828' };
const GRADE_BG    = { A: '#e8f5e9', B: '#e0f2f1', C: '#fffde7', D: '#fff3e0', F: '#fde8e8' };
function qualityBadge(score, grade) {
  return `<span class="badge" style="background:${GRADE_BG[grade]};color:${GRADE_COLOR[grade]};font-weight:700">${grade} · ${N(score)}</span>`;
}
function renderPublisherQuality({ rows }) {
  const pct = x => `${(x * 100).toFixed(1)}%`;
  const tableRows = rows.map(r => `<tr data-pub="${H(r.publisher)}" data-score="${r.score}" data-grade="${r.grade}" style="background:${GRADE_BG[r.grade]}">
    <td><strong>${H(r.publisher)}</strong></td>
    <td style="font-weight:700;color:${GRADE_COLOR[r.grade]}">${N(r.score)}</td>
    <td><span class="badge" style="background:#fff;color:${GRADE_COLOR[r.grade]};font-weight:700">${r.grade}</span></td>
    <td>${N(r.total)}</td>
    <td>${pct(r.rejection_rate)}</td>
    <td>${pct(r.fraud_rate)}</td>
    <td>${pct(r.ctit_anomaly_rate)}</td>
  </tr>`).join('');
  const body = `${adminHeader()}
<main>
<section>
  <div class="sh"><h2>Publisher Traffic Quality</h2><span class="meta">Last 90 days · score = 100 − rejection×40 − fraud×40 − CTIT×20</span></div>
  <div style="padding:10px 20px;font-size:12px;color:#6e6e73">Grades: <strong style="color:${GRADE_COLOR.A}">A 90+</strong> · <strong style="color:${GRADE_COLOR.B}">B 75+</strong> · <strong style="color:${GRADE_COLOR.C}">C 60+</strong> · <strong style="color:${GRADE_COLOR.D}">D 40+</strong> · <strong style="color:${GRADE_COLOR.F}">F &lt;40</strong></div>
  ${rows.length === 0 ? '<div class="empty">No publishers yet.</div>' : `
  <table><thead><tr>
    <th>Publisher</th><th>Score</th><th>Grade</th><th>Total Conv</th><th>Rejection</th><th>Fraud</th><th>CTIT Anomaly</th>
  </tr></thead><tbody>${tableRows}</tbody></table>`}
</section>
</main>`;
  return adminLayout('Publisher Quality', body);
}

// Backlog #14 — fraud review (flagged conversions grouped by click_id)
function fraudBadge(flag, source) {
  const out = [];
  if (source === 'protect360') out.push('<span class="badge" style="background:#fde8e8;color:#c62828;font-weight:700">P360</span>');
  for (const f of (flag || '').split('|').filter(Boolean)) {
    const label = f === 'duplicate_click_id' ? 'DUP' : f === 'ctit_too_fast' ? 'CTIT⚡' : f === 'ctit_too_slow' ? 'CTIT🐌' : f;
    out.push(`<span class="badge" style="background:#fff3e0;color:#e65100">${H(label)}</span>`);
  }
  return out.join(' ');
}
function renderFraudPage({ rows }) {
  const tableRows = rows.map(r => `<tr>
    <td><code class="xs">${H(r.click_id)}</code></td>
    <td>${H(r.advertiser_slug)}</td>
    <td>${H(r.publisher)}</td>
    <td>${H(r.events || '')}</td>
    <td>${N(r.n)}</td>
    <td>${fraudBadge(r.fraud_flag, r.fraud_source)}</td>
    <td>${H(r.last_at)}</td>
  </tr>`).join('');
  const body = `${adminHeader()}
<main>
<section>
  <div class="sh"><h2>Fraud Review</h2><span class="meta">Flagged conversions grouped by click_id</span></div>
  ${rows.length === 0 ? '<div class="empty">No flagged conversions.</div>' : `
  <table><thead><tr>
    <th>Click ID</th><th>Advertiser</th><th>Publisher</th><th>Events</th><th>Rows</th><th>Flags</th><th>Last Seen</th>
  </tr></thead><tbody>${tableRows}</tbody></table>`}
</section>
</main>`;
  return adminLayout('Fraud Review', body);
}

// Backlog #11 — Advertiser portal HTML templates (reuse the publisher portal CSS)
// ---------------------------------------------------------------------------
function advLayout(title, body, adv = null, activeTab = null) {
  const fonts = '<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">';
  if (!adv) {
    return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${H(title)} — Komorebi Advertiser</title>${fonts}<style>${PUB_CSS}</style></head>
<body>${body}<script>${PORTAL_JS}</script></body></html>`;
  }
  const navItem = (href, key, label) => `<a href="${href}" class="pub-nav-a${activeTab===key?' active':''}"><span>${label}</span></a>`;
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${H(title)} — Komorebi Advertiser Portal</title>${fonts}<style>${PUB_CSS}</style></head>
<body><div class="pub-shell">
  <header class="pub-topbar">
    <div class="pub-brand">
      <button class="nav-burger" type="button" data-nav-toggle aria-label="Toggle menu" aria-controls="adv-sidebar" aria-expanded="false">☰</button>
      <div class="pub-logo-mark">${SUN_ICON}</div>
      <div><div class="pub-brand-name">KOMOREBI</div><div class="pub-brand-sub">ADVERTISER</div></div>
    </div>
    <div class="pub-topbar-r">
      <span class="pub-topbar-user">Signed in as <strong>${H(adv.name)}</strong></span>
      <form method="POST" action="/advertiser/logout" style="display:inline"><button class="pub-logout">Sign out</button></form>
    </div>
  </header>
  <div class="pub-body">
    <aside class="pub-sidebar" id="adv-sidebar" data-nav-sidebar>
      <div class="pub-sb-group">OVERVIEW</div>
      ${navItem('/advertiser/dashboard','dashboard','Dashboard')}
      ${navItem('/advertiser/conversions','conversions','Conversions')}
      ${navItem('/advertiser/analytics','analytics','Analytics')}
      <div class="pub-sb-group">TOOLS</div>
      ${navItem('/advertiser/reconcile','reconcile','Reconciliation')}
      ${navItem('/advertiser/tracking-links','links','Tracking Links')}
    </aside>
    <div class="nav-backdrop" data-nav-backdrop></div>
    <div class="pub-content">${body}</div>
  </div>
</div><script>${CP_JS}${PORTAL_JS}${NAV_TOGGLE_JS}</script></body></html>`;
}

function renderAdvLogin({ error }) {
  const body = `<div style="max-width:400px;margin:80px auto;padding:0 20px">
    <div style="text-align:center;margin-bottom:24px"><div class="pub-logo-mark" style="margin:0 auto 12px">${SUN_ICON}</div>
      <h1 style="font-size:22px;font-weight:600">Advertiser Portal</h1>
      <p style="color:#6e6e73;font-size:13px">Sign in with your advertiser slug and portal password.</p></div>
    ${error ? `<div style="background:#fde8e8;color:#c62828;padding:10px 14px;border-radius:8px;font-size:13px;margin-bottom:14px">${H(error)}</div>` : ''}
    <form method="POST" action="/advertiser/login">
      <div style="margin-bottom:12px"><label style="font-size:12px;font-weight:600;display:block;margin-bottom:4px">Advertiser Slug</label>
        <input type="text" name="username" required autofocus style="width:100%;padding:10px 12px;border:1px solid #d2d2d7;border-radius:8px"></div>
      <div style="margin-bottom:16px"><label style="font-size:12px;font-weight:600;display:block;margin-bottom:4px">Password</label>
        <input type="password" name="password" required style="width:100%;padding:10px 12px;border:1px solid #d2d2d7;border-radius:8px"></div>
      <button type="submit" style="width:100%;padding:11px;background:#0F6E56;color:#fff;border:0;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer">Sign In</button>
    </form>
  </div>`;
  return advLayout('Advertiser Login', body);
}

function renderAdvDashboard({ adv, clicks, statusRows, payoutRows, recent }) {
  const payoutCards = (payoutRows.length ? payoutRows : [{ currency: adv.currency || 'USD', approved: 0 }])
    .map(p => `<div class="card"><div class="lbl">Approved Payout (${H(p.currency)})</div><div class="val green">${fmtCur(p.approved, p.currency)}</div></div>`).join('');
  const rows = recent.map(c => `<tr>
    <td>${H(formatInTz(c.received_at, validTz(adv.timezone) || FALLBACK_TZ))}</td>
    <td><code class="xs">${H(c.click_id)}</code></td><td>${H(c.event)}</td>
    <td>${fmtCur(c.payout, c.currency)}</td>
    <td><span class="badge ${c.status==='approved'?'active':(c.status==='pending'?'':'paused')}">${H(c.status)}</span></td>
  </tr>`).join('');
  const body = `
  <h1 style="font-size:22px;margin-bottom:4px">${H(adv.name)}</h1>
  <p style="color:#6e6e73;font-size:13px;margin-bottom:20px">Timezone ${H(validTz(adv.timezone)||FALLBACK_TZ)} · Currency ${H(adv.currency||'USD')}</p>
  <div class="cards" style="margin-bottom:24px">
    <div class="card"><div class="lbl">Clicks</div><div class="val">${N(clicks)}</div></div>
    <div class="card"><div class="lbl">Conversions</div><div class="val">${N(statusRows.total||0)}</div></div>
    <div class="card"><div class="lbl">Approved</div><div class="val green">${N(statusRows.approved||0)}</div></div>
    <div class="card"><div class="lbl">Pending</div><div class="val">${N(statusRows.pending||0)}</div></div>
    ${payoutCards}
  </div>
  <section><div class="sh"><h2>Recent Conversions</h2></div>
  ${recent.length===0 ? '<div class="empty">No conversions yet.</div>' :
    `<table><thead><tr><th>Received</th><th>Click ID</th><th>Event</th><th>Payout</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table>`}
  </section>`;
  return advLayout('Dashboard', body, adv, 'dashboard');
}

function renderAdvConversions({ adv, conversions }) {
  const tz = validTz(adv.timezone) || FALLBACK_TZ;
  const rows = conversions.map(c => `<tr>
    <td>${H(formatInTz(c.received_at, tz))}</td>
    <td><code class="xs">${H(c.click_id)}</code></td><td>${H(c.publisher)}</td><td>${H(c.event)}</td>
    <td>${fmtCur(c.payout, c.currency)}</td>
    <td><span class="badge ${c.status==='approved'?'active':(c.status==='pending'?'':'paused')}">${H(c.status)}</span></td>
    <td>${c.dispute_state && c.dispute_state!=='none' ? `<span class="badge paused">${H(c.dispute_state)}</span>` : ''}</td>
  </tr>`).join('');
  const body = `<h1 style="font-size:22px;margin-bottom:16px">Conversions</h1>
  <section>${conversions.length===0 ? '<div class="empty">No conversions yet.</div>' :
    `<table><thead><tr><th>Received</th><th>Click ID</th><th>Publisher</th><th>Event</th><th>Payout</th><th>Status</th><th>Dispute</th></tr></thead><tbody>${rows}</tbody></table>`}</section>`;
  return advLayout('Conversions', body, adv, 'conversions');
}

function renderAdvAnalytics({ adv, dailyClicks, dailyConv, geo }) {
  const clickMap = Object.fromEntries(dailyClicks.map(r => [r.day, r.n]));
  const convMap  = Object.fromEntries(dailyConv.map(r => [r.day, r.n]));
  const days = [...new Set([...dailyClicks.map(r => r.day), ...dailyConv.map(r => r.day)])].sort().reverse();
  const dayRows = days.map(d => `<tr><td>${H(d)}</td><td>${N(clickMap[d]||0)}</td><td>${N(convMap[d]||0)}</td></tr>`).join('');
  const geoRows = geo.map(g => `<tr><td>${H(g.country)}</td><td>${N(g.n)}</td></tr>`).join('');
  const body = `<h1 style="font-size:22px;margin-bottom:16px">Analytics</h1>
  <section style="margin-bottom:20px"><div class="sh"><h2>Last 30 Days</h2></div>
    ${days.length===0 ? '<div class="empty">No activity in the last 30 days.</div>' :
      `<table><thead><tr><th>Day</th><th>Clicks</th><th>Conversions</th></tr></thead><tbody>${dayRows}</tbody></table>`}</section>
  <section><div class="sh"><h2>Top Geos</h2></div>
    ${geo.length===0 ? '<div class="empty">No geo data.</div>' :
      `<table><thead><tr><th>Country</th><th>Clicks</th></tr></thead><tbody>${geoRows}</tbody></table>`}</section>`;
  return advLayout('Analytics', body, adv, 'analytics');
}

function renderAdvTrackingLinks({ adv, pubs }) {
  const rows = pubs.map(p => {
    const base = BASE_URL;
    const url = `${base}/track/${adv.slug}?pub=${encodeURIComponent(p.username)}`;
    return `<tr><td>${H(p.username)}</td><td><div class="ubox" data-copy="${H(url)}" style="word-break:break-all">${H(url)}</div></td></tr>`;
  }).join('');
  const body = `<h1 style="font-size:22px;margin-bottom:6px">Tracking Links</h1>
  <p style="color:#6e6e73;font-size:13px;margin-bottom:16px">Live tracking links for publishers assigned to your campaign. Each click generates a unique <code>click_id</code> (your AppsFlyer <code>customer_user_id</code>).</p>
  <section>${pubs.length===0 ? '<div class="empty">No publishers are assigned to your campaign yet.</div>' :
    `<table><thead><tr><th>Publisher</th><th>Tracking URL</th></tr></thead><tbody>${rows}</tbody></table>`}</section>`;
  return advLayout('Tracking Links', body, adv, 'links');
}

function renderAdvReconcile({ adv, runs, csrfToken, flash, error }) {
  const tz = validTz(adv.timezone) || FALLBACK_TZ;
  const rows = runs.map(r => `<tr>
    <td>${H(formatInTz(r.uploaded_at, tz))}</td><td>${H(r.filename)}</td>
    <td>${N(r.total_rows)}</td><td>${N(r.matched)}</td>
    <td style="color:#2e7d32">${N(r.approved)}</td><td style="color:#c62828">${N(r.rejected)}</td>
    <td style="color:#f57f17">${N(r.unmatched)}</td><td>${N(r.discrepancy||0)}</td>
  </tr>`).join('');
  const body = `<h1 style="font-size:22px;margin-bottom:6px">Reconciliation Upload</h1>
  <p style="color:#6e6e73;font-size:13px;margin-bottom:16px">Upload your conversion decisions as CSV to approve/reject conversions. Columns: <code>click_id</code> (or <code>transaction_id</code>), <code>status</code> (approved/rejected), optional <code>reason</code>, <code>payout</code>.</p>
  ${flash ? `<div class="flash success" style="margin-bottom:14px">${H(flash)}</div>` : ''}
  ${error ? `<div style="background:#fde8e8;color:#c62828;padding:10px 14px;border-radius:8px;font-size:13px;margin-bottom:14px">${H(error)}</div>` : ''}
  <section style="margin-bottom:20px"><div style="padding:18px 20px">
    <form method="POST" action="/advertiser/reconcile" enctype="multipart/form-data">${csrfField(csrfToken)}
      <input type="file" name="csv_file" accept=".csv,.txt" required style="padding:6px;border:1px solid #d2d2d7;border-radius:7px;width:100%;max-width:420px;margin-bottom:12px"><br>
      <button type="submit" style="padding:10px 18px;background:#0F6E56;color:#fff;border:0;border-radius:8px;font-weight:600;cursor:pointer">Upload &amp; Process</button>
    </form>
  </div></section>
  <section><div class="sh"><h2>Recent Runs</h2></div>
  ${runs.length===0 ? '<div class="empty">No reconciliation runs yet.</div>' :
    `<table><thead><tr><th>Date</th><th>File</th><th>Rows</th><th>Matched</th><th>Approved</th><th>Rejected</th><th>Unmatched</th><th>Discrepancy</th></tr></thead><tbody>${rows}</tbody></table>`}
  </section>`;
  return advLayout('Reconciliation', body, adv, 'reconcile');
}

// Publisher portal HTML templates
// ---------------------------------------------------------------------------

function pubLayout(title, body, pub = null, activeTab = null) {
  const fonts = '<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">';
  if (!pub) {
    return `<!DOCTYPE html><html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${H(title)} — Komorebi</title>${fonts}<style>${PUB_CSS}</style></head>
<body>${body}<script>${PORTAL_JS}</script></body></html>`;
  }

  const initials = (pub.username || '??').slice(0, 2).toUpperCase();
  const ic = (d) => `<svg width="14" height="14" fill="currentColor" viewBox="0 0 16 16">${d}</svg>`;
  const PICONS = {
    dashboard:   ic(`<rect x="1" y="1" width="6" height="6" rx="1"/><rect x="9" y="1" width="6" height="6" rx="1"/><rect x="1" y="9" width="6" height="6" rx="1"/><rect x="9" y="9" width="6" height="6" rx="1"/>`),
    conversions: ic(`<path fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" d="M2 4h12M2 8h8M2 12h10"/>`),
    payments:    ic(`<path fill="none" stroke="currentColor" stroke-width="1.5" d="M1 4.5h14a.5.5 0 0 1 .5.5v7a.5.5 0 0 1-.5.5H1a.5.5 0 0 1-.5-.5V5a.5.5 0 0 1 .5-.5z"/><path stroke="currentColor" stroke-width="1.4" d="M.5 7.5h15"/>`),
    api:         ic(`<path fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" d="M5 5L2 8l3 3M11 5l3 3-3 3M8 3v10"/>`),
    profile:     ic(`<circle cx="8" cy="5" r="3" fill="none" stroke="currentColor" stroke-width="1.5"/><path fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" d="M2.5 14c0-2.8 2.5-4.5 5.5-4.5s5.5 1.7 5.5 4.5"/>`),
    docs:        ic(`<path fill="none" stroke="currentColor" stroke-width="1.5" d="M3.5 1h9a.5.5 0 0 1 .5.5v13a.5.5 0 0 1-.5.5h-9A.5.5 0 0 1 3 14.5v-13A.5.5 0 0 1 3.5 1z"/><path stroke="currentColor" stroke-width="1.3" stroke-linecap="round" d="M5.5 5h5M5.5 8h5M5.5 11h3"/>`),
  };
  const navItem = (href, key, label, external = false) =>
    `<a href="${href}" class="pub-nav-a${activeTab===key?' active':''}"${external?' target="_blank" rel="noopener noreferrer"':''}>${PICONS[key]||''}<span>${label}</span>${external?'<svg width="9" height="9" viewBox="0 0 16 16" fill="currentColor" style="margin-left:auto;opacity:.35"><path d="M6 3h7v7l-2-2-4 4-2-2 4-4L6 3z"/></svg>':''}</a>`;

  return `<!DOCTYPE html><html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${H(title)} — Komorebi Publisher Portal</title>${fonts}<style>${PUB_CSS}</style></head>
<body>
<div class="pub-shell">
  <header class="pub-topbar">
    <div class="pub-brand">
      <button class="nav-burger" type="button" data-nav-toggle aria-label="Toggle menu" aria-controls="pub-sidebar" aria-expanded="false">☰</button>
      <div class="pub-logo-mark">${SUN_ICON}</div>
      <div>
        <div class="pub-brand-name">KOMOREBI</div>
        <div class="pub-brand-sub">NETWORK</div>
      </div>
    </div>
    <div class="pub-topbar-r">
      <span class="pub-topbar-user">Signed in as <strong>${H(pub.username)}</strong></span>
      <form method="POST" action="/publisher/logout" style="display:inline">
        <button class="pub-logout">Sign out</button>
      </form>
    </div>
  </header>
  <div class="pub-body">
    <aside class="pub-sidebar" id="pub-sidebar" data-nav-sidebar>
      <div class="pub-sb-group">OVERVIEW</div>
      ${navItem('/publisher/dashboard',   'dashboard',   'Dashboard')}
      ${navItem('/publisher/conversions', 'conversions', 'Conversions')}
      ${navItem('/publisher/payments',    'payments',    'Payments')}
      ${navItem('/marketplace',           'marketplace', 'Browse Offers')}
      <div class="pub-sb-group">ACCOUNT</div>
      ${navItem('/publisher/profile',     'profile',     'Profile')}
      <div class="pub-sb-group">DEVELOPER</div>
      ${navItem('/publisher/api-access',  'api',         'API Access')}
      ${navItem('/docs',                  'docs',        'Docs', true)}
      <div class="pub-sb-foot">
        <div style="display:flex;align-items:center;gap:8px">
          <div class="pub-avatar">${H(initials)}</div>
          <div>
            <div style="font-size:12px;color:#c9d1d9;font-weight:500">${H(pub.username)}</div>
            <div style="font-size:10px;color:rgba(255,255,255,.3)">Publisher</div>
          </div>
        </div>
      </div>
    </aside>
    <div class="nav-backdrop" data-nav-backdrop></div>
    <div class="pub-content">
      ${body}
    </div>
  </div>
</div>
<script>${CP_JS}${PORTAL_JS}${NAV_TOGGLE_JS}</script>
</body></html>`;
}

function pubNav() {} // kept for compatibility, logic moved to pubLayout

function renderPubRegister({ error = null, values = {} } = {}) {
  const SOURCES  = ['SEO', 'Social', 'Email', 'Push', 'Native', 'Other'];
  const selected = (values.traffic || '').split(',');
  const boxes    = SOURCES.map(s => `
    <label style="display:flex;align-items:center;gap:7px;font-size:13px;cursor:pointer;padding:3px 0">
      <input type="checkbox" name="traffic" value="${s}" ${selected.includes(s) ? 'checked' : ''}
             style="width:15px;height:15px;accent-color:#0d47a1;flex-shrink:0">
      ${s}
    </label>`).join('');

  const sunSvg = `<svg width="18" height="18" viewBox="0 0 16 16" fill="#00e5c3"><circle cx="8" cy="8" r="3.5"/><path stroke="#00e5c3" stroke-width="1.3" stroke-linecap="round" d="M8 1v1.5M8 13.5V15M1 8h1.5M13.5 8H15M3.2 3.2l1 1M11.8 11.8l1 1M12.8 3.2l-1 1M4.2 11.8l-1 1"/></svg>`;
  return pubLayout('Apply to Join', `
<div class="register-wrap">
  <div class="register-card">
    <div class="login-logo-mark">${sunSvg}</div>
    <div class="login-title">Apply for an account</div>
    <div class="login-sub" style="margin-bottom:22px">Komorebi Affiliate Network</div>
    ${error ? `<div class="login-err">${H(error)}</div>` : ''}
    <form method="POST" action="/publisher/register">
      <div class="register-grid-2">
        <div class="fg"><label>Username *</label>
          <input type="text" name="username" value="${H(values.username||'')}" required
                 pattern="[a-z0-9_-]+" placeholder="e.g. clickon" autocomplete="off"
                 data-slugify></div>
        <div class="fg"><label>Email *</label>
          <input type="email" name="email" value="${H(values.email||'')}" required placeholder="you@company.com"></div>
      </div>
      <div class="register-grid-2">
        <div class="fg"><label>Company</label>
          <input type="text" name="company" value="${H(values.company||'')}" placeholder="Company name"></div>
        <div class="fg"><label>Website</label>
          <input type="url" name="website" value="${H(values.website||'')}" placeholder="https://…"></div>
      </div>
      <div class="fg"><label>Traffic Sources *</label>
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:6px 12px;margin-top:6px;padding:10px 12px;background:#f9fafb;border:1px solid #e2e6ea;border-radius:6px">
          ${boxes}
        </div>
      </div>
      <div class="register-grid-2">
        <div class="fg"><label>Password *</label>
          <input type="password" name="password" required minlength="8" placeholder="Min. 8 chars" autocomplete="new-password"></div>
        <div class="fg"><label>Confirm Password *</label>
          <input type="password" name="password2" required minlength="8" placeholder="Repeat" autocomplete="new-password"></div>
      </div>
      <button type="submit" class="login-btn">Submit Application</button>
    </form>
    <div class="login-link">Already have an account? <a href="/publisher/login">Sign in →</a></div>
  </div>
</div>`);
}

function renderPubLogin({ error, username, success, next } = {}) {
  const sunSvg = `<svg width="18" height="18" viewBox="0 0 16 16" fill="#00e5c3"><circle cx="8" cy="8" r="3.5"/><path stroke="#00e5c3" stroke-width="1.3" stroke-linecap="round" d="M8 1v1.5M8 13.5V15M1 8h1.5M13.5 8H15M3.2 3.2l1 1M11.8 11.8l1 1M12.8 3.2l-1 1M4.2 11.8l-1 1"/></svg>`;
  return pubLayout('Login', `
<div class="login-page">
  <div class="login-card">
    <div class="login-logo-mark">${sunSvg}</div>
    <div class="login-title">Publisher login</div>
    <div class="login-sub">Komorebi Affiliate Network</div>
    ${success ? `<div class="login-ok">${H(success)}</div>` : ''}
    ${error   ? `<div class="login-err">${H(error)}</div>`   : ''}
    <form method="POST" action="/publisher/login">
      ${next ? `<input type="hidden" name="next" value="${H(next)}">` : ''}
      <div class="login-fg"><label>Username</label>
        <input type="text" name="username" value="${H(username||'')}" required autofocus autocomplete="username"></div>
      <div class="login-fg"><label>Password</label>
        <input type="password" name="password" required autocomplete="current-password"></div>
      <button type="submit" class="login-btn">Sign in</button>
    </form>
    <div class="login-link"><a href="/publisher/forgot-password">Forgot password?</a></div>
    <div class="login-link">Don't have an account? <a href="/publisher/register">Apply to join →</a></div>
  </div>
</div>`);
}

function renderForgotPassword({ error, success } = {}) {
  return pubLayout('Forgot Password', `
<div class="login-page">
  <div class="login-card">
    <div class="login-title">Reset your password</div>
    <div class="login-sub">Enter your account email and we'll send a reset link.</div>
    ${success ? `<div class="login-ok">${H(success)}</div>` : ''}
    ${error   ? `<div class="login-err">${H(error)}</div>`   : ''}
    ${success ? '' : `<form method="POST" action="/publisher/forgot-password">
      <div class="login-fg"><label>Email</label>
        <input type="email" name="email" required autofocus autocomplete="email"></div>
      <button type="submit" class="login-btn">Send reset link</button>
    </form>`}
    <div class="login-link"><a href="/publisher/login">← Back to login</a></div>
  </div>
</div>`);
}

function renderResetPassword({ token, error, invalid } = {}) {
  if (invalid) {
    return pubLayout('Reset Password', `
<div class="login-page">
  <div class="login-card">
    <div class="login-title">Link expired</div>
    <div class="login-err">This password reset link is invalid or has expired. Reset links are valid for 24 hours.</div>
    <div class="login-link"><a href="/publisher/forgot-password">Request a new link →</a></div>
  </div>
</div>`);
  }
  return pubLayout('Reset Password', `
<div class="login-page">
  <div class="login-card">
    <div class="login-title">Choose a new password</div>
    ${error ? `<div class="login-err">${H(error)}</div>` : ''}
    <form method="POST" action="/publisher/reset-password" autocomplete="off">
      <input type="hidden" name="token" value="${H(token)}">
      <div class="login-fg"><label>New Password</label>
        <input type="password" name="new_password" required minlength="8" autofocus autocomplete="new-password"></div>
      <div class="login-fg"><label>Confirm New Password</label>
        <input type="password" name="confirm_password" required minlength="8" autocomplete="new-password"></div>
      <button type="submit" class="login-btn">Update password</button>
    </form>
    <div class="login-link"><a href="/publisher/login">← Back to login</a></div>
  </div>
</div>`);
}

function renderPubConversions({ pub, conversions }) {
  // F17 — show loan_amount / revenue columns only when at least one row has them.
  const showLoan    = conversions.some(c => c.loan_amount != null);
  const showRevenue = conversions.some(c => c.revenue != null);
  const showSub     = conversions.some(c => c.af_sub1 != null);  // Backlog #17 — sub-affiliate column
  const fmtNum = v => v != null ? Number(v).toLocaleString('en-US') : '—';
  const rows = conversions.map(r => `<tr>
    <td style="white-space:nowrap;font-size:11px">${H(r.received_at.slice(0,10))}</td>
    <td>${H(r.adv_name||r.advertiser_slug)}</td>
    <td><code class="xs">${H(r.click_id)}</code></td>
    <td><span class="badge">${H(r.event)}</span></td>
    ${showSub     ? `<td>${r.af_sub1 ? `<code class="xs">${H(r.af_sub1)}</code>` : ''}</td>` : ''}
    ${showLoan    ? `<td>${fmtNum(r.loan_amount)}</td>` : ''}
    ${showRevenue ? `<td>${fmtNum(r.revenue)}</td>` : ''}
    <td>${fmtCur(r.payout, r.currency)}</td>
    <td><span class="badge ${H(r.status||'pending')}">${H(r.status||'pending')}</span>
        ${r.reason ? `<div style="font-size:10px;color:#6e6e73;margin-top:2px">${H(r.reason)}</div>` : ''}</td>
  </tr>`).join('');

  const body = `<main>
<section>
  <div class="sh"><h2>Conversion History</h2><span class="meta">${N(conversions.length)} conversions (last 500)</span></div>
  ${rows.length===0
    ? '<div class="empty">No conversions recorded yet.</div>'
    : `<table><thead><tr><th>Date</th><th>Advertiser</th><th>Click ID</th><th>Event</th>${showSub?'<th>Sub-Aff</th>':''}${showLoan?'<th>Loan Amount</th>':''}${showRevenue?'<th>Revenue</th>':''}<th>Payout</th><th>Status</th></tr></thead>
        <tbody>${rows}</tbody></table>`}
</section>
</main>`;
  return pubLayout(`${pub.username} — Conversions`, body, pub, 'conversions');
}

function renderPubPayments({ pub, payments, totalPaid, approvedByCurrency = [], approvedBalUsd = 0 }) {
  const minPay  = pub.minimum_payout ?? 50;
  const balance = approvedBalUsd - totalPaid; // USD-only (payments + threshold are USD)
  const rows    = payments.map(p => `<tr>
    <td>${H(p.paid_at)}</td>
    <td><strong style="color:#0F6E56">${usdVnd(p.amount_usd)}</strong></td>
    <td>${H(p.method)}</td>
    <td style="font-size:11px;color:#6e6e73">${H(p.notes)}</td>
  </tr>`).join('');

  // F17 — payment timeline: payouts are processed on the first of each month.
  const now = new Date();
  const nextPay = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1));
  const nextPayStr = nextPay.toLocaleDateString('en-GB', { day: '2-digit', month: 'long', year: 'numeric', timeZone: 'UTC' });

  const body = `<main>
<div style="background:#eef2ff;border:1px solid #c7d2fe;border-radius:10px;padding:12px 18px;margin-bottom:20px;font-size:13px;color:#3730a3">
  📅 <strong>Expected next payment:</strong> ${nextPayStr} (first day of next month).
</div>
<div class="cards" style="margin-bottom:20px">
  <div class="card"><div class="lbl">Total Paid Out (USD)</div><div class="val blue">$${$(totalPaid)}</div></div>
  <div class="card"><div class="lbl">Approved Earnings</div><div class="val green" style="font-size:18px">${fmtByCurrency(approvedByCurrency)}</div></div>
  <div class="card"><div class="lbl">Outstanding Balance (USD)</div><div class="val ${balance>0?'green':''}" style="${balance<0?'color:#c62828':''}">$${$(balance)}</div></div>
  <div class="card"><div class="lbl">Minimum Payout</div><div class="val" style="font-size:18px">$${$(minPay)}</div></div>
</div>
<div style="background:${balance>=minPay?'#e8f5ef':'#f5f5f7'};border:1px solid ${balance>=minPay?'#0F6E56':'#e0e0e0'};border-radius:10px;padding:13px 18px;margin-bottom:20px;font-size:13px">
  ${balance>=minPay
    ? `✓ <strong>Payout available.</strong> Your outstanding balance ($${$(balance)}) exceeds the minimum ($${$(minPay)}). Contact your account manager to request payment.`
    : `You need $${$(Math.max(0,minPay-balance))} more in approved earnings to reach the $${$(minPay)} minimum payout threshold.`}
</div>
<section>
  <div class="sh"><h2>Payment History</h2>${payments.length>0?`<span class="meta">Total paid: <strong>$${$(totalPaid)}</strong> (${vnd(totalPaid)})</span>`:''}
  </div>
  ${rows.length===0
    ? '<div class="empty">No payments recorded yet. Contact your account manager when your balance reaches the minimum threshold.</div>'
    : `<table><thead><tr><th>Date</th><th>Amount</th><th>Method</th><th>Notes</th></tr></thead><tbody>${rows}</tbody></table>`}
</section>
</main>`;
  return pubLayout(`${pub.username} — Payments`, body, pub, 'payments');
}

function renderPubApiAccess({ pub }) {
  const suffix = pub.api_key_suffix || (pub.api_key ? pub.api_key.slice(-8) : null);
  const body = `
<main>
<section>
  <div class="sh"><h2>API Access</h2></div>
  <div style="padding:20px 22px">
    ${pub.api_key_hash ? `
    <p style="font-size:13px;color:#6e6e73;margin-bottom:14px">Use your API key with the <code>X-API-Key</code> header to fetch your stats programmatically. See <a href="/docs#rest-api" style="color:#0F6E56">documentation</a> for details.</p>
    <div style="display:flex;gap:8px;align-items:center;margin-bottom:8px">
      <input type="text" value="••••••••••• (saved)" readonly disabled
             style="font-family:monospace;font-size:12px;flex:1;background:#f5f5f7;border:1px solid #d2d2d7;border-radius:7px;padding:8px 11px;color:#6e6e73">
      ${suffix ? `<code style="font-size:11px;color:#0F6E56">…${H(suffix)}</code>` : ''}
    </div>
    <p style="font-size:11px;color:#9ca3af;margin-bottom:18px">For security, your full key is shown only once — at the moment it is (re)generated. If you've lost it, ask your account manager to regenerate it.</p>
    <div style="background:#f5f5f7;border-radius:5px;padding:8px 11px;font-size:11px;color:#555;font-family:monospace;margin-bottom:20px">curl -H "X-API-Key: kom_live_…" ${H(BASE_URL)}/api/v1/stats</div>
    <h3 style="font-size:13px;font-weight:600;margin-bottom:10px">Example Response</h3>
    <pre style="background:#f5f5f7;border-radius:8px;padding:14px;font-size:11px;overflow-x:auto;color:#333">GET /api/v1/stats → { publisher, status, stats: { clicks, conversions, earnings }, by_advertiser }</pre>
    ` : `<div style="color:#c62828;font-size:13px">Your API key has been revoked. Contact your account manager to issue a new one.</div>`}
  </div>
</section>
</main>
<script>${CP_JS}</script>`;
  return pubLayout(`${pub.username} — API Access`, body, pub, 'api');
}

function renderPubProfile({ pub, csrfToken = '', flash, error }) {
  const body = `
<main>
<section style="margin-bottom:20px">
  <div class="sh"><h2>Account</h2></div>
  <div style="padding:18px 22px;font-size:13px;color:#333">
    <div style="margin-bottom:8px"><strong>Username:</strong> ${H(pub.username)}</div>
    <div style="margin-bottom:8px"><strong>Email:</strong> ${H(pub.email || '—')}</div>
    <div style="margin-bottom:8px"><strong>Company:</strong> ${H(pub.company || '—')}</div>
    <div><strong>Member since:</strong> ${H((pub.created_at || '').slice(0,10) || '—')}</div>
  </div>
</section>
<section>
  <div class="sh"><h2>Change Password</h2></div>
  <div style="padding:18px 22px;max-width:420px">
    ${flash  ? `<div class="login-ok"  style="margin-bottom:14px">${H(flash)}</div>`  : ''}
    ${error  ? `<div class="login-err" style="margin-bottom:14px">${H(error)}</div>` : ''}
    <form method="POST" action="/publisher/change-password" autocomplete="off">${csrfField(csrfToken)}
      <div class="fg" style="margin-bottom:12px">
        <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px">Current Password</label>
        <input type="password" name="current_password" required autocomplete="current-password"
               style="width:100%;padding:9px 11px;border:1px solid #d2d2d7;border-radius:7px;font-size:13px">
      </div>
      <div class="fg" style="margin-bottom:12px">
        <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px">New Password</label>
        <input type="password" name="new_password" required minlength="8" autocomplete="new-password"
               style="width:100%;padding:9px 11px;border:1px solid #d2d2d7;border-radius:7px;font-size:13px">
        <small style="color:#6e6e73">At least 8 characters.</small>
      </div>
      <div class="fg" style="margin-bottom:16px">
        <label style="display:block;font-size:12px;font-weight:600;margin-bottom:4px">Confirm New Password</label>
        <input type="password" name="confirm_password" required minlength="8" autocomplete="new-password"
               style="width:100%;padding:9px 11px;border:1px solid #d2d2d7;border-radius:7px;font-size:13px">
      </div>
      <button type="submit" class="btn btn-primary">Update Password</button>
    </form>
  </div>
</section>
</main>
${flash ? `<script>document.addEventListener('DOMContentLoaded',function(){showToast(${JSON.stringify(flash)},'success');});</script>` : ''}`;
  return pubLayout(`${pub.username} — Profile`, body, pub, 'profile');
}

function renderPubDashboard({ pub, totalClicks, totalConversions,
  totalPayout, approvedByCurrency = [], pendingByCurrency = [], monthlyApprovedByCurrency = [], monthlyPendingByCurrency = [],
  advStats, recent, thisMonth, payments = [], totalPaid = 0, subStats = [] }) {

  // F17 — "Last updated" caption shown under each stats card (server time, no polling).
  const updatedNote = `<div style="font-size:9px;color:#9ca3af;margin-top:5px">Updated ${H(new Date().toLocaleString('en-GB', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', hour12: false }))}</div>`;

  // F7 — Sub ID (sub1) performance breakdown
  const subSection = subStats.length === 0 ? '' : `
<section>
  <div class="sh"><h2>Sub ID Breakdown</h2><span class="meta">By sub1 · top ${subStats.length}</span></div>
  <table><thead><tr><th>Sub1</th><th>Clicks</th><th>Conversions</th><th>Payout</th><th>CVR</th></tr></thead>
    <tbody>${subStats.map(s => `<tr>
      <td><code class="xs">${H(s.sub1)}</code></td>
      <td>${N(s.clicks)}</td>
      <td>${N(s.conversions)}</td>
      <td>${fmtCur(s.payout, s.currency)}</td>
      <td>${cvr(s.clicks, s.conversions)}</td>
    </tr>`).join('')}</tbody></table>
</section>`;

  const minPay  = pub.minimum_payout ?? 50;
  const balance = totalPayout - totalPaid;   // approved earnings minus paid out
  const payable = balance >= minPay;

  // ── Onboarding checklist ────────────────────────────────────────────────
  const step = (done, label, sub = '') => {
    const icon = done
      ? `<svg width="18" height="18" viewBox="0 0 18 18" fill="none"><circle cx="9" cy="9" r="9" fill="#0F6E56"/><path d="M5 9l3 3 5-5" stroke="#fff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>`
      : `<svg width="18" height="18" viewBox="0 0 18 18" fill="none"><circle cx="9" cy="9" r="8.5" stroke="#d2d2d7"/></svg>`;
    return `<div style="display:flex;align-items:flex-start;gap:12px;padding:11px 0;border-bottom:1px solid #f5f5f7">
      <div style="margin-top:1px;flex-shrink:0">${icon}</div>
      <div>
        <div style="font-size:13px;font-weight:${done?'600':'400'};color:${done?'#1d1d1f':'#6e6e73'}">${label}</div>
        ${sub ? `<div style="font-size:11px;color:#8e8e93;margin-top:2px">${sub}</div>` : ''}
      </div>
    </div>`;
  };

  const allDone = advStats.length > 0 && totalClicks > 0 && totalConversions > 0;
  const checklist = `
<section style="margin-bottom:20px">
  <div class="sh"><h2>Getting Started</h2><span class="meta">${allDone ? '✓ All steps complete' : `${[true, advStats.length>0, true, totalClicks>0, totalConversions>0].filter(Boolean).length} of 5 complete`}</span></div>
  <div style="padding:4px 20px 8px">
    ${step(true,          'Account approved',             'Your account is active and ready to use.')}
    ${step(advStats.length > 0, 'Get your tracking links', 'Find your unique URLs in the table below — click to copy.')}
    ${step(false,         'Set up postback with your MMP', 'Configure Komorebi as a partner in AppsFlyer or Adjust. See <a href="/docs#postback-setup" style="color:#0F6E56">documentation</a>.')}
    ${step(totalClicks > 0, 'Send a test click',          totalClicks > 0 ? `${N(totalClicks)} click${totalClicks===1?'':'s'} recorded.` : 'Click one of your tracking links to verify the link is working.')}
    ${step(totalConversions > 0, 'View your first conversion', totalConversions > 0 ? `${N(totalConversions)} conversion${totalConversions===1?'':'s'} recorded.` : 'Once a postback fires successfully, your conversion will appear below.')}
  </div>
</section>`;

  // ── Payout status banner ─────────────────────────────────────────────────
  const payoutBanner = `
<div style="background:${payable?'#e8f5ef':'#f5f5f7'};border:1px solid ${payable?'#0F6E56':'#e0e0e0'};border-radius:10px;padding:13px 18px;margin-bottom:20px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px">
  <div>
    <div style="font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:${payable?'#0F6E56':'#6e6e73'};margin-bottom:3px">
      ${payable ? '✓ Payout available' : 'Payout threshold not yet reached'}
    </div>
    <div style="font-size:13px;color:#1d1d1f">
      Minimum payout: <strong>$${$(minPay)}</strong> &nbsp;·&nbsp;
      Approved USD balance: <strong style="color:#0F6E56">$${$(balance)}</strong>
      ${totalPaid > 0 ? `&nbsp;·&nbsp; Total paid out: <strong>$${$(totalPaid)}</strong>` : ''}
    </div>
  </div>
  ${payable ? `<div style="font-size:12px;color:#0F6E56;font-weight:600">Contact your account manager to request payment →</div>` : `<div style="font-size:12px;color:#8e8e93">$${$(minPay - balance)} more needed</div>`}
</div>`;

  // ── Rows ─────────────────────────────────────────────────────────────────
  const advRows = advStats.map(a => `<tr>
    <td><strong>${H(a.name)}</strong></td>
    <td><div class="ubox" data-copy="${H(a.trackingUrl)}">${H(a.trackingUrl)}</div></td>
    <td>${N(a.clicks)}</td>
    <td>${N(a.approved_count)} ${a.pending_count > 0 ? `<span style="color:#f57f17;font-size:10px">+${a.pending_count} pending</span>` : ''}</td>
    <td>
      <span style="color:#0F6E56;font-weight:600">${fmtCur(a.approved_payout, a.currency)}</span>
      ${a.pending_payout > 0 ? `<div style="font-size:10px;color:#f57f17">${fmtCur(a.pending_payout, a.currency)} pending</div>` : ''}
    </td>
    <td>${cvr(a.clicks, a.conversions)}</td>
  </tr>`).join('');

  // F17 — for percentage-based (loan) conversions, show the payout calculation.
  const fmtNum = v => Number(v).toLocaleString('en-US');
  const recentRows = recent.map(r => {
    const showCalc = r.loan_amount != null && r.loan_amount > 0 && r.payout > 0;
    const pct = showCalc ? +(r.payout / r.loan_amount * 100).toFixed(4) : null;
    const calc = showCalc
      ? `<div style="font-size:10px;color:#6e6e73;margin-top:2px">${fmtNum(r.loan_amount)} VND × ${pct}% = ${fmtNum(r.payout)} VND</div>`
      : '';
    return `<tr>
    <td>${H(r.received_at)}</td>
    <td>${H(r.adv_name||r.advertiser_slug)}</td>
    <td><code class="xs">${H(r.click_id)}</code></td>
    <td><span class="badge">${H(r.event)}</span></td>
    <td>${fmtCur(r.payout, r.currency)}${calc}</td>
    <td><span class="badge ${H(r.status||'pending')}">${H(r.status||'pending')}</span>
        ${r.reason ? `<div style="font-size:10px;color:#6e6e73;margin-top:2px">${H(r.reason)}</div>` : ''}</td>
  </tr>`;
  }).join('');

  const paymentRows = payments.map(p => `<tr>
    <td>${H(p.paid_at)}</td>
    <td><strong style="color:#0F6E56">${usdVnd(p.amount_usd)}</strong></td>
    <td>${H(p.method)}</td>
    <td style="font-size:11px;color:#6e6e73">${H(p.notes)}</td>
  </tr>`).join('');

  const body = `<main>

${checklist}

<div class="cards">
  <div class="card"><div class="lbl">Total Clicks</div><div class="val">${N(totalClicks)}</div>${updatedNote}</div>
  <div class="card"><div class="lbl">Total Conversions</div><div class="val">${N(totalConversions)}</div>${updatedNote}</div>
  <div class="card hero">
    <div class="lbl">Your Approved Balance</div>
    <div class="val" style="font-size:20px">${fmtByCurrency(approvedByCurrency)}</div>
    <div style="font-size:11px;color:#0a7c5c;margin-top:8px">USD payout when balance ≥ $${$(minPay)}</div>
    ${updatedNote}
  </div>
  <div class="card"><div class="lbl">Pending Earnings</div><div class="val" style="color:#f57f17;font-size:18px">${fmtByCurrency(pendingByCurrency)}</div>${updatedNote}</div>
  <div class="card"><div class="lbl">This Month Approved</div><div class="val blue" style="font-size:18px">${fmtByCurrency(monthlyApprovedByCurrency)}</div>${updatedNote}</div>
  <div class="card"><div class="lbl">This Month Pending</div><div class="val" style="color:#f57f17;font-size:18px">${fmtByCurrency(monthlyPendingByCurrency)}</div>${updatedNote}</div>
  ${(() => { const qs = publisherQualityScore(pub.username); return `<div class="card"><div class="lbl">Traffic Quality Score</div><div class="val" style="font-size:20px;color:${GRADE_COLOR[qs.grade]}">${N(qs.score)} <span style="font-size:13px">(${qs.grade})</span></div>${updatedNote}</div>`; })()}
</div>

${payoutBanner}

<section>
  <div class="sh"><h2>Tracking Links &amp; Earnings</h2><span class="meta">Click any URL to copy</span></div>
  ${advStats.length===0
    ? '<div class="empty">No active advertisers yet. Contact your account manager.</div>'
    : `<table><thead><tr><th>Advertiser</th><th>Your Tracking URL</th><th>Clicks</th><th>Conversions</th><th>Earnings</th><th>CVR</th></tr></thead>
        <tbody>${advRows}</tbody></table>`}
</section>

${subSection}

<section>
  <div class="sh">
    <h2>Recent Conversions</h2>
    <a href="/publisher/conversions" class="btn btn-ghost" style="font-size:11px">View all →</a>
  </div>
  ${recentRows.length===0
    ? '<div class="empty">No conversions recorded yet.</div>'
    : `<table><thead><tr><th>Date</th><th>Advertiser</th><th>Click ID</th><th>Event</th><th>Payout</th><th>Status</th></tr></thead>
        <tbody>${recentRows}</tbody></table>`}
</section>

</main>
<script>${CP_JS}</script>`;

  return pubLayout(`${pub.username} — Dashboard`, body, pub, 'dashboard');
}

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Funnel SVG helper
// ---------------------------------------------------------------------------

function funnelSvg(stages) {
  // stages: [{ label, value, color }]  — first stage is always the widest (100%)
  const LABEL_W = 134, BAR_MAX = 310, RIGHT_W = 90;
  const TOTAL_W = LABEL_W + BAR_MAX + RIGHT_W;
  const BAR_H   = 40, CONN_H = 30;
  const TOTAL_H = stages.length * BAR_H + (stages.length - 1) * CONN_H + 16;
  const top     = stages[0]?.value || 1;

  const rows = stages.map((s, i) => {
    const ratio   = top > 0 ? s.value / top : 0;
    const barW    = Math.max(8, Math.round(ratio * BAR_MAX));
    const barX    = LABEL_W + Math.round((BAR_MAX - barW) / 2);
    const barY    = i * (BAR_H + CONN_H) + 8;
    const textMid = barY + BAR_H / 2 + 4;
    const pctLbl  = i === 0 ? '100%' : `${(ratio * 100).toFixed(1)}%`;

    const bar   = `<rect x="${barX}" y="${barY}" width="${barW}" height="${BAR_H}" fill="${s.color}" rx="5" opacity=".88"/>`;
    const lbl   = `<text x="${LABEL_W - 8}" y="${textMid}" text-anchor="end" font-size="12" font-weight="600" fill="#1d1d1f">${s.label}</text>`;
    const count = `<text x="${barX + barW / 2}" y="${textMid}" text-anchor="middle" font-size="12" font-weight="700" fill="#fff">${N(s.value)}</text>`;
    const pct   = `<text x="${LABEL_W + BAR_MAX + 8}" y="${textMid}" font-size="11" fill="#6e6e73">${pctLbl}</text>`;

    let conn = '';
    if (i < stages.length - 1) {
      const prev     = stages[i].value;
      const next     = stages[i + 1].value;
      const dropPct  = prev > 0 ? ((prev - next) / prev * 100).toFixed(1) : '0';
      const cx       = LABEL_W + BAR_MAX / 2;
      const lineY1   = barY + BAR_H + 3;
      const lineY2   = lineY1 + CONN_H - 6;
      const textY    = lineY1 + CONN_H / 2;
      conn = `<line x1="${cx}" y1="${lineY1}" x2="${cx}" y2="${lineY2}" stroke="#d2d2d7" stroke-width="1.5" stroke-dasharray="3,3"/>
        <polygon points="${cx-4},${lineY2} ${cx+4},${lineY2} ${cx},${lineY2+5}" fill="#d2d2d7"/>
        <text x="${cx + 10}" y="${textY + 4}" font-size="10" fill="#aaa">▾ ${dropPct}% drop-off</text>`;
    }

    return [bar, lbl, count, pct, conn].join('\n    ');
  }).join('\n    ');

  return `<svg viewBox="0 0 ${TOTAL_W} ${TOTAL_H}" style="width:100%;max-width:${TOTAL_W}px;height:auto;display:block;overflow:visible">
  <style>text{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}</style>
  ${rows}
</svg>`;
}

// ---------------------------------------------------------------------------
// Per-advertiser analytics page
// ---------------------------------------------------------------------------

function renderAnalyticsPage({ adv, dailyClicks, dailyConv, geoBreakdown,
  deviceBreakdown, osBreakdown, browserBreakdown, totalClicksAdv, totalConvAdv,
  convStatus = {}, subAffBreakdown = [] }) {
  // Backlog #17 — "By Sub-Affiliate" section
  const subAffSection = subAffBreakdown.length === 0 ? '' : `
<section>
  <div class="sh"><h2>By Sub-Affiliate</h2><span class="meta">af_sub1 · ${subAffBreakdown.length}</span></div>
  <table><thead><tr><th>Sub-Affiliate (af_sub1)</th><th>Clicks</th><th>Conversions</th><th>Payout</th><th>CVR</th></tr></thead>
    <tbody>${subAffBreakdown.map(s => `<tr>
      <td><code class="xs">${H(s.af_sub1)}</code></td>
      <td>${N(s.clicks)}</td><td>${N(s.conversions)}</td>
      <td>$${$(s.payout)}</td>
      <td>${s.clicks > 0 ? ((s.conversions / s.clicks) * 100).toFixed(1) + '%' : '—'}</td>
    </tr>`).join('')}</tbody></table>
</section>`;

  // Build 30-day array
  const days = [];
  for (let i = 29; i >= 0; i--) {
    const d = new Date(Date.now() - i * 86400000);
    days.push(d.toISOString().slice(0, 10));
  }
  const clickMap = Object.fromEntries(dailyClicks.map(r => [r.day, r.n]));
  const convMap  = Object.fromEntries(dailyConv.map(r => [r.day, r.n]));
  const cData    = days.map(d => clickMap[d] || 0);
  const kData    = days.map(d => convMap[d]  || 0);
  const maxVal   = Math.max(...cData, 1);

  // SVG bar chart (760 × 180 viewBox)
  const CW = 760, CH = 180, PL = 38, PB = 26, PT = 12;
  const iW = CW - PL - 8, iH = CH - PB - PT;
  const slotW = iW / days.length;
  const bW    = Math.max(2, Math.floor(slotW * 0.55));
  const kW    = Math.max(1, Math.floor(bW * 0.45));

  const clickBars = cData.map((v, i) => {
    const bh = Math.max(1, Math.round((v / maxVal) * iH));
    const x  = PL + i * slotW + 1;
    return `<rect x="${x.toFixed(1)}" y="${(PT + iH - bh).toFixed(1)}" width="${bW}" height="${bh}" fill="#0071e3" opacity=".75" rx="1"/>`;
  }).join('');

  const convBars = kData.map((v, i) => {
    if (!v) return '';
    const bh = Math.max(1, Math.round((v / maxVal) * iH));
    const x  = PL + i * slotW + 1 + bW - kW;
    return `<rect x="${x.toFixed(1)}" y="${(PT + iH - bh).toFixed(1)}" width="${kW}" height="${bh}" fill="#2e7d32" opacity=".9" rx="1"/>`;
  }).join('');

  const xLabels = days.map((d, i) => {
    if (i % 5 !== 0 && i !== days.length - 1) return '';
    const x = PL + i * slotW + slotW / 2;
    return `<text x="${x.toFixed(1)}" y="${CH - 6}" text-anchor="middle" font-size="9" fill="#8e8e93">${d.slice(5)}</text>`;
  }).join('');

  const yTop = `<text x="${PL - 4}" y="${PT + 8}" text-anchor="end" font-size="9" fill="#8e8e93">${maxVal}</text>`;
  const yMid = `<text x="${PL - 4}" y="${PT + Math.round(iH / 2) + 4}" text-anchor="end" font-size="9" fill="#8e8e93">${Math.round(maxVal / 2)}</text>`;
  const gridMid = `<line x1="${PL}" y1="${PT + Math.round(iH / 2)}" x2="${CW - 8}" y2="${PT + Math.round(iH / 2)}" stroke="#f0f0f0" stroke-width="1"/>`;

  const svg = `<svg viewBox="0 0 ${CW} ${CH}" style="width:100%;height:auto;display:block;overflow:visible">
    <line x1="${PL}" y1="${PT}" x2="${PL}" y2="${PT + iH}" stroke="#e8e8ed" stroke-width="1"/>
    <line x1="${PL}" y1="${PT + iH}" x2="${CW - 8}" y2="${PT + iH}" stroke="#e8e8ed" stroke-width="1"/>
    ${gridMid}${yTop}${yMid}
    ${clickBars}${convBars}${xLabels}
    <rect x="${CW - 110}" y="${PT + 2}" width="8" height="8" fill="#0071e3" opacity=".75" rx="1"/>
    <text x="${CW - 98}" y="${PT + 10}" font-size="10" fill="#6e6e73">Clicks</text>
    <rect x="${CW - 110}" y="${PT + 16}" width="8" height="8" fill="#2e7d32" opacity=".9" rx="1"/>
    <text x="${CW - 98}" y="${PT + 24}" font-size="10" fill="#6e6e73">Conversions</text>
  </svg>`;

  // Geo table
  const geoTotal = geoBreakdown.reduce((s, r) => s + r.n, 0) || 1;
  const geoRows  = geoBreakdown.map(r => {
    const pct = Math.round((r.n / geoTotal) * 100);
    return `<tr>
      <td><strong>${H(r.country)}</strong> <span style="font-size:11px;color:#6e6e73">${H(countryName(r.country))}</span></td>
      <td>${N(r.n)}</td>
      <td style="min-width:140px">
        <div style="display:flex;align-items:center;gap:8px">
          <div style="flex:1;background:#f0f0f0;border-radius:3px;height:6px">
            <div style="width:${pct}%;background:#0071e3;border-radius:3px;height:6px"></div>
          </div>
          <span style="font-size:11px;color:#6e6e73;width:32px;text-align:right">${pct}%</span>
        </div>
      </td>
    </tr>`;
  }).join('');

  // Breakdown helper
  function splitSection(title, rows, colorMap = {}) {
    const total = rows.reduce((s, r) => s + r.n, 0) || 1;
    const items = rows.map(r => {
      const key   = r.device_type || r.os || r.browser;
      const color = colorMap[key] || '#6e6e73';
      const pct   = Math.round((r.n / total) * 100);
      return `<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
        <div style="width:70px;font-size:12px;flex-shrink:0">${H(key)}</div>
        <div style="flex:1;background:#f0f0f0;border-radius:3px;height:8px">
          <div style="width:${pct}%;background:${color};border-radius:3px;height:8px"></div>
        </div>
        <div style="width:60px;text-align:right;font-size:12px;color:#6e6e73">${N(r.n)} <strong>${pct}%</strong></div>
      </div>`;
    }).join('');
    return `<div style="margin-bottom:0">
      <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:#6e6e73;margin-bottom:12px">${title}</div>
      ${items || '<div style="color:#8e8e93;font-size:12px">No data yet</div>'}
    </div>`;
  }

  const deviceColors = { mobile: '#0071e3', desktop: '#2e7d32', tablet: '#f57f17' };
  const osColors     = { Android: '#2e7d32', iOS: '#0071e3', Windows: '#9c27b0', Mac: '#f57f17', Linux: '#607d8b' };
  const browserColors= { Chrome: '#f57f17', Safari: '#0071e3', Firefox: '#c62828', Edge: '#2e7d32' };

  const body = `${adminHeader(`
    <a href="/admin/advertisers/${H(adv.slug)}/analytics?period=7" class="hbtn ghost">7d</a>
    <a href="/admin/advertisers/${H(adv.slug)}/analytics" class="hbtn ghost">30d</a>
    <a href="/admin/advertisers/${H(adv.slug)}/reconcile" class="hbtn ghost">Reconcile</a>
    <a href="/admin" class="hbtn ghost">← Dashboard</a>`)}
<main>

<div class="cards">
  <div class="card"><div class="lbl">Total Clicks (all time)</div><div class="val">${N(totalClicksAdv)}</div></div>
  <div class="card"><div class="lbl">Total Conversions (all time)</div><div class="val">${N(totalConvAdv)}</div></div>
  <div class="card"><div class="lbl">CVR (all time)</div><div class="val">${cvr(totalClicksAdv, totalConvAdv)}</div></div>
  <div class="card"><div class="lbl">Clicks (last 30d)</div><div class="val">${N(cData.reduce((a, b) => a + b, 0))}</div></div>
  <div class="card"><div class="lbl">Conversions (last 30d)</div><div class="val">${N(kData.reduce((a, b) => a + b, 0))}</div></div>
</div>

<section>
  <div class="sh"><h2>Conversion Funnel</h2><span class="meta">all time</span></div>
  <div style="padding:20px 28px">
    ${funnelSvg([
      { label: 'Clicks',      value: totalClicksAdv,              color: '#0071e3' },
      { label: 'Conversions', value: totalConvAdv,                color: '#7c3aed' },
      { label: 'Approved',    value: convStatus.approved || 0,    color: '#2e7d32' },
      { label: 'Pending',     value: convStatus.pending  || 0,    color: '#f57f17' },
      { label: 'Rejected',    value: convStatus.rejected || 0,    color: '#c62828' },
    ])}
  </div>
</section>

<section>
  <div class="sh"><h2>Clicks &amp; Conversions — Last 30 Days</h2></div>
  <div style="padding:16px 20px 10px">${svg}</div>
</section>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:20px">

  <section style="margin-bottom:0">
    <div class="sh"><h2>Geographic Breakdown</h2><span class="meta">by clicks</span></div>
    ${geoBreakdown.length === 0
      ? '<div class="empty">No geo data yet — clicks will be geolocated going forward.</div>'
      : `<table><thead><tr><th>Country</th><th>Clicks</th><th>Share</th></tr></thead><tbody>${geoRows}</tbody></table>`}
  </section>

  <section style="margin-bottom:0">
    <div class="sh"><h2>Device &amp; Browser Breakdown</h2></div>
    <div style="padding:18px 20px;display:flex;flex-direction:column;gap:22px">
      ${splitSection('Device', deviceBreakdown, deviceColors)}
      ${splitSection('OS', osBreakdown, osColors)}
      ${splitSection('Browser', browserBreakdown, browserColors)}
    </div>
  </section>

  ${subAffSection}

</div>

</main>`;

  return adminLayout(`Analytics — ${adv.name}`, body);
}

// ---------------------------------------------------------------------------
// Legal pages  /terms  /privacy
// ---------------------------------------------------------------------------

function renderLegal(page) {
  const LEGAL_CSS = `
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f9fafb;color:#1d1d1f;font-size:15px;line-height:1.7}
    a{color:#0F6E56;text-decoration:none}a:hover{text-decoration:underline}
    .topbar{background:#0F6E56;padding:0 32px;height:56px;display:flex;align-items:center;justify-content:space-between;box-shadow:0 2px 8px rgba(15,110,86,.3)}
    .topbar a{text-decoration:none}
    .topbar .links{display:flex;gap:16px;align-items:center}
    .topbar .links a{color:rgba(255,255,255,.8);font-size:13px;font-weight:500}
    .topbar .links a:hover{color:#fff}
    .topbar .login-link{background:#fff;color:#0F6E56;padding:5px 14px;border-radius:7px;font-size:13px;font-weight:600}
    .topbar .login-link:hover{background:#e8f5ef;color:#0a5f4b;text-decoration:none}
    .wrap{max-width:800px;margin:0 auto;padding:48px 24px 80px}
    .logo-row{text-align:center;margin-bottom:40px}
    h1{font-size:28px;font-weight:700;letter-spacing:-.4px;margin-bottom:8px}
    .updated{font-size:12px;color:#8e8e93;margin-bottom:40px}
    h2{font-size:18px;font-weight:700;margin:36px 0 10px;color:#0F6E56}
    p{margin-bottom:14px;color:#3a3a3c}
    ul{margin:0 0 14px 20px;color:#3a3a3c}
    ul li{margin-bottom:6px}
    .footer{text-align:center;margin-top:60px;padding-top:24px;border-top:1px solid #e8e8ed;font-size:12px;color:#8e8e93}
    .footer a{color:#0F6E56}
  `;

  const topbar = `<div class="topbar">
    <a href="/">
      <span style="display:inline-flex;align-items:center;background:#fff;border-radius:7px;padding:3px 10px">
        <img src="/static/komorebi-logo-white.png" height="28" alt="Komorebi" style="display:block;width:auto">
      </span>
    </a>
    <div class="links">
      <a href="/docs">Docs</a>
      <a href="/terms">Terms</a>
      <a href="/privacy">Privacy</a>
      <a href="/publisher/register">Apply to Join</a>
      <a href="/publisher/login" class="login-link">Publisher Login →</a>
    </div>
  </div>`;

  const terms = `
    <h1>Terms of Service</h1>
    <div class="updated">Last updated: May 2026</div>

    <h2>1. Acceptance of Terms</h2>
    <p>By accessing or using the Komorebi Media affiliate network (the "Service"), you agree to be bound by these Terms of Service. If you do not agree, do not use the Service.</p>

    <h2>2. Publisher Accounts</h2>
    <p>Publisher accounts are subject to approval by Komorebi Media. You are responsible for maintaining the confidentiality of your credentials and for all activity under your account. Accounts may not be transferred or shared.</p>

    <h2>3. Tracking & Attribution</h2>
    <p>Conversions are tracked using server-to-server postback technology. A valid <code>click_id</code> must be present in each postback for attribution. Komorebi Media deduplicates postbacks by <code>click_id + event</code> pair.</p>

    <h2>4. Payments</h2>
    <p>Payouts are calculated based on approved conversions following the monthly reconciliation process. Komorebi Media reserves the right to withhold payment for conversions that are found to be fraudulent, duplicated, or in violation of advertiser terms.</p>

    <h2>5. Prohibited Conduct</h2>
    <ul>
      <li>Generating artificial or fraudulent clicks or conversions</li>
      <li>Misrepresenting traffic sources in your application</li>
      <li>Using brand names or trademarks without authorisation</li>
      <li>Violating any applicable laws or regulations</li>
    </ul>

    <h2>6. Termination</h2>
    <p>Komorebi Media may suspend or terminate your account at any time for violation of these terms, fraudulent activity, or for any other reason at our discretion.</p>

    <h2>7. Limitation of Liability</h2>
    <p>The Service is provided "as is". Komorebi Media shall not be liable for any indirect, incidental, or consequential damages arising from use of the Service.</p>

    <h2>8. Governing Law</h2>
    <p>These Terms are governed by the laws of Vietnam. Any disputes shall be resolved in the courts of Ho Chi Minh City.</p>

    <h2>9. Contact</h2>
    <p>Questions? Contact us at <a href="mailto:chi@komorebimedia.com">chi@komorebimedia.com</a>.</p>`;

  const privacy = `
    <h1>Privacy Policy</h1>
    <div class="updated">Last updated: May 2026</div>

    <h2>1. Information We Collect</h2>
    <p>We collect information you provide during registration (username, email, company, website, traffic sources) and information generated through your use of the Service (click data, conversion data, IP addresses, user agents).</p>

    <h2>2. How We Use Your Information</h2>
    <ul>
      <li>To operate and maintain the affiliate tracking platform</li>
      <li>To calculate and process publisher payouts</li>
      <li>To send transactional notifications (conversion alerts, daily summaries)</li>
      <li>To detect and prevent fraud</li>
      <li>To comply with legal obligations</li>
    </ul>

    <h2>3. Click & Conversion Data</h2>
    <p>Each click through a Komorebi tracking link records the click ID, timestamp, IP address, user agent, country, device type, and publisher ID. This data is used solely for attribution and fraud prevention.</p>

    <h2>4. Data Sharing</h2>
    <p>We do not sell your personal data. We may share data with advertisers in aggregate form for reporting purposes. IP addresses used for geolocation are processed locally using an offline database and are not shared with third parties.</p>

    <h2>5. Data Retention</h2>
    <p>Click and conversion data is retained for a minimum of 24 months to support reconciliation and dispute resolution. Account data is retained for the lifetime of your account plus 12 months after closure.</p>

    <h2>6. Cookies</h2>
    <p>The publisher portal uses a session cookie for authentication. This cookie is strictly necessary and does not track you across other websites.</p>

    <h2>7. Your Rights</h2>
    <p>You may request access to, correction of, or deletion of your personal data by contacting <a href="mailto:chi@komorebimedia.com">chi@komorebimedia.com</a>. We will respond within 30 days.</p>

    <h2>8. Security</h2>
    <p>Passwords are stored using scrypt hashing. API keys use cryptographically random values. All connections should be made over HTTPS in production.</p>

    <h2>9. Contact</h2>
    <p>For privacy questions, contact <a href="mailto:chi@komorebimedia.com">chi@komorebimedia.com</a>.</p>`;

  const content = page === 'terms' ? terms : privacy;

  return `<!DOCTYPE html><html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${page === 'terms' ? 'Terms of Service' : 'Privacy Policy'} — Komorebi Media</title>
<style>${LEGAL_CSS}</style></head>
<body>
${topbar}
<div class="wrap">
  <div class="logo-row">
    <img src="/static/komorebi-logo-white.png" height="56" alt="Komorebi Media" style="display:inline-block;width:auto">
  </div>
  ${content}
  <div class="footer">
    <p>&copy; ${new Date().getFullYear()} Komorebi Media · <a href="/terms">Terms of Service</a> · <a href="/privacy">Privacy Policy</a> · <a href="/docs">Documentation</a></p>
  </div>
</div>
</body></html>`;
}

// ---------------------------------------------------------------------------
// Public docs template
// ---------------------------------------------------------------------------

function renderDocs() {
  const TRACK_DOMAIN = 'https://track.komorebimedia.com';

  const DOCS_CSS = `
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    html{scroll-behavior:smooth}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#fff;color:#1d1d1f;font-size:15px;line-height:1.6}
    a{color:#0071e3;text-decoration:none}
    a:hover{text-decoration:underline}

    /* Top nav */
    .topnav{position:sticky;top:0;z-index:100;background:#0F6E56;color:#fff;padding:0 32px;height:56px;display:flex;align-items:center;justify-content:space-between;box-shadow:0 2px 8px rgba(15,110,86,.3)}
    .topnav .brand{display:flex;align-items:center}
    .topnav .nav-links{display:flex;gap:20px;align-items:center}
    .topnav .nav-links a{color:rgba(255,255,255,.8);font-size:13px;font-weight:500}
    .topnav .nav-links a:hover{color:#fff;text-decoration:none}
    .topnav .signin{background:#fff;color:#0F6E56;padding:6px 14px;border-radius:7px;font-size:13px;font-weight:600}
    .topnav .signin:hover{background:#e8f5ef;color:#0a5f4b;text-decoration:none}

    /* Layout */
    .layout{display:grid;grid-template-columns:240px 1fr;min-height:calc(100vh - 52px);max-width:1160px;margin:0 auto;padding:0 24px;gap:0}

    /* Sidebar */
    .sidebar{padding:32px 0 32px 0;border-right:1px solid #f0f0f0}
    .sidebar-inner{position:sticky;top:72px}
    .sidebar h3{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:#8e8e93;margin-bottom:10px;padding-left:14px}
    .sidebar ul{list-style:none;margin-bottom:24px}
    .sidebar ul li a{display:block;padding:5px 14px;font-size:13px;color:#3a3a3c;border-left:2px solid transparent;border-radius:0 6px 6px 0}
    .sidebar ul li a:hover{background:#f5f5f7;color:#1d1d1f;text-decoration:none;border-left-color:#d2d2d7}
    .sidebar ul li a.active{background:#e8f5ef;color:#0F6E56;border-left-color:#0F6E56;font-weight:500}

    /* Main content */
    .main{padding:40px 0 80px 48px}
    .main section{margin-bottom:64px}
    .main section:last-child{margin-bottom:0}
    .section-label{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:#0F6E56;margin-bottom:10px}
    h1.page-title{font-size:32px;font-weight:700;letter-spacing:-.5px;margin-bottom:12px;line-height:1.2}
    h2.section-title{font-size:22px;font-weight:700;letter-spacing:-.3px;margin-bottom:16px;padding-bottom:12px;border-bottom:1px solid #f0f0f0}
    h3.sub-title{font-size:16px;font-weight:600;margin:28px 0 10px}
    p{margin-bottom:14px;color:#3a3a3c}
    p:last-child{margin-bottom:0}

    /* Lead text */
    .lead{font-size:17px;color:#6e6e73;margin-bottom:32px;line-height:1.5}

    /* Callout boxes */
    .callout{border-radius:10px;padding:14px 18px;margin-bottom:20px;font-size:14px}
    .callout.info{background:#e8f0fe;border-left:3px solid #0071e3;color:#1a3a6e}
    .callout.warn{background:#fff8e1;border-left:3px solid #f5a623;color:#7a5000}
    .callout.tip{background:#e8f5e9;border-left:3px solid #34c759;color:#1a4d2a}
    .callout strong{font-weight:700}

    /* Code blocks */
    .code-block{background:#1d1d1f;border-radius:10px;padding:18px 20px;margin-bottom:20px;overflow-x:auto}
    .code-block pre{margin:0;font-family:'SF Mono',Fira Code,monospace;font-size:13px;line-height:1.7;color:#e0e0e0}
    .code-block .comment{color:#6e7e8a}
    .code-block .key{color:#79d4f4}
    .code-block .str{color:#f8b458}
    .code-block .num{color:#b5f0a5}
    .code-block .kw{color:#d9a9f5}
    .code-label{font-size:11px;font-weight:600;color:#8e8e93;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px}

    /* Inline code */
    code{background:#f5f5f7;padding:2px 6px;border-radius:4px;font-family:'SF Mono',Fira Code,monospace;font-size:13px;color:#1d1d1f}

    /* Tables */
    table{width:100%;border-collapse:collapse;margin-bottom:24px;font-size:14px}
    thead tr{background:#f5f5f7}
    th{padding:10px 14px;text-align:left;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:#6e6e73;border-bottom:2px solid #e5e5e5}
    td{padding:11px 14px;border-bottom:1px solid #f0f0f0;vertical-align:top}
    tr:last-child td{border-bottom:none}
    tr:hover td{background:#fafafa}

    /* Steps */
    .steps{counter-reset:step;list-style:none;margin-bottom:20px}
    .steps li{counter-increment:step;display:flex;gap:14px;margin-bottom:16px;align-items:flex-start}
    .steps li::before{content:counter(step);min-width:28px;height:28px;background:#0071e3;color:#fff;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;flex-shrink:0;margin-top:1px}

    /* FAQ */
    .faq-item{border:1px solid #f0f0f0;border-radius:10px;margin-bottom:12px;overflow:hidden}
    .faq-q{padding:16px 20px;font-weight:600;font-size:15px;cursor:pointer;display:flex;justify-content:space-between;align-items:center;user-select:none}
    .faq-q:hover{background:#fafafa}
    .faq-q::after{content:'+';font-size:20px;color:#6e6e73;font-weight:300;transition:transform .2s}
    .faq-item.open .faq-q::after{transform:rotate(45deg)}
    .faq-a{display:none;padding:0 20px 16px;color:#3a3a3c;font-size:14px;line-height:1.6}
    .faq-item.open .faq-a{display:block}

    /* Badges */
    .method{display:inline-block;background:#e8f5e9;color:#2e7d32;font-family:monospace;font-size:12px;font-weight:700;padding:2px 8px;border-radius:4px;margin-right:8px}
    .endpoint{font-family:monospace;font-size:14px;font-weight:600}

    /* Footer */
    footer{background:#f5f5f7;border-top:1px solid #e5e5e5;padding:32px;text-align:center;font-size:13px;color:#8e8e93;margin-top:0}

    @media(max-width:768px){
      .layout{grid-template-columns:1fr}
      .sidebar{display:none}
      .main{padding:28px 0 48px}
    }
  `;

  const macroRows = [
    ['{click_id}',   'Unique identifier for the click', 'Required — maps conversion back to the original click'],
    ['{payout}',     'Revenue amount for this conversion', 'Optional — overrides the advertiser default payout'],
    ['{event}',      'Event name (e.g. sale, lead, install)', 'Optional — defaults to <code>sale</code> if omitted'],
    ['{advertiser}', 'Advertiser slug (in URL path)', 'Set in the postback URL path, not a query macro'],
  ].map(([macro, desc, notes]) => `<tr>
    <td><code>${macro}</code></td>
    <td>${desc}</td>
    <td style="color:#6e6e73;font-size:13px">${notes}</td>
  </tr>`).join('');

  const exampleStatsJson = `{
  <span class="key">"publisher"</span>: <span class="str">"your-username"</span>,
  <span class="key">"status"</span>:    <span class="str">"active"</span>,
  <span class="key">"stats"</span>: {
    <span class="key">"clicks"</span>: <span class="num">142</span>,
    <span class="key">"conversions"</span>: {
      <span class="key">"total"</span>:    <span class="num">38</span>,
      <span class="key">"approved"</span>: <span class="num">31</span>,
      <span class="key">"pending"</span>:  <span class="num">5</span>,
      <span class="key">"rejected"</span>: <span class="num">2</span>
    },
    <span class="key">"earnings"</span>: {
      <span class="key">"approved"</span>:            <span class="num">465.00</span>,
      <span class="key">"pending"</span>:             <span class="num">75.00</span>,
      <span class="key">"this_month_approved"</span>: <span class="num">120.00</span>
    }
  },
  <span class="key">"by_advertiser"</span>: [
    {
      <span class="key">"advertiser"</span>:      <span class="str">"ACBS"</span>,
      <span class="key">"advertiser_slug"</span>: <span class="str">"acbs"</span>,
      <span class="key">"clicks"</span>:          <span class="num">98</span>,
      <span class="key">"conversions"</span>:     <span class="num">26</span>,
      <span class="key">"approved_payout"</span>: <span class="num">390.00</span>,
      <span class="key">"pending_payout"</span>:  <span class="num">60.00</span>
    }
  ]
}`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Publisher Documentation — Komorebi Media</title>
<style>${DOCS_CSS}</style>
</head>
<body>

<nav class="topnav">
  <div class="brand">
    <a href="/docs" style="display:flex;align-items:center;text-decoration:none">
      <span style="display:inline-flex;align-items:center;background:#fff;border-radius:7px;padding:3px 10px">
        <img src="/static/komorebi-logo-white.png" height="30" alt="Komorebi" style="display:block;width:auto">
      </span>
    </a>
  </div>
  <div class="nav-links">
    <a href="/docs">Docs</a>
    <a href="/terms">Terms</a>
    <a href="/privacy">Privacy</a>
    <a href="/publisher/register" style="color:rgba(255,255,255,.8);font-size:13px;font-weight:500">Apply to Join</a>
    <a href="/publisher/login" class="signin">Publisher Login →</a>
  </div>
</nav>

<div class="layout">

  <!-- Sidebar -->
  <aside class="sidebar">
    <div class="sidebar-inner">
      <h3>Contents</h3>
      <ul>
        <li><a href="#getting-started">Getting Started</a></li>
        <li><a href="#what-is-komorebi">&nbsp;&nbsp;What is Komorebi Network</a></li>
        <li><a href="#getting-an-account">&nbsp;&nbsp;Getting an Account</a></li>
      </ul>
      <ul>
        <li><a href="#tracking-links">Tracking Links</a></li>
        <li><a href="#link-format">&nbsp;&nbsp;Link Format</a></li>
        <li><a href="#link-example">&nbsp;&nbsp;Example</a></li>
      </ul>
      <ul>
        <li><a href="#postback-setup">Postback Setup</a></li>
        <li><a href="#appsflyer">&nbsp;&nbsp;AppsFlyer</a></li>
        <li><a href="#adjust">&nbsp;&nbsp;Adjust</a></li>
        <li><a href="#macros">&nbsp;&nbsp;Supported Macros</a></li>
      </ul>
      <ul>
        <li><a href="#rest-api">REST API</a></li>
        <li><a href="#api-auth">&nbsp;&nbsp;Authentication</a></li>
        <li><a href="#api-stats">&nbsp;&nbsp;GET /api/v1/stats</a></li>
      </ul>
      <ul>
        <li><a href="#faq">FAQ</a></li>
      </ul>
    </div>
  </aside>

  <!-- Main -->
  <main class="main">

    <!-- Hero -->
    <section id="getting-started">
      <div class="section-label">Documentation</div>
      <h1 class="page-title">Publisher Integration Guide</h1>
      <p class="lead">Everything you need to start sending traffic and tracking conversions on the Komorebi Affiliate Network.</p>

      <h2 class="section-title" id="what-is-komorebi">What is Komorebi Network?</h2>
      <p>Komorebi Media operates a cost-per-sale (CPS) affiliate network connecting publishers with financial product advertisers across Vietnam and Southeast Asia. When an end user completes a qualifying action — such as opening a bank account or applying for a loan — through your traffic, you earn a commission.</p>
      <p>The platform tracks every click with a unique <code>click_id</code>, records conversions via a server-to-server postback, and provides real-time reporting in your publisher portal.</p>

      <div class="callout info">
        <strong>How it works:</strong> User clicks your tracking link → lands on advertiser's offer page → completes a conversion → advertiser's MMP fires a postback to Komorebi → you see the conversion in your dashboard.
      </div>

      <h3 class="sub-title" id="getting-an-account">Getting an Account</h3>
      <p>Publisher accounts are created by the Komorebi Media team. To request access:</p>
      <ol class="steps">
        <li>Contact your Komorebi account manager and provide your company name, traffic sources, and expected volume.</li>
        <li>Once approved, you'll receive your username and a temporary password by email.</li>
        <li>Log in to the <a href="/publisher/login">publisher portal</a>, where you'll find your tracking links, earnings dashboard, and API key.</li>
      </ol>
    </section>

    <!-- Tracking Links -->
    <section id="tracking-links">
      <h2 class="section-title">Tracking Links</h2>
      <p>Use these links in your campaigns. Each click is assigned a unique <code>click_id</code> that ties the eventual conversion back to your account.</p>

      <h3 class="sub-title" id="link-format">Link Format</h3>
      <div class="code-label">URL structure</div>
      <div class="code-block"><pre>${TRACK_DOMAIN}/track/<span class="key">{advertiser}</span>?pub=<span class="str">{your_username}</span></pre></div>

      <table>
        <thead><tr><th>Parameter</th><th>Description</th><th>Required</th></tr></thead>
        <tbody>
          <tr><td><code>{advertiser}</code></td><td>The advertiser slug (provided by your account manager, e.g. <code>acbs</code>, <code>shb-finance</code>, <code>kafi</code>)</td><td>Yes</td></tr>
          <tr><td><code>pub</code></td><td>Your publisher username — used to attribute clicks and conversions to your account</td><td>Yes</td></tr>
        </tbody>
      </table>

      <h3 class="sub-title" id="link-example">Example</h3>
      <p>For a publisher with username <code>clickon</code> promoting the ACBS advertiser:</p>
      <div class="code-label">Your tracking link</div>
      <div class="code-block"><pre>${TRACK_DOMAIN}/track/<span class="key">acbs</span>?pub=<span class="str">clickon</span></pre></div>

      <p>When a user clicks this link, they are immediately redirected to the advertiser's offer page with a unique <code>click_id</code> appended:</p>
      <div class="code-label">Redirect destination (example)</div>
      <div class="code-block"><pre>https://acbs.com.vn/open-account?click_id=<span class="num">4a7f2e1c-...</span></pre></div>

      <div class="callout tip">
        <strong>Tip:</strong> Find all your pre-built tracking links — one per active advertiser — in the <a href="/publisher/login">publisher portal</a> under "Your Tracking Links &amp; Earnings".
      </div>
    </section>

    <!-- Postback Setup -->
    <section id="postback-setup">
      <h2 class="section-title">Postback Setup</h2>
      <p>Conversions are tracked via a server-to-server (S2S) postback fired by the advertiser's mobile measurement partner (MMP) — typically AppsFlyer or Adjust — when a qualifying event occurs.</p>

      <div class="callout warn">
        <strong>Important:</strong> The <code>{click_id}</code> macro must be passed through from the tracking link click to the postback. Your account manager will confirm which advertiser slug to use in the postback URL.
      </div>

      <h3 class="sub-title" id="appsflyer-onboarding">AppsFlyer Onboarding Walkthrough</h3>
      <p>Komorebi integrates with AppsFlyer as an <strong>Agency partner</strong>. Follow these steps in your AppsFlyer dashboard to grant Komorebi the access it needs and start sending attributed conversions. This mirrors AppsFlyer's exact permission and event-selection flow.</p>

      <div class="callout info">
        <strong>Before you start:</strong> have your Komorebi advertiser <code>slug</code>, your partner-link template (provided by your account manager — see <a href="#partner-link">Partner-Link Template</a>), and AppsFlyer admin access to the relevant app.
      </div>

      <ol class="steps">
        <li><strong>Add Komorebi as an Agency partner.</strong> In AppsFlyer, go to <em>Configuration → Partner Marketplace</em> (or <em>Active Integrations → Add Partner</em>), search for your agency/partner entry, and enable it for the app. If Komorebi is set up as a custom partner, use <em>Configuration → Integrated Partners → Add a dedicated partner</em> and enter the Komorebi partner ID supplied to you.</li>
        <li><strong>Set the attribution / click-through lookback window</strong> to match the value configured on the Komorebi advertiser (default <strong>90 days</strong>). A mismatch causes valid postbacks to be rejected. See <a href="#appsflyer">AppsFlyer Integration</a>.</li>
        <li><strong>Configure the tracking link.</strong> Paste Komorebi's partner-link template into the partner's <em>Attribution Link</em> / <em>Click-through URL</em>. The template injects Komorebi's <code>click_id</code> into <code>customer_user_id</code> and maps <code>af_siteid</code>, <code>af_sub1–5</code>, and <code>af_c_id</code>.</li>
        <li><strong>Grant event postbacks.</strong> Open the partner's <em>Integration → In-app events</em> tab. Toggle <em>"Send in-app events to this partner"</em> on, then select <em>"Events attributed to this partner only"</em> (recommended) and map each in-app event (e.g. <code>af_purchase</code>, <code>deposit_Trade_succeeded</code>) you want Komorebi to receive. Map those names to the matching Komorebi event under <a href="#event-mapping">Event Name Mapping</a> on the advertiser.</li>
        <li><strong>Configure the postback URL.</strong> For real-time postbacks, set the partner's <em>Postback URL</em> to Komorebi's endpoint: <code>${BASE_URL}/postback/&lt;slug&gt;?click_id={click_id}&amp;event={event_name}</code>. For pull-based reconciliation, grant Komorebi <em>Raw Data / Pull API</em> access and an API token (entered in the advertiser's MMP section).</li>
        <li><strong>Grant raw-data access (for reconciliation).</strong> Under <em>Configuration → Permissions</em>, enable raw-data report access so Komorebi's MMP sync can pull the in-app-events export and reconcile each event against the originating click.</li>
        <li><strong>Verify.</strong> Use the <a href="#postback-setup">postback test</a> or your account manager's test tool to fire a sample conversion and confirm it appears as <em>attributed</em> in Komorebi.</li>
      </ol>

      <div class="callout warn">
        <strong>The single most important step:</strong> Komorebi's <code>click_id</code> must be carried into AppsFlyer as <code>customer_user_id</code> — it is the reconciliation match key. If it is empty, conversions cannot be attributed to your traffic.
      </div>

      <h3 class="sub-title" id="hmac">HMAC Postback Signing</h3>
      <p>Komorebi supports optional per-advertiser <strong>HMAC-SHA256</strong> signing on inbound postbacks. When a postback secret is configured for an advertiser, every postback must include a valid <code>sig</code> parameter or it is rejected (HTTP 403). Leave the secret blank to accept unsigned postbacks (backward compatible).</p>
      <div class="code-label">Signature formula</div>
      <table>
        <thead><tr><th>Field</th><th>Value</th></tr></thead>
        <tbody>
          <tr><td>Base string</td><td><code>click_id + ":" + event + ":" + payout</code> (payout empty string if omitted)</td></tr>
          <tr><td>Algorithm</td><td><code>HMAC-SHA256(secret, base)</code> → lowercase hex digest</td></tr>
          <tr><td>Parameter</td><td>append <code>&amp;sig=&lt;hex digest&gt;</code> to the postback URL</td></tr>
        </tbody>
      </table>
      <div class="callout info">
        Example (pseudocode): <code>sig = hex(hmac_sha256("mysecret", "abc-123:sale:15.00"))</code>. Admins can verify the exact signed URL using the <strong>Postback Test Tool</strong> on the advertiser edit page, which signs automatically when a secret is set.
      </div>

      
      <h3 class="sub-title" id="appsflyer">AppsFlyer Integration</h3>
      <p>AppsFlyer conversions are reconciled by Komorebi's <strong>MMP sync</strong>: Komorebi pulls AppsFlyer's raw in-app-events export and matches each event back to the originating click. The match key is AppsFlyer's <strong>Customer User ID</strong> — so Komorebi's auto-generated <code>click_id</code> must be passed into AppsFlyer as the <code>customer_user_id</code>.</p>

      <div class="callout warn">
        <strong>Key requirement:</strong> Komorebi's tracking link generates a unique <code>click_id</code> on every click — you do not create it yourself. Set that value as AppsFlyer's <code>customer_user_id</code> (the SDK <code>setCustomerUserId()</code> call, or the <code>customer_user_id</code> field on a server-to-server install/event). Komorebi's sync reads the <code>Customer User ID</code> column of the AppsFlyer export and matches it back to the click — if it is empty, the conversion cannot be attributed to your traffic.
      </div>

      <ol class="steps">
        <li>Drive traffic with your Komorebi tracking link — it appends a unique <code>click_id</code> to the redirect automatically.</li>
        <li>Capture that <code>click_id</code> on the landing page (query parameter / deep link) and carry it into the app install flow.</li>
        <li>In the AppsFlyer SDK, call <code>setCustomerUserId(&lt;click_id&gt;)</code> before logging events — or send <code>customer_user_id=&lt;click_id&gt;</code> on the server-to-server call — so AppsFlyer stores Komorebi's <code>click_id</code> against that user.</li>
        <li>On each sync, Komorebi pulls the AppsFlyer in-app-events export and matches the <code>Customer User ID</code> column back to the <code>click_id</code> to approve or flag the conversion.</li>
      </ol>

      <div class="code-label">Komorebi → AppsFlyer field mapping</div>
      <table>
        <thead><tr><th>Komorebi value</th><th>AppsFlyer field (export column)</th><th>How to set it</th></tr></thead>
        <tbody>
          <tr>
            <td><code>click_id</code> — auto-generated by the tracking link</td>
            <td><code>customer_user_id</code> — the “Customer User ID” export column</td>
            <td>AppsFlyer SDK <code>setCustomerUserId()</code> or the S2S <code>customer_user_id</code> field</td>
          </tr>
        </tbody>
      </table>

      <h3 class="sub-title" id="adjust">Adjust Integration</h3>
      <p>Adjust is <strong>push-based</strong>: unlike AppsFlyer, there is <strong>no CSV export and no pull sync</strong>. Adjust fires a server-to-server (S2S) postback to Komorebi in real time the moment a conversion is attributed, and the <code>click_id</code> is carried back via Adjust's <code>{click_id}</code> macro. Conversions are recorded the instant the postback arrives — no reconciliation pull is required.</p>

      <div class="callout info">
        <strong>No export needed:</strong> Set MMP Type to <strong>Adjust</strong> on the advertiser and configure the postback URL below — you do not need an App ID or API token, and the Sync Dashboard / pull export (used for AppsFlyer) does not apply.
      </div>

      <p>To configure a custom postback in Adjust:</p>
      <ol class="steps">
        <li>Log in to your Adjust dashboard and open the app.</li>
        <li>Go to <strong>Settings → Partner Setup</strong> and click <strong>Add Partner</strong>.</li>
        <li>Select <strong>Custom Partner</strong> and enter the postback URL below.</li>
        <li>Map the <code>click_id</code> query parameter to Adjust's click ID placeholder <code>{click_id}</code>, and <code>payout</code> to <code>{revenue}</code>.</li>
        <li>Configure the event tokens you want to track (e.g. install, purchase) and assign them to the <code>event</code> parameter.</li>
      </ol>

      <div class="code-label">Adjust postback URL</div>
      <div class="code-block"><pre>${TRACK_DOMAIN}/postback/<span class="key">{advertiser}</span>?click_id=<span class="str">{click_id}</span>&amp;payout=<span class="str">{revenue}</span>&amp;event=<span class="str">{event_token}</span></pre></div>

      <h3 class="sub-title" id="signed-postbacks">Signed Postbacks (HMAC, optional)</h3>
      <p>An advertiser may be issued a <strong>postback secret</strong>. When a secret is configured, every postback for that advertiser must include a <code>sig</code> parameter or it is rejected with <code>403</code>. Advertisers without a secret accept unsigned postbacks (backward compatible).</p>
      <p>The signature is a lowercase hex <strong>HMAC-SHA256</strong> of the values joined by colons — <code>click_id:event:payout</code> — keyed by the shared secret:</p>
      <div class="code-block"><pre>sig = HMAC_SHA256(secret, click_id + ":" + event + ":" + payout)   <span class="str"># hex digest</span></pre></div>
      <div class="callout warn">
        <strong>Base string:</strong> the three values are joined with a colon (<code>:</code>) separator, in order. <code>event</code> defaults to <code>sale</code> and <code>payout</code> to an empty string when omitted — so always send explicit <code>event</code> and <code>payout</code> values when signing.
      </div>
      <div class="code-label">Signed postback URL</div>
      <div class="code-block"><pre>${TRACK_DOMAIN}/postback/<span class="key">{advertiser}</span>?click_id=<span class="str">{click_id}</span>&amp;event=<span class="str">{event}</span>&amp;payout=<span class="str">{payout}</span>&amp;sig=<span class="str">{hmac_sha256_hex}</span></pre></div>

      <h3 class="sub-title" id="macros">Supported Macros</h3>
      <table>
        <thead><tr><th>Macro</th><th>Description</th><th>Notes</th></tr></thead>
        <tbody>${macroRows}</tbody>
      </table>

      <div class="callout info">
        <strong>Deduplication:</strong> Komorebi deduplicates postbacks by <code>click_id + event</code> pair. A second postback with the same combination returns HTTP 409 and is not recorded — this is expected behaviour, not an error.
      </div>
    </section>

    <!-- REST API -->
    <section id="rest-api">
      <h2 class="section-title">REST API</h2>
      <p>Publishers can query their own performance data programmatically using the Komorebi REST API.</p>

      <h3 class="sub-title" id="api-auth">Authentication</h3>
      <p>All API requests must include your API key in the <code>X-API-Key</code> header. Your key is available in the <a href="/publisher/login">publisher portal</a> under the "API Access" section.</p>

      <div class="code-label">Header</div>
      <div class="code-block"><pre>X-API-Key: <span class="str">kom_live_a1b2c3d4e5f6...</span></pre></div>

      <table>
        <thead><tr><th>Code</th><th>Meaning</th></tr></thead>
        <tbody>
          <tr><td><code>200 OK</code></td><td>Request succeeded.</td></tr>
          <tr><td><code>401 Unauthorized</code></td><td>Missing, invalid, or revoked API key.</td></tr>
          <tr><td><code>429 Too Many Requests</code></td><td>Rate limit exceeded — max 100 requests per minute.</td></tr>
        </tbody>
      </table>

      <h3 class="sub-title" id="api-stats">GET /api/v1/stats</h3>
      <p>Returns your current performance statistics: click volume, conversions by status, earnings by approval state, and a per-advertiser breakdown.</p>

      <div class="code-label">Request</div>
      <div class="code-block"><pre>curl ${TRACK_DOMAIN}/api/v1/stats \\
  -H <span class="str">"X-API-Key: kom_live_your_key_here"</span></pre></div>

      <div class="code-label">Response (200 OK)</div>
      <div class="code-block"><pre>${exampleStatsJson}</pre></div>

      <table>
        <thead><tr><th>Field</th><th>Type</th><th>Description</th></tr></thead>
        <tbody>
          <tr><td><code>stats.clicks</code></td><td>number</td><td>Total click volume across all advertisers</td></tr>
          <tr><td><code>stats.conversions.approved</code></td><td>number</td><td>Conversions confirmed via reconciliation</td></tr>
          <tr><td><code>stats.conversions.pending</code></td><td>number</td><td>Conversions awaiting reconciliation</td></tr>
          <tr><td><code>stats.conversions.rejected</code></td><td>number</td><td>Conversions rejected during reconciliation</td></tr>
          <tr><td><code>stats.earnings.approved</code></td><td>number</td><td>Total approved payout (all time, USD)</td></tr>
          <tr><td><code>stats.earnings.this_month_approved</code></td><td>number</td><td>Approved payout for the current calendar month</td></tr>
          <tr><td><code>by_advertiser</code></td><td>array</td><td>Per-advertiser breakdown with individual click and payout totals</td></tr>
        </tbody>
      </table>
    </section>

    <!-- FAQ -->
    <section id="faq">
      <h2 class="section-title">FAQ</h2>

      <div class="faq-item">
        <div class="faq-q">How are conversions validated?</div>
        <div class="faq-a">
          <p>Every postback is validated against three criteria: (1) the <code>click_id</code> must exist in our system — if it does not match a known click, the postback is rejected; (2) the <code>click_id + event</code> pair must be unique — duplicate postbacks are deduplicated and return HTTP 409; (3) the postback must originate from a whitelisted IP address belonging to AppsFlyer or Adjust.</p>
          <p>Conversions recorded via postback initially enter a <strong>pending</strong> status. They move to <strong>approved</strong> or <strong>rejected</strong> only after the monthly reconciliation process.</p>
        </div>
      </div>

      <div class="faq-item">
        <div class="faq-q">What is the reconciliation process?</div>
        <div class="faq-a">
          <p>At the end of each reporting period (typically monthly), the advertiser provides a CSV file listing each <code>click_id</code> with a status of <code>approved</code> or <code>rejected</code> and optionally a final payout amount. Our team uploads this file, and your dashboard is updated immediately.</p>
          <p>Approved conversions count toward your confirmed earnings. Rejected conversions (e.g. duplicate applications, fraud flags, cancelled orders) are marked accordingly and excluded from your payout calculation.</p>
          <p>You will see the status of each conversion in the <strong>Recent Conversions</strong> table in your publisher portal.</p>
        </div>
      </div>

      <div class="faq-item">
        <div class="faq-q">How often are S2S postbacks fired back to my system?</div>
        <div class="faq-a">
          <p>If you have configured a publisher-side postback URL in your account settings, Komorebi fires it in real time — within seconds of recording the conversion. If the initial request fails (non-2xx response or timeout), the system will automatically retry up to <strong>3 times</strong>, with a <strong>5-minute delay</strong> between each attempt.</p>
          <p>You can view the full postback delivery log, including HTTP status codes and any error messages, in the publisher portal under your account settings. Contact your account manager to configure or update your postback URL.</p>
        </div>
      </div>

      <div class="faq-item">
        <div class="faq-q">What happens if my API key is lost or compromised?</div>
        <div class="faq-a">
          <p>API keys can be regenerated at any time by the Komorebi admin team. Regenerating a key immediately invalidates the old one — any requests using the old key will return HTTP 401. Contact your account manager to request a key regeneration. Your username/password portal access is not affected.</p>
        </div>
      </div>

      <div class="faq-item">
        <div class="faq-q">Which MMP macros map to the Komorebi postback parameters?</div>
        <div class="faq-a">
          <table style="margin-top:10px">
            <thead><tr><th>Komorebi param</th><th>AppsFlyer</th><th>Adjust macro</th></tr></thead>
            <tbody>
              <tr><td><code>click_id</code></td><td><code>customer_user_id</code> (matched via sync — not a postback macro)</td><td><code>{click_id}</code></td></tr>
              <tr><td><code>payout</code></td><td><code>{revenue}</code></td><td><code>{revenue}</code></td></tr>
              <tr><td><code>event</code></td><td><code>{event_name}</code></td><td><code>{event_token}</code></td></tr>
            </tbody>
          </table>
          <p style="margin-top:8px;font-size:13px;color:#6b7280">AppsFlyer click matching is reconciled by Komorebi's sync via the <code>Customer User ID</code> field (set Komorebi's <code>click_id</code> as <code>customer_user_id</code>) — see <a href="#appsflyer">AppsFlyer Integration</a>. The <code>payout</code>/<code>event</code> macros apply to postback-based MMPs such as Adjust.</p>
        </div>
      </div>

    </section>

  </main>
</div>

<footer>
  <p>Komorebi Media · Affiliate Network · <a href="mailto:chi@komorebimedia.com">chi@komorebimedia.com</a></p>
  <p style="margin-top:6px">For integration support, contact your account manager.</p>
</footer>

<script>
// FAQ accordion
document.querySelectorAll('.faq-q').forEach(q => {
  q.addEventListener('click', () => {
    const item = q.parentElement;
    const wasOpen = item.classList.contains('open');
    document.querySelectorAll('.faq-item').forEach(i => i.classList.remove('open'));
    if (!wasOpen) item.classList.add('open');
  });
});

// Sidebar active link on scroll
const sections = document.querySelectorAll('section[id], h2[id], h3[id]');
const sideLinks = document.querySelectorAll('.sidebar a');
const observer = new IntersectionObserver(entries => {
  entries.forEach(e => {
    if (e.isIntersecting) {
      sideLinks.forEach(l => l.classList.remove('active'));
      const active = document.querySelector('.sidebar a[href="#' + e.target.id + '"]');
      if (active) active.classList.add('active');
    }
  });
}, { rootMargin: '-20% 0px -70% 0px' });
sections.forEach(s => observer.observe(s));
</script>

</body>
</html>`;
}

// Daily summary — 8:00 AM Singapore time (UTC+8 = 00:00 UTC)
cron.schedule('0 0 * * *', () => {
  sendDailySummaryEmail().catch(e => console.error('Daily summary email error:', e.message));
  fireWebhookDailySummary().catch(e => console.error('Daily summary webhook error:', e.message));
}, { timezone: 'Asia/Singapore' });

// ---------------------------------------------------------------------------
// Memory monitoring — every 5 minutes, alert if > 85%, at most once per hour
// ---------------------------------------------------------------------------

const MEM_THRESHOLD   = 85;   // percent
const MEM_ALERT_QUIET = 3600_000; // 1 hour cooldown
let   _lastMemAlert   = 0;

function fmtGiB(bytes) {
  return (bytes / 1073741824).toFixed(2) + 'GiB';
}

cron.schedule('*/5 * * * *', () => {
  const total   = os.totalmem();
  const used    = total - os.freemem();
  const pct     = Math.round((used / total) * 100);
  const now     = Date.now();

  if (pct > MEM_THRESHOLD && now - _lastMemAlert > MEM_ALERT_QUIET) {
    _lastMemAlert = now;
    const msg = `⚠️ High memory usage: ${pct}% (${fmtGiB(used)}/${fmtGiB(total)}) on track.komorebimedia.com`;
    console.warn('[mem-alert]', msg);
    sendTelegram(msg).catch(e => console.error('Mem alert Telegram error:', e.message));
  }
});

app.listen(PORT, () => {
  console.log(`\nKomorebi Affiliate Tracker`);
  console.log(`  Admin      : ${BASE_URL}/admin  (user: ${ADMIN_USER})`);
  console.log(`  Publishers : ${BASE_URL}/publisher/login`);
  console.log(`  Track      : ${BASE_URL}/track/:advertiser?pub=PUBLISHER`);
  console.log(`  Postback   : ${BASE_URL}/postback/:advertiser?click_id=X&payout=Y&event=sale\n`);

  sendTelegram('🔄 Komorebi tracker restarted — track.komorebimedia.com is up.')
    .catch(e => console.error('Startup Telegram error:', e.message));

  // F19(D) — alert if critical secrets are unset or still at insecure defaults.
  const weak = [];
  if (!process.env.SESSION_SECRET) weak.push('SESSION_SECRET (unset — using insecure default)');
  if (!process.env.ADMIN_PASS)     weak.push('ADMIN_PASS (unset)');
  if (weak.length) {
    const msg = `⚠️ Komorebi security warning — insecure config: ${weak.join('; ')}.`;
    console.warn(msg);
    sendTelegram(msg).catch(() => {});
  }
});
