'use strict';

const crypto      = require('node:crypto');
const fs          = require('node:fs');
const os          = require('node:os');
const path        = require('node:path');
const express     = require('express');
const session     = require('express-session');
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
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc:   ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc:    ["'self'", "https://fonts.gstatic.com"],
      scriptSrc:  ["'self'", "'unsafe-inline'"],
      imgSrc:     ["'self'", "data:"],
    },
  },
}));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'komorebi-dev-secret-change-in-prod',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 8 * 60 * 60 * 1000, // 8 hours
  },
}));

const PORT       = process.env.PORT       || 3000;
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
let ADMIN_PASS   = process.env.ADMIN_PASS || 'changeme';
const BASE_URL   = process.env.BASE_URL   || `http://localhost:${PORT}`;

if (!process.env.SESSION_SECRET) {
  console.warn('WARNING: SESSION_SECRET not set — using insecure default. Set it in production.');
}

const ADMIN_EMAIL    = process.env.ADMIN_EMAIL        || 'chi@komorebimedia.com';
const GMAIL_USER     = process.env.GMAIL_USER;
const GMAIL_PASS     = process.env.GMAIL_PASS;
const TELEGRAM_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const TELEGRAM_CHAT  = process.env.TELEGRAM_CHAT_ID   || '';
const SLACK_URL      = process.env.SLACK_WEBHOOK_URL  || '';

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

const rlMap          = new Map();
const adminLoginAttempts     = new Map(); // ip → { count, firstAt, blockedUntil }
const publisherLoginAttempts = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [k, r] of rlMap) if (now > r.resetAt) rlMap.delete(k);
}, 60_000).unref();

function rateLimit(req, res, next) {
  const ip  = req.ip;
  const now = Date.now();
  let r = rlMap.get(ip);
  if (!r || now > r.resetAt) { r = { count: 0, resetAt: now + 60_000 }; rlMap.set(ip, r); }
  r.count++;
  res.setHeader('X-RateLimit-Limit', '100');
  res.setHeader('X-RateLimit-Remaining', Math.max(0, 100 - r.count));
  if (r.count > 100) return res.status(429).json({ error: 'Rate limit exceeded — max 100 req/min' });
  next();
}
app.use(rateLimit);

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

const logStream = fs.createWriteStream(path.join(__dirname, 'postback.log'), { flags: 'a' });
function logPostback(req, result) {
  logStream.write(JSON.stringify({ ts: new Date().toISOString(), ip: req.ip, params: req.query, result }) + '\n');
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
  // Hash lookup first; fallback to plaintext for keys not yet migrated
  const pub = db.prepare(
    "SELECT * FROM publishers WHERE (api_key_hash = ? OR (api_key_hash IS NULL AND api_key = ?)) AND status = 'active'"
  ).get(keyHash, key);
  if (!pub) {
    return res.status(401).json({ error: 'API key not found or account is paused' });
  }
  req.publisher = pub;
  next();
}

function logAudit(action, entityType, entityId, detail, reqOrIp) {
  const isReq = reqOrIp && typeof reqOrIp === 'object';
  const ip = isReq ? getIp(reqOrIp) : (reqOrIp || '');
  const tz = isReq ? detectTz(reqOrIp) : FALLBACK_TZ;
  db.prepare(
    'INSERT INTO audit_log (action, entity_type, entity_id, detail, ip_address, timezone) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(action, entityType ?? null, String(entityId ?? ''), JSON.stringify(detail ?? {}), ip, tz);
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
  const totals = db.prepare(`
    SELECT COUNT(*) as conversions,
           COALESCE(SUM(payout), 0) as total_payout,
           COALESCE(SUM(CASE WHEN status='approved' THEN payout ELSE 0 END), 0) as approved_payout
    FROM conversions WHERE date(received_at, '+8 hours') = ?
  `).get(yesterday);
  if (totals.conversions === 0) return;
  const byAdv = db.prepare(`
    SELECT a.name, COUNT(*) as conversions, COALESCE(SUM(cv.payout),0) as payout
    FROM conversions cv JOIN advertisers a ON a.slug = cv.advertiser_slug
    WHERE date(cv.received_at, '+8 hours') = ?
    GROUP BY cv.advertiser_slug ORDER BY payout DESC
  `).all(yesterday);
  const advLines = byAdv.map(r => `• ${r.name}: ${r.conversions} conv — $${r.payout.toFixed(2)}`).join('\n');
  const plain = `\u{1F4CA} Daily Summary ${yesterday} SGT\n` +
    `Conversions: ${totals.conversions} | Total: $${totals.total_payout.toFixed(2)} | Approved: $${totals.approved_payout.toFixed(2)}\n` +
    advLines;
  await Promise.allSettled([
    sendTelegram(plain),
    sendSlack(plain, [
      {
        type: 'section',
        text: { type: 'mrkdwn', text: `\u{1F4CA} *Daily Summary — ${yesterday} SGT*` },
        fields: [
          { type: 'mrkdwn', text: `*Conversions*\n${totals.conversions}` },
          { type: 'mrkdwn', text: `*Total Payout*\n$${totals.total_payout.toFixed(2)}` },
          { type: 'mrkdwn', text: `*Approved*\n$${totals.approved_payout.toFixed(2)}` },
        ],
      },
      ...(byAdv.length > 0 ? [{
        type: 'section',
        text: { type: 'mrkdwn', text: byAdv.map(r => `• *${r.name}*: ${r.conversions} conv — $${r.payout.toFixed(2)}`).join('\n') },
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

  const totals = db.prepare(`
    SELECT COUNT(*) as conversions,
           COALESCE(SUM(payout), 0) as total_payout,
           COALESCE(SUM(CASE WHEN status='approved' THEN payout ELSE 0 END), 0) as approved_payout
    FROM conversions
    WHERE date(received_at, '+8 hours') = ?
  `).get(yesterday);

  if (totals.conversions === 0) return; // nothing to report

  const byAdv = db.prepare(`
    SELECT a.name, COUNT(*) as conversions, COALESCE(SUM(cv.payout),0) as payout
    FROM conversions cv
    JOIN advertisers a ON a.slug = cv.advertiser_slug
    WHERE date(cv.received_at, '+8 hours') = ?
    GROUP BY cv.advertiser_slug ORDER BY payout DESC
  `).all(yesterday);

  const byPub = db.prepare(`
    SELECT publisher, COUNT(*) as conversions, COALESCE(SUM(payout),0) as payout
    FROM conversions
    WHERE date(received_at, '+8 hours') = ?
    GROUP BY publisher ORDER BY payout DESC
  `).all(yesterday);

  const tableHtml = (rows, cols) => `
    <table style="border-collapse:collapse;width:100%;margin-bottom:20px">
      <thead><tr>${cols.map(c=>`<th style="padding:6px 12px;background:#f5f5f7;text-align:left;font-size:12px">${c}</th>`).join('')}</tr></thead>
      <tbody>${rows.map(r=>`<tr>${Object.values(r).map(v=>`<td style="padding:7px 12px;border-bottom:1px solid #f0f0f0;font-size:13px">${typeof v==='number'&&v%1!==0?'$'+v.toFixed(2):v}</td>`).join('')}</tr>`).join('')}</tbody>
    </table>`;

  await sendMail({
    subject: `[Komorebi] Daily Summary — ${yesterday} SGT`,
    text:
      `Daily Summary for ${yesterday} (Singapore time)\n\n` +
      `Conversions : ${totals.conversions}\n` +
      `Total Payout: $${totals.total_payout.toFixed(2)}\n` +
      `Approved    : $${totals.approved_payout.toFixed(2)}\n\n` +
      `By Advertiser:\n${byAdv.map(r=>`  ${r.name}: ${r.conversions} conv — $${r.payout.toFixed(2)}`).join('\n')}\n\n` +
      `By Publisher:\n${byPub.map(r=>`  ${r.publisher}: ${r.conversions} conv — $${r.payout.toFixed(2)}`).join('\n')}\n`,
    html: `
      <div style="font-family:sans-serif;max-width:600px">
        <h2 style="color:#1d1d1f;margin-bottom:4px">Daily Summary</h2>
        <p style="color:#6e6e73;font-size:13px;margin-bottom:20px">${yesterday} · Singapore Time</p>
        <div style="display:flex;gap:16px;margin-bottom:24px">
          ${[
            ['Conversions', totals.conversions],
            ['Total Payout', `$${totals.total_payout.toFixed(2)}`],
            ['Approved', `$${totals.approved_payout.toFixed(2)}`],
          ].map(([l,v])=>`<div style="background:#f5f5f7;border-radius:8px;padding:12px 16px;min-width:120px">
            <div style="font-size:11px;color:#6e6e73;font-weight:700;text-transform:uppercase;margin-bottom:4px">${l}</div>
            <div style="font-size:22px;font-weight:700">${v}</div>
          </div>`).join('')}
        </div>
        <h3 style="font-size:13px;margin-bottom:8px">By Advertiser</h3>
        ${tableHtml(byAdv.map(r=>({Advertiser:r.name,Conversions:r.conversions,Payout:r.payout})),['Advertiser','Conversions','Payout'])}
        <h3 style="font-size:13px;margin-bottom:8px">By Publisher</h3>
        ${tableHtml(byPub.map(r=>({Publisher:r.publisher,Conversions:r.conversions,Payout:r.payout})),['Publisher','Conversions','Payout'])}
      </div>`,
  });
}

// ---------------------------------------------------------------------------
// S2S postback — fire publisher's postback URL on conversion
// ---------------------------------------------------------------------------

const S2S_MAX_ATTEMPTS = 3;
const S2S_RETRY_MS     = 5 * 60 * 1_000; // 5 minutes

async function fireS2SPostback(publisher, { click_id, payout, event, advertiser }, attempt = 1) {
  const pub = db.prepare('SELECT postback_url FROM publishers WHERE username = ?').get(publisher);
  if (!pub?.postback_url) return;

  const url = pub.postback_url
    .replace('{click_id}',   encodeURIComponent(click_id))
    .replace('{payout}',     payout)
    .replace('{event}',      encodeURIComponent(event))
    .replace('{advertiser}', encodeURIComponent(advertiser));

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
      () => fireS2SPostback(publisher, { click_id, payout, event, advertiser }, attempt + 1).catch(() => {}),
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

function requireAdmin(req, res, next) {
  if (!req.session?.isAdmin) return res.redirect('/admin/login');
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
  const pub = db.prepare('SELECT * FROM publishers WHERE id = ?').get(id);
  if (!pub || pub.status !== 'active') {
    req.session.destroy(() => {});
    return res.redirect('/publisher/login?err=Account+is+disabled');
  }
  req.publisher = pub;
  next();
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

  const clickId  = crypto.randomUUID();
  const clickIp  = getIp(req);
  const clickUa  = req.get('User-Agent') || '';
  const { device, os, browser } = parseUA(clickUa);
  const country  = geoLookup(clickIp);
  db.prepare(
    'INSERT INTO clicks (click_id, advertiser_slug, publisher, ip, user_agent, country, device_type, os, browser) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).run(clickId, slug, pub, clickIp, clickUa, country, device, os, browser);

  if (!adv.offer_url) return res.json({ click_id: clickId, advertiser: slug, publisher: pub });

  const url = new URL(adv.offer_url);
  url.searchParams.set('click_id', clickId);
  res.redirect(302, url.toString());
});

// ---------------------------------------------------------------------------
// Postback  GET /postback/:slug?click_id=X&payout=Y[&event=sale][&publisher=Z]
// ---------------------------------------------------------------------------

app.get('/postback/:slug', (req, res) => {
  const ip = getIp(req);
  if (!isWhitelisted(ip)) {
    logPostback(req, { status: 'rejected', reason: 'ip_not_whitelisted' });
    return res.status(403).json({ error: 'Forbidden — IP not whitelisted', ip });
  }

  const { slug }                             = req.params;
  const { click_id, payout, event = 'sale' } = req.query;

  if (!click_id) {
    logPostback(req, { status: 'rejected', reason: 'missing_click_id' });
    return res.status(400).json({ error: 'Missing required param: click_id' });
  }

  const click = db.prepare('SELECT publisher FROM clicks WHERE click_id = ?').get(click_id);
  if (!click) {
    logPostback(req, { status: 'rejected', reason: 'invalid_click_id', click_id });
    return res.status(400).json({ error: 'Invalid click_id' });
  }

  const adv = db.prepare('SELECT * FROM advertisers WHERE slug = ?').get(slug);
  if (!adv) return res.status(404).json({ error: `Unknown advertiser: ${slug}` });

  let amount;
  if (adv.payout_amount > 0) {
    amount = adv.payout_amount;
  } else {
    const reqPayout = parseFloat(payout);
    if (reqPayout > 0) {
      console.warn(`[postback] advertiser ${slug} has no payout_amount — using request payout=${reqPayout}`);
      amount = reqPayout;
    } else {
      amount = 0;
    }
  }

  const pub = click.publisher;

  let result;
  try {
    db.prepare(
      'INSERT INTO conversions (click_id, advertiser_slug, publisher, event, payout, raw_params) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(click_id, slug, pub, event, amount, JSON.stringify(req.query));
    result = { status: 'ok', click_id, advertiser: slug, publisher: pub, event, payout: amount };
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE' || (err.message && err.message.includes('UNIQUE constraint'))) {
      logPostback(req, { status: 'duplicate', click_id, event });
      return res.json({ status: 'duplicate' });
    }
    throw err;
  }

  logPostback(req, result);
  res.json(result);

  // Fire S2S postback, email, and webhooks — all async, do not block response
  fireS2SPostback(pub, { click_id, payout: amount, event, advertiser: slug }).catch(() => {});
  sendConversionEmail({
    advertiserName: adv.name, publisher: pub, payout: amount,
    click_id, event, received_at: new Date().toISOString().replace('T', ' ').slice(0, 19),
  }).catch(() => {});
  fireWebhookConversion({ advertiserName: adv.name, publisher: pub, payout: amount, event }).catch(() => {});
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
  res.json({ status: 'ok', uptime: process.uptime() });
});

// ---------------------------------------------------------------------------
// Public documentation  GET /docs  (no auth)
// ---------------------------------------------------------------------------

app.get('/docs', (req, res) => res.send(renderDocs()));

// ---------------------------------------------------------------------------
// Publisher portal
// ---------------------------------------------------------------------------

app.get('/',                (req, res) => res.redirect('/publisher/login'));
app.get('/publisher',       requirePublisher, (req, res) => res.redirect('/publisher/dashboard'));
app.get('/publisher/login', (req, res) => {
  if (req.session?.pubId) return res.redirect('/publisher/dashboard');
  const success = req.query.registered
    ? 'Application submitted! We\'ll review it and notify you when approved.'
    : null;
  res.send(renderPubLogin({ error: req.query.err, success }));
});

app.post('/publisher/login', (req, res) => {
  if (checkLoginLockout(req, res, publisherLoginAttempts)) return;
  const { username, password } = req.body;
  const uname = (username || '').trim().toLowerCase();
  const pub = uname ? db.prepare('SELECT * FROM publishers WHERE username = ?').get(uname) : null;
  if (!pub || !checkPassword(password || '', pub.password_hash)) {
    recordLoginFailure(req.ip, publisherLoginAttempts);
    return res.send(renderPubLogin({ error: 'Invalid username or password', username: uname }));
  }
  if (pub.status !== 'active') {
    const msg = pub.status === 'pending'
      ? 'Your application is pending review. We\'ll be in touch once it\'s approved.'
      : pub.status === 'rejected'
        ? 'Your application was not approved. Contact chi@komorebimedia.com for details.'
        : 'Your account has been disabled. Contact your account manager.';
    return res.send(renderPubLogin({ error: msg }));
  }
  req.session.regenerate(err => {
    if (err) return res.status(500).send('Session error');
    req.session.pubId = pub.id;
    req.session.save(saveErr => {
      if (saveErr) return res.status(500).send('Session error');
      recordLoginSuccess(req.ip, publisherLoginAttempts);
      res.redirect('/publisher/dashboard');
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

app.get('/publisher/dashboard', requirePublisher, (req, res) => {
  const pub       = req.publisher;
  const thisMonth = new Date().toISOString().slice(0, 7);

  const totalClicks = db.prepare(
    'SELECT COUNT(*) as n FROM clicks WHERE publisher = ?'
  ).get(pub.username).n;

  const totalConversions = db.prepare(
    'SELECT COUNT(*) as n FROM conversions WHERE publisher = ?'
  ).get(pub.username).n;

  const payoutRow = db.prepare(`
    SELECT COALESCE(SUM(CASE WHEN status='approved' THEN payout ELSE 0 END),0) as approved,
           COALESCE(SUM(CASE WHEN status='pending'  THEN payout ELSE 0 END),0) as pending
    FROM conversions WHERE publisher = ?
  `).get(pub.username);
  const totalPayout   = payoutRow.approved;
  const pendingPayout = payoutRow.pending;

  const monthlyRow = db.prepare(`
    SELECT COALESCE(SUM(CASE WHEN status='approved' THEN payout ELSE 0 END),0) as approved,
           COALESCE(SUM(CASE WHEN status='pending'  THEN payout ELSE 0 END),0) as pending
    FROM conversions WHERE publisher = ? AND strftime('%Y-%m',received_at) = ?
  `).get(pub.username, thisMonth);
  const monthlyPayout        = monthlyRow.approved;
  const monthlyPendingPayout = monthlyRow.pending;

  const advertisers = db.prepare(
    "SELECT * FROM advertisers WHERE status = 'active' AND slug != 'legacy' ORDER BY name"
  ).all();

  const advClicks = db.prepare(
    'SELECT advertiser_slug, COUNT(*) as n FROM clicks WHERE publisher = ? GROUP BY advertiser_slug'
  ).all(pub.username);
  const advConv = db.prepare(`
    SELECT advertiser_slug, COUNT(*) as n,
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
    approved_payout: convMap[a.slug]?.approved_payout || 0,
    pending_payout: convMap[a.slug]?.pending_payout || 0,
    approved_count: convMap[a.slug]?.approved_count || 0,
    pending_count:  convMap[a.slug]?.pending_count || 0,
    rejected_count: convMap[a.slug]?.rejected_count || 0,
    trackingUrl: `${BASE_URL}/track/${a.slug}?pub=${encodeURIComponent(pub.username)}`,
  }));

  const recent = db.prepare(`
    SELECT cv.received_at, cv.advertiser_slug, cv.click_id, cv.event,
           cv.payout, cv.status, cv.reason, a.name as adv_name
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

  res.send(renderPubDashboard({ pub, totalClicks, totalConversions,
    totalPayout, pendingPayout, monthlyPayout, monthlyPendingPayout,
    advStats, recent, thisMonth, payments, totalPaid }));
});

app.get('/publisher/conversions', requirePublisher, (req, res) => {
  const pub = req.publisher;
  const conversions = db.prepare(`
    SELECT cv.received_at, cv.advertiser_slug, cv.click_id, cv.event,
           cv.payout, cv.status, cv.reason, a.name as adv_name
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
  const approvedBal  = db.prepare(
    "SELECT COALESCE(SUM(CASE WHEN status='approved' THEN payout ELSE 0 END),0) as b FROM conversions WHERE publisher=?"
  ).get(pub.username).b;
  res.send(renderPubPayments({ pub, payments, totalPaid, approvedBal }));
});

app.get('/publisher/api-access', requirePublisher, (req, res) => {
  res.send(renderPubApiAccess({ pub: req.publisher }));
});

// ---------------------------------------------------------------------------
// Admin — main dashboard
// ---------------------------------------------------------------------------

// Admin login / logout
app.get('/admin/login', (req, res) => {
  if (req.session?.isAdmin) return res.redirect('/admin');
  res.send(renderAdminLogin(''));
});

app.post('/admin/login', (req, res) => {
  if (checkLoginLockout(req, res, adminLoginAttempts)) return;
  const { username, password } = req.body;
  if (username === ADMIN_USER && password === ADMIN_PASS) {
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
  if (req.path === '/login' || req.path === '/logout') return next();
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

  const globalPayout = db.prepare(`
    SELECT COALESCE(SUM(payout),0) as total,
           COALESCE(SUM(CASE WHEN status='approved' THEN payout ELSE 0 END),0) as approved,
           COALESCE(SUM(CASE WHEN status='pending'  THEN payout ELSE 0 END),0) as pending
    FROM conversions
  `).get();
  const totalPayout    = globalPayout.total;
  const approvedPayout = globalPayout.approved;
  const pendingPayout  = globalPayout.pending;

  const monthlyPayout = db.prepare(
    "SELECT COALESCE(SUM(CASE WHEN status='approved' THEN payout ELSE 0 END),0) as s FROM conversions WHERE strftime('%Y-%m',received_at)=?"
  ).get(thisMonth).s;

  const advertisers = db.prepare('SELECT * FROM advertisers ORDER BY name').all();

  const advClicks = db.prepare('SELECT advertiser_slug, COUNT(*) as n FROM clicks GROUP BY advertiser_slug').all();
  const advConv   = db.prepare(`
    SELECT advertiser_slug, COUNT(*) as n,
           COALESCE(SUM(payout),0) as payout,
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
    payout:          convMap[a.slug]?.payout || 0,
    approved_payout: convMap[a.slug]?.approved_payout || 0,
    pending_count:   convMap[a.slug]?.pending_count || 0,
  }));

  const pubStats = db.prepare(`
    SELECT c.advertiser_slug, c.publisher,
           COUNT(DISTINCT c.click_id) as clicks,
           COUNT(cv.id) as conversions,
           COALESCE(SUM(cv.payout),0) as payout
    FROM clicks c
    LEFT JOIN conversions cv ON cv.click_id = c.click_id
    GROUP BY c.advertiser_slug, c.publisher
    ORDER BY payout DESC LIMIT 100
  `).all();

  const recent = db.prepare(
    'SELECT received_at, advertiser_slug, click_id, publisher, event, payout FROM conversions ORDER BY received_at DESC LIMIT 50'
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

  res.send(renderAdminDashboard({ totalClicks, totalConversions, totalPayout,
    approvedPayout, pendingPayout, monthlyPayout,
    thisMonth, advStats, pubStats, recent, flash, publisherCount,
    topCountries, deviceSplit, osSplit, globalConvStatus }));
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
  res.send(renderAdvList({ advStats, flash }));
});

app.get('/admin/advertisers/new', requireAdmin, (req, res) => {
  res.send(renderAdvForm({ title: 'New Advertiser', action: '/admin/advertisers', adv: {} }));
});

app.post('/admin/advertisers', requireAdmin, (req, res) => {
  const { name, slug, offer_url, payout_amount, status } = req.body;
  const s = slug || slugify(name);
  if (!name || !s) return res.send(renderAdvForm({ title: 'New Advertiser', action: '/admin/advertisers',
    adv: req.body, error: 'Name and slug are required.' }));
  if (!/^[a-z0-9-]+$/.test(s)) return res.send(renderAdvForm({ title: 'New Advertiser',
    action: '/admin/advertisers', adv: req.body, error: 'Slug must be lowercase letters, numbers, and hyphens.' }));
  try {
    db.prepare('INSERT INTO advertisers (slug, name, offer_url, payout_amount, status) VALUES (?, ?, ?, ?, ?)')
      .run(s, name.trim(), offer_url || '', parseFloat(payout_amount) || 0, status || 'active');
    logAudit('advertiser.created', 'advertiser', s,
      { name: name.trim(), slug: s, offer_url: offer_url || '', status: status || 'active' }, req);
    res.redirect(`/admin?msg=Advertiser+%22${encodeURIComponent(name)}%22+created`);
  } catch {
    res.send(renderAdvForm({ title: 'New Advertiser', action: '/admin/advertisers',
      adv: req.body, error: `Slug "${s}" is already taken.` }));
  }
});

app.get('/admin/advertisers/:slug/edit', requireAdmin, (req, res) => {
  const adv = db.prepare('SELECT * FROM advertisers WHERE slug = ?').get(req.params.slug);
  if (!adv) return res.redirect('/admin?msg=Advertiser+not+found&ok=0');
  res.send(renderAdvForm({ title: `Edit — ${adv.name}`, action: `/admin/advertisers/${adv.slug}/update`, adv }));
});

app.post('/admin/advertisers/:slug/update', requireAdmin, (req, res) => {
  const { name, offer_url, payout_amount, status } = req.body;
  const { slug } = req.params;
  if (!name) return res.send(renderAdvForm({ title: 'Edit Advertiser',
    action: `/admin/advertisers/${slug}/update`, adv: { slug, ...req.body }, error: 'Name is required.' }));
  db.prepare('UPDATE advertisers SET name=?, offer_url=?, payout_amount=?, status=? WHERE slug=?')
    .run(name.trim(), offer_url || '', parseFloat(payout_amount) || 0, status || 'active', slug);
  logAudit('advertiser.updated', 'advertiser', slug,
    { name: name.trim(), offer_url: offer_url || '', payout_amount: parseFloat(payout_amount) || 0, status: status || 'active' }, req);
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

  res.send(renderPubList({ publishers, pending, flash }));
});

app.get('/admin/publishers/new', requireAdmin, (req, res) => {
  res.send(renderPubForm({ title: 'New Publisher', action: '/admin/publishers', pub: {} }));
});

app.post('/admin/publishers', requireAdmin, (req, res) => {
  const { username, password, status, postback_url } = req.body;
  const uname = (username || '').trim().toLowerCase();
  if (!uname || !password) return res.send(renderPubForm({ title: 'New Publisher',
    action: '/admin/publishers', pub: req.body, error: 'Username and password are required.' }));
  if (!/^[a-z0-9_-]+$/.test(uname)) return res.send(renderPubForm({ title: 'New Publisher',
    action: '/admin/publishers', pub: req.body,
    error: 'Username must be lowercase letters, numbers, underscores, or hyphens.' }));
  if (password.length < 8) return res.send(renderPubForm({ title: 'New Publisher',
    action: '/admin/publishers', pub: req.body, error: 'Password must be at least 8 characters.' }));
  const pbUrl  = (postback_url || '').trim();
  const apiKey = generateApiKey();
  try {
    db.prepare('INSERT INTO publishers (username, password_hash, postback_url, api_key, api_key_hash, status) VALUES (?, ?, ?, ?, ?, ?)')
      .run(uname, hashPassword(password), pbUrl, apiKey, hashApiKey(apiKey), status || 'active');
    logAudit('publisher.created', 'publisher', uname,
      { username: uname, status: status || 'active', s2s_url: pbUrl || null }, req);
    res.redirect(`/admin/publishers?msg=Publisher+%22${encodeURIComponent(uname)}%22+created`);
  } catch {
    res.send(renderPubForm({ title: 'New Publisher', action: '/admin/publishers',
      pub: req.body, error: `Username "${uname}" is already taken.` }));
  }
});

app.get('/admin/publishers/:id/edit', requireAdmin, (req, res) => {
  const pub = db.prepare('SELECT * FROM publishers WHERE id = ?').get(req.params.id);
  if (!pub) return res.redirect('/admin/publishers?msg=Publisher+not+found&ok=0');
  const flash = req.query.msg ? { type: 'success', text: req.query.msg } : null;
  res.send(renderPubForm({ title: `Edit — ${pub.username}`,
    action: `/admin/publishers/${pub.id}/update`, pub, flash }));
});

app.post('/admin/publishers/:id/update', requireAdmin, (req, res) => {
  const { password, status, postback_url, minimum_payout } = req.body;
  const { id } = req.params;
  const pub = db.prepare('SELECT * FROM publishers WHERE id = ?').get(id);
  if (!pub) return res.redirect('/admin/publishers?msg=Not+found&ok=0');
  if (password && password.length < 8) return res.send(renderPubForm({ title: `Edit — ${pub.username}`,
    action: `/admin/publishers/${id}/update`, pub: { ...pub, ...req.body },
    error: 'Password must be at least 8 characters.' }));
  const pbUrl  = (postback_url || '').trim();
  const minPay = parseFloat(minimum_payout) >= 0 ? parseFloat(minimum_payout) : 50;
  if (password) {
    db.prepare('UPDATE publishers SET password_hash=?, postback_url=?, status=?, minimum_payout=? WHERE id=?')
      .run(hashPassword(password), pbUrl, status || 'active', minPay, id);
  } else {
    db.prepare('UPDATE publishers SET postback_url=?, status=?, minimum_payout=? WHERE id=?')
      .run(pbUrl, status || 'active', minPay, id);
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
  const pub = db.prepare('SELECT id, username, api_key FROM publishers WHERE id = ?').get(req.params.id);
  if (!pub) return res.redirect('/admin/publishers?msg=Not+found&ok=0');
  const newKey = generateApiKey();
  db.prepare('UPDATE publishers SET api_key = ?, api_key_hash = ? WHERE id = ?').run(newKey, hashApiKey(newKey), pub.id);
  logAudit('api_key.regenerated', 'publisher', pub.username,
    { old_key_suffix: (pub.api_key || '').slice(-8) }, req);
  res.redirect(`/admin/publishers/${pub.id}/edit?msg=API+key+regenerated+%E2%80%94+copy+now%3A+${encodeURIComponent(newKey)}`);
});

// Revoke API key (sets to NULL — publisher can no longer use key auth)
app.post('/admin/publishers/:id/revoke-key', requireAdmin, (req, res) => {
  const pub = db.prepare('SELECT id, username FROM publishers WHERE id = ?').get(req.params.id);
  if (!pub) return res.redirect('/admin/publishers?msg=Not+found&ok=0');
  db.prepare('UPDATE publishers SET api_key = NULL WHERE id = ?').run(pub.id);
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
  const approvedBalance = db.prepare(
    "SELECT COALESCE(SUM(CASE WHEN status='approved' THEN payout ELSE 0 END),0) as bal FROM conversions WHERE publisher=?"
  ).get(pub.username).bal;
  res.send(renderPaymentsPage({ pub, payments, totalPaid, approvedBalance, flash }));
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
// Invoices
// ---------------------------------------------------------------------------

function invoiceLines(username, year, month) {
  const pad  = String(month).padStart(2, '0');
  const from = `${year}-${pad}-01`;
  const to   = `${year}-${pad}-31`;
  return db.prepare(`
    SELECT cv.id, cv.click_id, cv.advertiser_slug, cv.event, cv.payout,
           cv.received_at, a.name as adv_name
    FROM   conversions cv
    LEFT JOIN advertisers a ON a.slug = cv.advertiser_slug
    WHERE  cv.publisher = ?
      AND  cv.status    = 'approved'
      AND  date(cv.received_at) BETWEEN ? AND ?
    ORDER  BY cv.received_at
  `).all(username, from, to);
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
  const total = lines.reduce((s, r) => s + r.payout, 0);

  const inv   = upsertInvoice(pub.id, pub.username, year, month, total);
  const flash = req.query.msg
    ? { type: req.query.ok === '0' ? 'error' : 'success', text: req.query.msg } : null;

  res.send(renderInvoice({ inv, pub, lines, flash }));
});

// Regenerate (recalculate total from live approved conversions)
app.post('/admin/publishers/:id/invoice/:year/:month/regenerate', requireAdmin, (req, res) => {
  const pub = db.prepare('SELECT * FROM publishers WHERE id = ?').get(req.params.id);
  if (!pub) return res.redirect('/admin/publishers?msg=Not+found&ok=0');

  const year  = parseInt(req.params.year,  10);
  const month = parseInt(req.params.month, 10);
  if (!year || month < 1 || month > 12) return res.redirect('/admin/publishers?msg=Invalid+period&ok=0');

  const lines = invoiceLines(pub.username, year, month);
  const total = lines.reduce((s, r) => s + r.payout, 0);
  upsertInvoice(pub.id, pub.username, year, month, total);
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

  if (!current_password || current_password !== ADMIN_PASS) {
    return res.redirect('/admin/settings?msg=Current+password+is+incorrect&ok=0');
  }
  if (!new_password || new_password.length < 8) {
    return res.redirect('/admin/settings?msg=New+password+must+be+at+least+8+characters&ok=0');
  }
  if (new_password !== confirm_password) {
    return res.redirect('/admin/settings?msg=Passwords+do+not+match&ok=0');
  }

  ADMIN_PASS             = new_password;
  process.env.ADMIN_PASS = new_password;

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
      runResult = { run, unmatched, rejected };
    }
  }

  res.send(renderReconcilePage({ adv, runs, runResult }));
});

app.post('/admin/advertisers/:slug/reconcile', requireAdmin, (req, res, next) => {
  csvUpload(req, res, err => {
    if (err) return res.redirect(`/admin/advertisers/${req.params.slug}/reconcile?msg=${encodeURIComponent(err.message)}&ok=0`);

    const adv = db.prepare('SELECT * FROM advertisers WHERE slug = ?').get(req.params.slug);
    if (!adv) return res.redirect('/admin?msg=Advertiser+not+found&ok=0');
    if (!req.file) return res.redirect(`/admin/advertisers/${adv.slug}/reconcile?msg=No+file+uploaded&ok=0`);

    const rows     = parseCSV(req.file.buffer);
    const filename = req.file.originalname;

    // Create run record
    const runId = db.prepare(
      'INSERT INTO reconciliation_runs (advertiser_slug, filename, total_rows) VALUES (?, ?, ?)'
    ).run(adv.slug, filename, rows.length).lastInsertRowid;

    let matched = 0, approved = 0, rejected = 0, unmatched = 0;

    const insertUnmatched = db.prepare(
      'INSERT INTO reconciliation_unmatched (run_id, click_id, raw_status, reason, issue) VALUES (?, ?, ?, ?, ?)'
    );

    for (const row of rows) {
      const click_id  = (row.click_id || row.clickid || row.click || '').trim();
      const rawStatus = (row.status || '').trim().toLowerCase();
      const reason    = (row.reason || row.note || row.notes || '').trim();
      const payout    = row.payout !== undefined && row.payout !== '' ? parseFloat(row.payout) : null;

      if (!click_id) {
        unmatched++;
        insertUnmatched.run(runId, '', rawStatus, reason, 'Missing click_id');
        continue;
      }
      if (!['approved', 'rejected'].includes(rawStatus)) {
        unmatched++;
        insertUnmatched.run(runId, click_id, rawStatus, reason, `Invalid status: "${rawStatus}"`);
        continue;
      }

      const conv = db.prepare(
        'SELECT id FROM conversions WHERE click_id = ? AND advertiser_slug = ?'
      ).get(click_id, adv.slug);

      if (!conv) {
        unmatched++;
        insertUnmatched.run(runId, click_id, rawStatus, reason, 'click_id not found for this advertiser');
        continue;
      }

      matched++;
      if (rawStatus === 'approved') approved++; else rejected++;

      if (payout !== null && !isNaN(payout)) {
        db.prepare('UPDATE conversions SET status=?, reason=?, reconciliation_run_id=?, payout=? WHERE click_id=? AND advertiser_slug=?')
          .run(rawStatus, reason, runId, payout, click_id, adv.slug);
      } else {
        db.prepare('UPDATE conversions SET status=?, reason=?, reconciliation_run_id=? WHERE click_id=? AND advertiser_slug=?')
          .run(rawStatus, reason, runId, click_id, adv.slug);
      }
    }

    db.prepare('UPDATE reconciliation_runs SET matched=?, approved=?, rejected=?, unmatched=? WHERE id=?')
      .run(matched, approved, rejected, unmatched, runId);

    logAudit('reconciliation.uploaded', 'advertiser', adv.slug,
      { advertiser: adv.name, filename, total_rows: rows.length, matched, approved, rejected, unmatched }, req);

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

  res.send(renderAnalyticsPage({ adv, dailyClicks, dailyConv, geoBreakdown,
    deviceBreakdown, osBreakdown, browserBreakdown, totalClicksAdv, totalConvAdv, convStatus }));
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
    `SELECT received_at,advertiser_slug,click_id,publisher,event,payout,status,reason FROM conversions ${where} ORDER BY received_at`
  ).all(...params);

  const parts = [advertiser, month].filter(Boolean);
  const filename = parts.length ? `conversions-${parts.join('-')}.csv` : 'conversions-all.csv';
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

  const q = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
  res.send([
    'received_at,advertiser,click_id,publisher,event,payout,status,reason',
    ...rows.map(r => [r.received_at, r.advertiser_slug, r.click_id, r.publisher, r.event, r.payout, r.status, r.reason].map(q).join(',')),
  ].join('\r\n'));
});

// ---------------------------------------------------------------------------
// HTML templates — shared helpers
// ---------------------------------------------------------------------------

const H   = s => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const $   = n  => Number(n).toFixed(2);
const N   = n  => Number(n).toLocaleString();
const cvr = (cl, co) => cl > 0 ? ((co / cl) * 100).toFixed(1) + '%' : '—';

const VND_RATE = 25700;
const vnd  = usd => Math.round(Number(usd) * VND_RATE).toLocaleString('en-US') + ' ₫';
const usdVnd = (usd, style = '') => `$${$(usd)}<span style="font-size:11px;color:#6e6e73;margin-left:4px">(${vnd(usd)})</span>`;

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
  .pub-nav-a.active{background:rgba(0,229,195,.1);color:#00e5c3;border-left-color:#00e5c3;font-weight:500}
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
  section{background:#fff;border:1px solid #e2e6ea;border-radius:8px;margin-bottom:10px;overflow:hidden}
  .sh{padding:10px 16px;border-bottom:1px solid #f3f4f6;display:flex;align-items:center;justify-content:space-between;gap:8px}
  .sh h2{font-size:13px;font-weight:600;color:#111827}
  .sh .meta{font-size:11px;color:#9ca3af}
  table{width:100%;border-collapse:collapse}
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
  .btn{display:inline-flex;align-items:center;padding:4px 10px;border-radius:5px;font-size:11px;font-weight:500;cursor:pointer;border:1px solid transparent;white-space:nowrap;font-family:inherit}
  .btn-ghost{background:#f9fafb;color:#374151;border-color:#e2e6ea}
  .btn-ghost:hover{background:#f3f4f6}
  .btn-primary{background:#00e5c3;color:#0d1117;border-color:#00e5c3}
  .btn-primary:hover{background:#00c9aa}
  .empty{padding:32px;text-align:center;color:#9ca3af;font-size:13px}
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
`;

const CP_JS = `
function cp(el,url){
  navigator.clipboard.writeText(url)
    .then(()=>{const o=el.style.background;el.style.background='#d4edda';setTimeout(()=>el.style.background=o,700);})
    .catch(()=>prompt('Copy:',url));
}`;

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
  };
  const nav = (href, label, icon, paths) =>
    `<a href="${href}" class="adm-nav-a" data-paths="${paths||href}">${ICONS[icon]}<span>${label}</span></a>`;
  return `<aside class="adm-sidebar">
  <div class="adm-sb-group">OVERVIEW</div>
  ${nav('/admin',             'Dashboard',   'dashboard',   '/admin')}
  ${nav('/admin/analytics',   'Analytics',   'analytics',   '/admin/analytics')}
  <div class="adm-sb-group">MANAGEMENT</div>
  ${nav('/admin/advertisers', 'Advertisers', 'advertisers', '/admin/advertisers')}
  ${nav('/admin/publishers',  'Publishers',  'publishers',  '/admin/publishers')}
  ${nav('/admin/invoices',    'Invoices',    'invoices',    '/admin/invoices')}
  <div class="adm-sb-group">SYSTEM</div>
  ${nav('/admin/audit-log',   'Audit log',   'auditlog',    '/admin/audit-log')}
  ${nav('/admin/settings',    'Settings',    'settings',    '/admin/settings')}
  <div class="adm-sb-foot">
    <a href="/health" target="_blank"
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
  // Cover programmatic form.submit() calls (e.g. onchange="this.form.submit()")
  var _origSubmit=HTMLFormElement.prototype.submit;
  HTMLFormElement.prototype.submit=function(){injectCsrf(this);_origSubmit.call(this);};
})();
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

function renderAdminDashboard({ totalClicks, totalConversions, totalPayout,
  approvedPayout, pendingPayout, monthlyPayout,
  thisMonth, advStats, pubStats, recent, flash, publisherCount,
  topCountries = [], deviceSplit = [], osSplit = [], globalConvStatus = {} }) {

  const advRows = advStats.filter(a => a.slug !== 'legacy' || a.clicks > 0).map(a => {
    const trackUrl   = `${BASE_URL}/track/${a.slug}?pub=PUBLISHER_NAME`;
    const postbkUrl  = `${BASE_URL}/postback/${a.slug}?click_id=CLICK_ID&payout=AMOUNT&event=sale`;
    const isLegacy   = a.slug === 'legacy';
    return `<tr>
      <td>
        <strong>${H(a.name)}</strong>
        ${isLegacy ? '' : `<div style="margin-top:5px">
          <div class="ubox" onclick="cp(this,'${H(trackUrl)}')">/track/${H(a.slug)}?pub=PUBLISHER_NAME</div>
        </div>`}
      </td>
      <td><span class="badge ${a.status}">${a.status}</span></td>
      <td>${N(a.clicks)}</td><td>${N(a.conversions)}</td>
      <td>
        <div>$${$(a.approved_payout)} <span style="font-size:10px;color:#2e7d32">approved</span></div>
        ${a.pending_count > 0 ? `<div style="font-size:11px;color:#f57f17">${N(a.pending_count)} pending</div>` : ''}
      </td>
      <td>${cvr(a.clicks,a.conversions)}</td>
      <td><div class="ubox" onclick="cp(this,'${H(postbkUrl)}')" style="max-width:200px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis">/postback/${H(a.slug)}?click_id=…</div></td>
      <td><div class="act">
        ${isLegacy ? '' : `<a href="/admin/advertisers/${H(a.slug)}/edit" class="btn btn-ghost">Edit</a>`}
        ${isLegacy ? '' : `<a href="/admin/advertisers/${H(a.slug)}/analytics" class="btn btn-ghost">Analytics</a>`}
        ${isLegacy ? '' : `<a href="/admin/advertisers/${H(a.slug)}/reconcile" class="btn btn-primary">Reconcile</a>`}
        ${isLegacy ? '' : `<form method="POST" action="/admin/advertisers/${H(a.slug)}/toggle" style="display:inline">
          <button class="btn ${a.status==='active'?'btn-warn':'btn-ghost'}">${a.status==='active'?'Pause':'Activate'}</button></form>`}
        ${isLegacy ? '' : `<form method="POST" action="/admin/advertisers/${H(a.slug)}/delete" style="display:inline"
          onsubmit="return confirm('Delete ${H(a.name)}? Historical data is kept.')">
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
      <td>$${$(r.payout)}</td><td>${cvr(r.clicks,r.conversions)}</td>
      <td><a href="/admin/export.csv?advertiser=${H(r.advertiser_slug)}&month=${thisMonth}" class="btn btn-ghost">CSV</a></td>
    </tr>`;
  }).join('');

  const recentRows = recent.map(r => {
    const adv = advStats.find(a => a.slug === r.advertiser_slug);
    return `<tr>
      <td>${H(r.received_at)}</td><td>${H(adv?.name||r.advertiser_slug)}</td>
      <td><code>${H(r.publisher)}</code></td>
      <td><code class="xs">${H(r.click_id)}</code></td>
      <td><span class="badge ev">${H(r.event)}</span></td>
      <td>$${$(r.payout)}</td>
    </tr>`;
  }).join('');

  const body = `
${adminHeader(`<a href="/admin/export.csv" class="hbtn ghost">Export All</a>
  <a href="/admin/advertisers/new" class="hbtn">+ Advertiser</a>`)}
<main>
${flashHtml(flash)}
<div class="cards">
  <div class="card"><div class="lbl">Total Clicks</div><div class="val">${N(totalClicks)}</div></div>
  <div class="card"><div class="lbl">Total Conversions</div><div class="val">${N(totalConversions)}</div></div>
  <div class="card"><div class="lbl">Approved Payout</div><div class="val green">$${$(approvedPayout)}</div></div>
  <div class="card"><div class="lbl">Pending Payout</div><div class="val" style="color:#f57f17">$${$(pendingPayout)}</div></div>
  <div class="card"><div class="lbl">Approved This Month</div><div class="val green">$${$(monthlyPayout)}</div></div>
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
        <th>Conv</th><th>Payout</th><th>CVR</th><th>Postback URL</th><th>Actions</th></tr></thead>
        <tbody>${advRows}</tbody></table>`}
</section>

<section>
  <div class="sh"><h2>Publisher Performance</h2><span class="meta">Top 100 by payout</span></div>
  ${pubRows.length===0 ? '<div class="empty">No data yet.</div>'
    : `<table><thead><tr><th>Advertiser</th><th>Publisher</th><th>Clicks</th><th>Conv</th><th>Payout</th><th>CVR</th><th></th></tr></thead>
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
      <a href="/admin/export.csv" class="btn btn-ghost">All CSV</a>
      <a href="/admin/export.csv?month=${thisMonth}" class="btn btn-ghost">${thisMonth} CSV</a></div>
  </div>
  ${recentRows.length===0 ? '<div class="empty">No conversions yet.</div>'
    : `<table><thead><tr><th>Received</th><th>Advertiser</th><th>Publisher</th><th>Click ID</th><th>Event</th><th>Payout</th></tr></thead>
        <tbody>${recentRows}</tbody></table>`}
</section>
</main><script>${CP_JS}</script>`;

  return adminLayout('Dashboard', body);
}

function renderAdvList({ advStats, flash }) {
  const rows = advStats.filter(a => a.slug !== 'legacy' || a.clicks > 0).map(a => {
    const trackUrl  = `${BASE_URL}/track/${a.slug}?pub=PUBLISHER_NAME`;
    const postbkUrl = `${BASE_URL}/postback/${a.slug}?click_id=CLICK_ID&payout=AMOUNT&event=sale`;
    const isLegacy  = a.slug === 'legacy';
    return `<tr>
      <td>
        <strong>${H(a.name)}</strong>
        ${isLegacy ? '' : `<div style="margin-top:5px"><div class="ubox" onclick="cp(this,'${H(trackUrl)}')">/track/${H(a.slug)}?pub=PUBLISHER_NAME</div></div>`}
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
        ${isLegacy ? '' : `<div class="ubox" onclick="cp(this,'${H(postbkUrl)}')" style="max-width:200px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis">/postback/${H(a.slug)}?click_id=…</div>`}
      </td>
      <td><div class="act">
        ${isLegacy ? '' : `<a href="/admin/advertisers/${H(a.slug)}/edit" class="btn btn-ghost">Edit</a>`}
        ${isLegacy ? '' : `<a href="/admin/advertisers/${H(a.slug)}/analytics" class="btn btn-ghost">Analytics</a>`}
        ${isLegacy ? '' : `<a href="/admin/advertisers/${H(a.slug)}/reconcile" class="btn btn-primary">Reconcile</a>`}
        ${isLegacy ? '' : `<form method="POST" action="/admin/advertisers/${H(a.slug)}/toggle" style="display:inline">
          <button class="btn ${a.status==='active'?'btn-warn':'btn-ghost'}">${a.status==='active'?'Pause':'Activate'}</button></form>`}
        ${isLegacy ? '' : `<form method="POST" action="/admin/advertisers/${H(a.slug)}/delete" style="display:inline"
          onsubmit="return confirm('Delete ${H(a.name)}? Historical data is kept.')">
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

function renderAdvForm({ title, action, adv = {}, error }) {
  const isEdit = action.includes('/update');
  const statusOpts = ['active','paused'].map(s =>
    `<option value="${s}" ${(adv.status||'active')===s?'selected':''}>${s[0].toUpperCase()+s.slice(1)}</option>`
  ).join('');

  const body = `${adminHeader()}
<main><div class="fw">
  <h2>${H(title)}</h2>
  ${error ? `<div class="form-err">${H(error)}</div>` : ''}
  <form method="POST" action="${H(action)}">
    <div class="fg"><label>Advertiser Name *</label>
      <input type="text" name="name" value="${H(adv.name||'')}" required
             oninput="${isEdit?'':'autoSlug(this)'}"></div>
    ${isEdit ? '' : `<div class="fg"><label>Slug (used in URLs) *</label>
      <input type="text" name="slug" id="slug" value="${H(adv.slug||'')}"
             pattern="[a-z0-9-]+" required placeholder="e.g. acbs, shb-finance">
      <small>Lowercase letters, numbers, hyphens. Cannot be changed after creation.</small></div>`}
    <div class="fg"><label>Offer URL *</label>
      <input type="url" name="offer_url" value="${H(adv.offer_url||'')}" placeholder="https://…" required>
      <small>A <code>click_id</code> param will be appended automatically.</small></div>
    <div class="fg-row">
      <div class="fg"><label>Default Payout ($)</label>
        <input type="number" name="payout_amount" value="${H(adv.payout_amount||'0')}" step="0.01" min="0">
        <small>Used when postback sends no payout.</small></div>
      <div class="fg"><label>Status</label><select name="status">${statusOpts}</select></div>
    </div>
    ${isEdit && adv.slug ? `
    <div class="fg"><label>Tracking URL format</label>
      <div class="ubox" onclick="cp(this,'${H(BASE_URL)}/track/${H(adv.slug)}?pub=PUBLISHER_NAME')">
        ${H(BASE_URL)}/track/${H(adv.slug)}?pub=PUBLISHER_NAME</div></div>
    <div class="fg"><label>Postback URL format</label>
      <div class="ubox" onclick="cp(this,'${H(BASE_URL)}/postback/${H(adv.slug)}?click_id=CLICK_ID&payout=AMOUNT&event=sale')">
        ${H(BASE_URL)}/postback/${H(adv.slug)}?click_id=CLICK_ID&amp;payout=AMOUNT&amp;event=sale</div></div>` : ''}
    <div class="form-act">
      <button type="submit" class="btn btn-primary btn-lg">Save Advertiser</button>
      <a href="/admin" class="btn btn-ghost btn-lg">Cancel</a>
    </div>
  </form>
</div></main>
<script>
function autoSlug(n){const s=document.getElementById('slug');if(s)s.value=n.value.toLowerCase().trim().replace(/[^a-z0-9]+/g,'-').replace(/^-+|-+$/g,'');}
${CP_JS}
</script>`;

  return adminLayout(title, body);
}

function renderPubList({ publishers, pending = [], flash }) {
  const pendingRows = pending.map(p => `<tr style="background:#fffbf0">
    <td>
      <strong>${H(p.username)}</strong>
      ${p.email    ? `<div style="font-size:11px;color:#6e6e73;margin-top:2px">${H(p.email)}</div>` : ''}
      ${p.company  ? `<div style="font-size:11px;color:#8e8e93">${H(p.company)}</div>` : ''}
      ${p.website  ? `<div style="font-size:11px"><a href="${H(p.website)}" target="_blank" style="color:#0071e3">${H(p.website.replace(/^https?:\/\//,''))}</a></div>` : ''}
      ${p.traffic_sources ? `<div style="margin-top:4px">${p.traffic_sources.split(',').map(s => `<span style="background:#f5f5f7;border:1px solid #e0e0e0;border-radius:4px;padding:1px 6px;font-size:10px;margin-right:3px">${H(s)}</span>`).join('')}</div>` : ''}
    </td>
    <td><span class="badge pending">Pending</span></td>
    <td style="color:#8e8e93;font-size:11px">${H(p.created_at?.slice(0,10)||'')}</td>
    <td>
      <div class="act">
        <form method="POST" action="/admin/publishers/${p.id}/approve" style="display:inline">
          <button class="btn btn-primary">Approve</button>
        </form>
        <form method="POST" action="/admin/publishers/${p.id}/reject" style="display:inline"
              onsubmit="return confirm('Reject application from ${H(p.username)}?')">
          <button class="btn btn-danger">Reject</button>
        </form>
        <form method="POST" action="/admin/publishers/${p.id}/delete" style="display:inline"
              onsubmit="return confirm('Permanently delete application from ${H(p.username)}?')">
          <button class="btn btn-ghost">Delete</button>
        </form>
      </div>
    </td>
  </tr>`).join('');

  const rows = publishers.map(p => {
    const keyBadge = p.api_key
      ? `<code style="font-size:10px;color:#2e7d32">…${p.api_key.slice(-8)}</code>`
      : `<span style="font-size:10px;color:#c62828">revoked</span>`;
    return `<tr>
    <td>
      <strong>${H(p.username)}</strong>
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
      <form onsubmit="event.preventDefault();const v=this.period.value;if(v){const[y,m]=v.split('-');location.href='/admin/publishers/${p.id}/invoice/'+y+'/'+m;}" style="display:inline-flex;gap:3px;vertical-align:middle">
        <input type="month" name="period" value="${new Date().toISOString().slice(0,7)}" style="padding:4px 7px;border:1px solid #d2d2d7;border-radius:6px;font-size:11px;height:27px">
        <button type="submit" class="btn btn-ghost">Invoice</button>
      </form>
      <form method="POST" action="/admin/publishers/${p.id}/regenerate-key" style="display:inline"
            onsubmit="return confirm('Regenerate API key for ${H(p.username)}? The old key stops working immediately.')">
        <button class="btn btn-ghost">↻ Key</button>
      </form>
      ${p.api_key ? `<form method="POST" action="/admin/publishers/${p.id}/revoke-key" style="display:inline"
            onsubmit="return confirm('Revoke API key for ${H(p.username)}?')">
        <button class="btn btn-danger">Revoke Key</button>
      </form>` : ''}
      <form method="POST" action="/admin/publishers/${p.id}/toggle" style="display:inline">
        <button class="btn ${p.status==='active'?'btn-warn':'btn-ghost'}">${p.status==='active'?'Pause':'Activate'}</button>
      </form>
      <form method="POST" action="/admin/publishers/${p.id}/delete" style="display:inline"
            onsubmit="return confirm('Delete publisher ${H(p.username)}?')">
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
    <td>$${$(inv.total_amount)}</td>
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

function renderInvoice({ inv, pub, lines, flash }) {
  const MONTHS = ['','January','February','March','April','May','June',
                  'July','August','September','October','November','December'];

  const invNum  = `INV-${inv.year}${String(inv.month).padStart(2,'0')}-${String(inv.id).padStart(4,'0')}`;
  const period  = `${MONTHS[inv.month]} ${inv.year}`;
  const total   = lines.reduce((s, r) => s + r.payout, 0);

  const statusColor = { draft: '#f57f17', sent: '#1565c0', paid: '#2e7d32' };
  const statusLabel = { draft: 'DRAFT', sent: 'SENT', paid: 'PAID' };
  const nextStatus  = { draft: 'sent', sent: 'paid', paid: 'draft' };
  const nextLabel   = { draft: 'Mark as Sent', sent: 'Mark as Paid', paid: 'Revert to Draft' };

  const lineRows = lines.map(l => `<tr>
    <td style="color:#6e6e73;font-size:11px">${H(l.received_at.slice(0,10))}</td>
    <td>${H(l.adv_name || l.advertiser_slug)}</td>
    <td style="font-size:11px"><span style="background:#e3f2fd;color:#1565c0;padding:2px 6px;border-radius:10px;font-size:10px;font-weight:700;text-transform:uppercase">${H(l.event)}</span></td>
    <td style="font-family:monospace;font-size:11px;color:#6e6e73">${H(l.click_id)}</td>
    <td style="text-align:right;font-weight:600">$${$(l.payout)}</td>
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
  <form method="POST" action="/admin/invoices/${H(inv.id)}/status" style="display:inline">
    <input type="hidden" name="status" value="${H(nextStatus[inv.status] || 'draft')}">
    <button class="btn btn-primary btn-lg">${H(nextLabel[inv.status] || 'Update Status')}</button>
  </form>
  <form method="POST" action="/admin/publishers/${H(pub.id)}/invoice/${inv.year}/${inv.month}/regenerate" style="display:inline">
    <button class="btn btn-ghost btn-lg">↻ Recalculate</button>
  </form>
  <button class="btn btn-ghost btn-lg" onclick="window.print()">Print / Save PDF</button>
  <a href="/admin/invoices" class="btn btn-ghost btn-lg">← All Invoices</a>
</div>
<div class="no-print" style="max-width:820px;margin:12px auto 0">
  <form method="POST" action="/admin/publishers/${H(pub.id)}/invoice/${inv.year}/${inv.month}/notes" style="display:flex;gap:8px;align-items:flex-start">
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
        <span class="inv-total-val">$${$(total)}</span>
      </div>`}

  ${inv.notes ? `<div class="inv-notes">${H(inv.notes)}</div>` : ''}

</div>`;

  return adminLayout(`Invoice ${invNum}`, body);
}

function renderPaymentsPage({ pub, payments, totalPaid, approvedBalance, flash }) {
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
  <div class="card"><div class="lbl">Approved Earnings</div><div class="val green">$${$(approvedBalance)}</div></div>
  <div class="card"><div class="lbl">Total Paid Out</div><div class="val">$${$(totalPaid)}</div></div>
  <div class="card"><div class="lbl">Outstanding Balance</div><div class="val ${balance>0?'green':''}" style="${balance<0?'color:#c62828':''}">$${$(balance)}</div></div>
  <div class="card"><div class="lbl">Minimum Payout</div><div class="val" style="font-size:18px">$${$(minPay)}</div></div>
</div>

<section style="margin-bottom:20px">
  <div class="sh"><h2>Record New Payment</h2></div>
  <div style="padding:20px 24px">
    <form method="POST" action="/admin/publishers/${H(pub.id)}/payments"
          style="display:grid;grid-template-columns:130px 160px 1fr 1fr auto;gap:10px;align-items:end">
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

function renderPubForm({ title, action, pub = {}, error, flash }) {
  const isEdit = action.includes('/update');
  const statusOpts = ['active','paused'].map(s =>
    `<option value="${s}" ${(pub.status||'active')===s?'selected':''}>${s[0].toUpperCase()+s.slice(1)}</option>`
  ).join('');

  const body = `${adminHeader('<a href="/admin/publishers" class="hbtn ghost">← Publishers</a>')}
<main><div class="fw">
  <h2>${H(title)}</h2>
  ${flash   ? `<div class="flash success">${H(flash.text)}</div>` : ''}
  ${error   ? `<div class="form-err">${H(error)}</div>` : ''}
  <form method="POST" action="${H(action)}">
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
    ${isEdit ? `<div class="fg"><label>API Key</label>
      ${pub.api_key
        ? `<div style="display:flex;gap:8px;align-items:center;margin-bottom:8px">
            <input type="text" id="apiKeyInput" value="${H(pub.api_key)}" readonly
                   style="font-family:monospace;font-size:12px;flex:1;background:#f5f5f7;color:#1d1d1f">
            <button type="button" class="btn btn-ghost" onclick="toggleKey()">Show</button>
            <button type="button" class="btn btn-ghost" onclick="cp(document.getElementById('apiKeyInput'),'${H(pub.api_key)}')">Copy</button>
          </div>
          <div style="display:flex;gap:8px">
            <form method="POST" action="/admin/publishers/${H(pub.id)}/regenerate-key" style="display:inline"
                  onsubmit="return confirm('Regenerate API key? The current key stops working immediately.')">
              <button class="btn btn-warn">↻ Regenerate Key</button>
            </form>
            <form method="POST" action="/admin/publishers/${H(pub.id)}/revoke-key" style="display:inline"
                  onsubmit="return confirm('Revoke this API key? The publisher will lose API access until a new key is generated.')">
              <button class="btn btn-danger">Revoke Key</button>
            </form>
          </div>`
        : `<div style="color:#c62828;font-size:13px;margin-bottom:8px">API key is revoked — publisher cannot use key auth.</div>
           <form method="POST" action="/admin/publishers/${H(pub.id)}/regenerate-key" style="display:inline">
             <button class="btn btn-primary">Generate New Key</button>
           </form>`}
      <small style="display:block;margin-top:8px">Key is masked by default. The publisher sees their key in their portal. Use <code>X-API-Key: kom_live_...</code> header for REST API access.</small>
    </div>` : ''}
    ${isEdit ? `<div class="fg"><label>Their Tracking URLs</label>
      <small style="display:block;margin-bottom:8px">One link per active advertiser — pre-filled with their username.</small>
      ${db.prepare("SELECT slug,name FROM advertisers WHERE status='active' AND slug!='legacy' ORDER BY name").all()
        .map(a => {
          const url = `${BASE_URL}/track/${a.slug}?pub=${encodeURIComponent(pub.username||'')}`;
          return `<div style="margin-bottom:6px">
            <div style="font-size:10px;color:#6e6e73;margin-bottom:2px">${H(a.name)}</div>
            <div class="ubox" onclick="cp(this,'${H(url)}')">${H(url)}</div>
          </div>`;
        }).join('')}
    </div>` : ''}
    <div class="form-act">
      <button type="submit" class="btn btn-primary btn-lg">${isEdit?'Save Changes':'Create Publisher'}</button>
      ${isEdit ? `<a href="/admin/publishers/${H(pub.id)}/payments" class="btn btn-ghost btn-lg">Payment History</a>` : ''}
      <a href="/admin/publishers" class="btn btn-ghost btn-lg">Cancel</a>
    </div>
  </form>
</div></main>
<script>
${CP_JS}
function toggleKey(){
  const inp=document.getElementById('apiKeyInput');
  if(!inp)return;
  const btn=inp.nextElementSibling;
  if(inp.type==='password'){inp.type='text';btn.textContent='Hide';}
  else{inp.type='password';btn.textContent='Show';}
}
document.addEventListener('DOMContentLoaded',()=>{
  const inp=document.getElementById('apiKeyInput');
  if(inp)inp.type='password';
});
</script>`;

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
        <input type="checkbox" name="${name}" ${checked ? 'checked' : ''} onchange="this.form.submit()"
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
        <a href="https://myaccount.google.com/apppasswords" target="_blank" style="color:#0071e3">myaccount.google.com/apppasswords</a>.
      </div>` : ''}
      <form method="POST" action="/admin/settings/test-email" style="display:inline">
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
        Create a bot via <a href="https://t.me/BotFather" target="_blank" style="color:#0071e3">@BotFather</a>, then add it to your channel and get the chat ID.
      </div>` : ''}
      <form method="POST" action="/admin/settings/test-telegram" style="display:inline">
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
      <form method="POST" action="/admin/settings/test-slack" style="display:inline">
        <button class="btn btn-ghost" ${!slOk ? 'disabled' : ''}>Send Test Message</button>
      </form>
    </div>
  </section>

  <section>
    <div class="sh"><h2>Notification Preferences</h2></div>
    <div style="padding:0 20px">
      <form method="POST" action="/admin/settings" id="settings-form">
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

function renderReconcilePage({ adv, runs, runResult }) {
  const resultHtml = runResult ? (() => {
    const { run, unmatched, rejected } = runResult;
    const matchRate = run.total_rows > 0 ? Math.round((run.matched / run.total_rows) * 100) : 0;
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

    return `
    <section style="border:2px solid #0071e3">
      <div class="sh"><h2>Run #${run.id} — ${H(run.filename)}</h2>
        <span class="meta">${H(run.uploaded_at)}</span></div>
      <div class="cards" style="padding:20px;margin-bottom:0">
        <div class="card"><div class="lbl">Total Rows</div><div class="val">${N(run.total_rows)}</div></div>
        <div class="card"><div class="lbl">Matched</div><div class="val">${N(run.matched)} <small style="font-size:12px;color:#6e6e73">(${matchRate}%)</small></div></div>
        <div class="card"><div class="lbl">Approved</div><div class="val green">${N(run.approved)}</div></div>
        <div class="card"><div class="lbl">Rejected</div><div class="val" style="color:#c62828">${N(run.rejected)}</div></div>
        <div class="card"><div class="lbl">Unmatched</div><div class="val" style="color:#f57f17">${N(run.unmatched)}</div></div>
      </div>
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
    <td>${H(r.uploaded_at)}</td>
    <td>${H(r.filename)}</td>
    <td>${N(r.total_rows)}</td>
    <td>${N(r.matched)}</td>
    <td><span style="color:#2e7d32;font-weight:600">${N(r.approved)}</span></td>
    <td><span style="color:#c62828">${N(r.rejected)}</span></td>
    <td><span style="color:#f57f17">${N(r.unmatched)}</span></td>
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
      <code>click_id,status,reason,payout</code><br>
      <code>abc-123-def,approved,,15.00</code><br>
      <code>xyz-456-ghi,rejected,Duplicate application,</code><br><br>
      <strong>Columns:</strong> <code>click_id</code> (required) · <code>status</code>: <code>approved</code> or <code>rejected</code> (required) · <code>reason</code> (optional) · <code>payout</code> override (optional)
    </div>
    <form method="POST" action="/admin/advertisers/${H(adv.slug)}/reconcile" enctype="multipart/form-data">
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
    <th>Approved</th><th>Rejected</th><th>Unmatched</th><th></th>
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

// ---------------------------------------------------------------------------
// Publisher portal HTML templates
// ---------------------------------------------------------------------------

function pubLayout(title, body, pub = null, activeTab = null) {
  const fonts = '<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap" rel="stylesheet">';
  if (!pub) {
    return `<!DOCTYPE html><html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${H(title)} — Komorebi</title>${fonts}<style>${PUB_CSS}</style></head>
<body>${body}</body></html>`;
  }

  const initials = (pub.username || '??').slice(0, 2).toUpperCase();
  const ic = (d) => `<svg width="14" height="14" fill="currentColor" viewBox="0 0 16 16">${d}</svg>`;
  const PICONS = {
    dashboard:   ic(`<rect x="1" y="1" width="6" height="6" rx="1"/><rect x="9" y="1" width="6" height="6" rx="1"/><rect x="1" y="9" width="6" height="6" rx="1"/><rect x="9" y="9" width="6" height="6" rx="1"/>`),
    conversions: ic(`<path fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" d="M2 4h12M2 8h8M2 12h10"/>`),
    payments:    ic(`<path fill="none" stroke="currentColor" stroke-width="1.5" d="M1 4.5h14a.5.5 0 0 1 .5.5v7a.5.5 0 0 1-.5.5H1a.5.5 0 0 1-.5-.5V5a.5.5 0 0 1 .5-.5z"/><path stroke="currentColor" stroke-width="1.4" d="M.5 7.5h15"/>`),
    api:         ic(`<path fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" d="M5 5L2 8l3 3M11 5l3 3-3 3M8 3v10"/>`),
    docs:        ic(`<path fill="none" stroke="currentColor" stroke-width="1.5" d="M3.5 1h9a.5.5 0 0 1 .5.5v13a.5.5 0 0 1-.5.5h-9A.5.5 0 0 1 3 14.5v-13A.5.5 0 0 1 3.5 1z"/><path stroke="currentColor" stroke-width="1.3" stroke-linecap="round" d="M5.5 5h5M5.5 8h5M5.5 11h3"/>`),
  };
  const navItem = (href, key, label, external = false) =>
    `<a href="${href}" class="pub-nav-a${activeTab===key?' active':''}"${external?' target="_blank"':''}>${PICONS[key]||''}<span>${label}</span>${external?'<svg width="9" height="9" viewBox="0 0 16 16" fill="currentColor" style="margin-left:auto;opacity:.35"><path d="M6 3h7v7l-2-2-4 4-2-2 4-4L6 3z"/></svg>':''}</a>`;

  return `<!DOCTYPE html><html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${H(title)} — Komorebi Publisher Portal</title>${fonts}<style>${PUB_CSS}</style></head>
<body>
<div class="pub-shell">
  <header class="pub-topbar">
    <div class="pub-brand">
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
    <aside class="pub-sidebar">
      <div class="pub-sb-group">OVERVIEW</div>
      ${navItem('/publisher/dashboard',   'dashboard',   'Dashboard')}
      ${navItem('/publisher/conversions', 'conversions', 'Conversions')}
      ${navItem('/publisher/payments',    'payments',    'Payments')}
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
    <div class="pub-content">
      ${body}
    </div>
  </div>
</div>
<script>${CP_JS}</script>
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
                 oninput="this.value=this.value.toLowerCase().replace(/[^a-z0-9_-]/g,'')"></div>
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

function renderPubLogin({ error, username, success } = {}) {
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
      <div class="login-fg"><label>Username</label>
        <input type="text" name="username" value="${H(username||'')}" required autofocus autocomplete="username"></div>
      <div class="login-fg"><label>Password</label>
        <input type="password" name="password" required autocomplete="current-password"></div>
      <button type="submit" class="login-btn">Sign in</button>
    </form>
    <div class="login-link">Don't have an account? <a href="/publisher/register">Apply to join →</a></div>
  </div>
</div>`);
}

function renderPubConversions({ pub, conversions }) {
  const rows = conversions.map(r => `<tr>
    <td style="white-space:nowrap;font-size:11px">${H(r.received_at.slice(0,10))}</td>
    <td>${H(r.adv_name||r.advertiser_slug)}</td>
    <td><code class="xs">${H(r.click_id)}</code></td>
    <td><span class="badge">${H(r.event)}</span></td>
    <td>${usdVnd(r.payout)}</td>
    <td><span class="badge ${H(r.status||'pending')}">${H(r.status||'pending')}</span>
        ${r.reason ? `<div style="font-size:10px;color:#6e6e73;margin-top:2px">${H(r.reason)}</div>` : ''}</td>
  </tr>`).join('');

  const body = `<main>
<section>
  <div class="sh"><h2>Conversion History</h2><span class="meta">${N(conversions.length)} conversions (last 500)</span></div>
  ${rows.length===0
    ? '<div class="empty">No conversions recorded yet.</div>'
    : `<table><thead><tr><th>Date</th><th>Advertiser</th><th>Click ID</th><th>Event</th><th>Payout</th><th>Status</th></tr></thead>
        <tbody>${rows}</tbody></table>`}
</section>
</main>`;
  return pubLayout(`${pub.username} — Conversions`, body, pub, 'conversions');
}

function renderPubPayments({ pub, payments, totalPaid, approvedBal }) {
  const minPay  = pub.minimum_payout ?? 50;
  const balance = approvedBal - totalPaid;
  const rows    = payments.map(p => `<tr>
    <td>${H(p.paid_at)}</td>
    <td><strong style="color:#0F6E56">${usdVnd(p.amount_usd)}</strong></td>
    <td>${H(p.method)}</td>
    <td style="font-size:11px;color:#6e6e73">${H(p.notes)}</td>
  </tr>`).join('');

  const body = `<main>
<div class="cards" style="margin-bottom:20px">
  <div class="card"><div class="lbl">Total Paid Out</div><div class="val blue">$${$(totalPaid)}</div></div>
  <div class="card"><div class="lbl">Approved Earnings</div><div class="val green">$${$(approvedBal)}</div></div>
  <div class="card"><div class="lbl">Outstanding Balance</div><div class="val ${balance>0?'green':''}" style="${balance<0?'color:#c62828':''}">$${$(balance)}</div></div>
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
  const body = `
<main>
<section>
  <div class="sh"><h2>API Access</h2></div>
  <div style="padding:20px 22px">
    ${pub.api_key ? `
    <p style="font-size:13px;color:#6e6e73;margin-bottom:14px">Use your API key with the <code>X-API-Key</code> header to fetch your stats programmatically. See <a href="/docs#rest-api" style="color:#0F6E56">documentation</a> for details.</p>
    <div style="display:flex;gap:8px;align-items:center;margin-bottom:14px">
      <input type="text" id="pubApiKey" value="${H(pub.api_key)}" readonly
             style="font-family:monospace;font-size:12px;flex:1;background:#f5f5f7;border:1px solid #d2d2d7;border-radius:7px;padding:8px 11px">
      <button class="btn btn-ghost" onclick="togglePubKey()">Show</button>
      <button class="btn btn-ghost" onclick="cp(document.getElementById('pubApiKey'),'${H(pub.api_key)}')">Copy</button>
    </div>
    <div class="ubox" onclick="cp(this,'curl -H \\'X-API-Key: ${H(pub.api_key)}\\' ${H(BASE_URL)}/api/v1/stats')"
         style="font-size:11px;color:#555;margin-bottom:20px">
      curl -H "X-API-Key: ${H(pub.api_key.slice(0,18))}…" ${H(BASE_URL)}/api/v1/stats
    </div>
    <h3 style="font-size:13px;font-weight:600;margin-bottom:10px">Example Response</h3>
    <pre style="background:#f5f5f7;border-radius:8px;padding:14px;font-size:11px;overflow-x:auto;color:#333">GET /api/v1/stats → { publisher, status, stats: { clicks, conversions, earnings }, by_advertiser }</pre>
    ` : `<div style="color:#c62828;font-size:13px">Your API key has been revoked. Contact your account manager to issue a new one.</div>`}
  </div>
</section>
</main>
<script>
${CP_JS}
function togglePubKey(){
  var inp=document.getElementById('pubApiKey');
  if(!inp)return;
  var btn=inp.nextElementSibling;
  if(inp.type==='password'){inp.type='text';btn.textContent='Hide';}
  else{inp.type='password';btn.textContent='Show';}
}
document.addEventListener('DOMContentLoaded',function(){
  var inp=document.getElementById('pubApiKey');
  if(inp)inp.type='password';
});
</script>`;
  return pubLayout(`${pub.username} — API Access`, body, pub, 'api');
}

function renderPubDashboard({ pub, totalClicks, totalConversions,
  totalPayout, pendingPayout, monthlyPayout, monthlyPendingPayout,
  advStats, recent, thisMonth, payments = [], totalPaid = 0 }) {

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
      Approved balance: <strong style="color:#0F6E56">${usdVnd(balance)}</strong>
      ${totalPaid > 0 ? `&nbsp;·&nbsp; Total paid out: <strong>$${$(totalPaid)}</strong>` : ''}
    </div>
  </div>
  ${payable ? `<div style="font-size:12px;color:#0F6E56;font-weight:600">Contact your account manager to request payment →</div>` : `<div style="font-size:12px;color:#8e8e93">$${$(minPay - balance)} more needed</div>`}
</div>`;

  // ── Rows ─────────────────────────────────────────────────────────────────
  const advRows = advStats.map(a => `<tr>
    <td><strong>${H(a.name)}</strong></td>
    <td><div class="ubox" onclick="cp(this,'${H(a.trackingUrl)}')">${H(a.trackingUrl)}</div></td>
    <td>${N(a.clicks)}</td>
    <td>${N(a.approved_count)} ${a.pending_count > 0 ? `<span style="color:#f57f17;font-size:10px">+${a.pending_count} pending</span>` : ''}</td>
    <td>
      <span style="color:#0F6E56;font-weight:600">${usdVnd(a.approved_payout)}</span>
      ${a.pending_payout > 0 ? `<div style="font-size:10px;color:#f57f17">${usdVnd(a.pending_payout)} pending</div>` : ''}
    </td>
    <td>${cvr(a.clicks, a.conversions)}</td>
  </tr>`).join('');

  const recentRows = recent.map(r => `<tr>
    <td>${H(r.received_at)}</td>
    <td>${H(r.adv_name||r.advertiser_slug)}</td>
    <td><code class="xs">${H(r.click_id)}</code></td>
    <td><span class="badge">${H(r.event)}</span></td>
    <td>${usdVnd(r.payout)}</td>
    <td><span class="badge ${H(r.status||'pending')}">${H(r.status||'pending')}</span>
        ${r.reason ? `<div style="font-size:10px;color:#6e6e73;margin-top:2px">${H(r.reason)}</div>` : ''}</td>
  </tr>`).join('');

  const paymentRows = payments.map(p => `<tr>
    <td>${H(p.paid_at)}</td>
    <td><strong style="color:#0F6E56">${usdVnd(p.amount_usd)}</strong></td>
    <td>${H(p.method)}</td>
    <td style="font-size:11px;color:#6e6e73">${H(p.notes)}</td>
  </tr>`).join('');

  const body = `<main>

${checklist}

<div class="cards">
  <div class="card"><div class="lbl">Total Clicks</div><div class="val">${N(totalClicks)}</div></div>
  <div class="card"><div class="lbl">Total Conversions</div><div class="val">${N(totalConversions)}</div></div>
  <div class="card"><div class="lbl">Approved Earnings</div><div class="val blue">${usdVnd(totalPayout)}</div></div>
  <div class="card"><div class="lbl">Pending Earnings</div><div class="val" style="color:#f57f17">${usdVnd(pendingPayout)}</div></div>
  <div class="card"><div class="lbl">This Month Approved</div><div class="val blue">${usdVnd(monthlyPayout)}</div></div>
  <div class="card"><div class="lbl">This Month Pending</div><div class="val" style="color:#f57f17">${usdVnd(monthlyPendingPayout)}</div></div>
</div>

${payoutBanner}

<section>
  <div class="sh"><h2>Tracking Links &amp; Earnings</h2><span class="meta">Click any URL to copy</span></div>
  ${advStats.length===0
    ? '<div class="empty">No active advertisers yet. Contact your account manager.</div>'
    : `<table><thead><tr><th>Advertiser</th><th>Your Tracking URL</th><th>Clicks</th><th>Conversions</th><th>Earnings</th><th>CVR</th></tr></thead>
        <tbody>${advRows}</tbody></table>`}
</section>

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
  convStatus = {} }) {

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

      <h3 class="sub-title" id="appsflyer">AppsFlyer Integration</h3>
      <p>To configure Komorebi as an integrated partner in AppsFlyer:</p>
      <ol class="steps">
        <li>Log in to your AppsFlyer dashboard and open the app you want to configure.</li>
        <li>Go to <strong>Configuration → Integrated Partners</strong> and search for <strong>Komorebi</strong>. If not listed, proceed with a custom partner (see your account manager).</li>
        <li>In the <strong>Integration</strong> tab, enable the partner and paste the postback URL below.</li>
        <li>Under <strong>Click-Through Attribution</strong>, map the postback URL's <code>click_id</code> parameter to AppsFlyer's click ID macro <code>{clickid}</code>.</li>
        <li>Save and test using AppsFlyer's postback validation tool.</li>
      </ol>

      <div class="code-label">AppsFlyer postback URL</div>
      <div class="code-block"><pre>${TRACK_DOMAIN}/postback/<span class="key">{advertiser}</span>?click_id=<span class="str">{clickid}</span>&amp;payout=<span class="str">{revenue}</span>&amp;event=<span class="str">{event_name}</span></pre></div>

      <h3 class="sub-title" id="adjust">Adjust Integration</h3>
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
            <thead><tr><th>Komorebi param</th><th>AppsFlyer macro</th><th>Adjust macro</th></tr></thead>
            <tbody>
              <tr><td><code>click_id</code></td><td><code>{clickid}</code></td><td><code>{click_id}</code></td></tr>
              <tr><td><code>payout</code></td><td><code>{revenue}</code></td><td><code>{revenue}</code></td></tr>
              <tr><td><code>event</code></td><td><code>{event_name}</code></td><td><code>{event_token}</code></td></tr>
            </tbody>
          </table>
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
  console.log(`  Admin      : ${BASE_URL}/admin  (HTTP Basic: ${ADMIN_USER} / ${ADMIN_PASS})`);
  console.log(`  Publishers : ${BASE_URL}/publisher/login`);
  console.log(`  Track      : ${BASE_URL}/track/:advertiser?pub=PUBLISHER`);
  console.log(`  Postback   : ${BASE_URL}/postback/:advertiser?click_id=X&payout=Y&event=sale\n`);

  sendTelegram('🔄 Komorebi tracker restarted — track.komorebimedia.com is up.')
    .catch(e => console.error('Startup Telegram error:', e.message));
});
