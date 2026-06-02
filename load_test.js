'use strict';
/*
 * load_test.js — capacity / breaking-point load test for the Komorebi tracker.
 *
 * Pure Node.js built-ins only (http/https selected by URL protocol — no deps).
 *
 * It exercises the REAL endpoints:
 *   - GET /track/:slug?pub=USER        → 302 redirect with click_id   (the write-heavy click path)
 *   - GET /postback/:slug?click_id=..  → 200 JSON                     (the conversion path)
 * plus admin setup/cleanup over /admin/* with CSRF + session cookie.
 *
 * Scenarios: baseline, normal CPI day, campaign burst, stress ramp (find the
 * knee), and a sustained run at 80% of max to surface SQLite lock contention.
 *
 * Run the server FIRST, then:  BASE=http://localhost:3999 node load_test.js
 *
 * Safety: against a public/prod host the per-IP rate limiter (RATE_LIMIT_MAX,
 * default 100/min) and IP whitelist on /postback will dominate the numbers —
 * intended to be run against a local/staging instance with the limiter raised
 * and POSTBACK_WHITELIST_ENABLED=false. It is destructive (creates + deletes a
 * test advertiser and 10 publishers); cleanup runs in a finally block.
 */

const http  = require('node:http');
const https = require('node:https');
const { URL } = require('node:url');

const BASE       = process.env.BASE || 'http://localhost:3999';
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'testpass123';

const ADV   = { name: 'Load Test Game', slug: 'loadtest-game', payout_amount: 0.50, payout_type: 'fixed' };
const PUBS  = Array.from({ length: 10 }, (_, i) => `loadpub${String(i + 1).padStart(2, '0')}`);
const PUB_PASS = 'loadpass123!';
const EVENT = 'install'; // CPI conversion event (no goal → advertiser default fixed payout)

const isHttps = new URL(BASE).protocol === 'https:';
const agent = new (isHttps ? https : http).Agent({ keepAlive: true, maxSockets: 1024, maxFreeSockets: 256 });

// ---------------------------------------------------------------------------
// low-level HTTP with latency timing
// ---------------------------------------------------------------------------
function request(method, path, { headers = {}, body = null } = {}) {
  return new Promise((resolve) => {
    const u = new URL(path, BASE);
    const lib = u.protocol === 'https:' ? https : http;
    const opts = { method, hostname: u.hostname, port: u.port, path: u.pathname + u.search, headers: { ...headers }, agent };
    if (body != null) {
      opts.headers['Content-Type'] = 'application/x-www-form-urlencoded';
      opts.headers['Content-Length'] = Buffer.byteLength(body);
    }
    const t0 = process.hrtime.bigint();
    const req = lib.request(opts, (res) => {
      let data = '';
      res.on('data', (c) => { if (data.length < 2048) data += c; }); // cap body capture
      res.on('end', () => {
        const ms = Number(process.hrtime.bigint() - t0) / 1e6;
        resolve({ status: res.statusCode, headers: res.headers, body: data, ms });
      });
    });
    req.on('error', (e) => {
      const ms = Number(process.hrtime.bigint() - t0) / 1e6;
      resolve({ status: 0, headers: {}, body: '', ms, err: e.code || e.message });
    });
    if (body != null) req.write(body);
    req.end();
  });
}

// cookie-jar wrapper for the authenticated admin session
function makeJar() {
  let cookie = '';
  return {
    async req(method, path, opts = {}) {
      const headers = { ...(opts.headers || {}) };
      if (cookie) headers.Cookie = cookie;
      const res = await request(method, path, { ...opts, headers });
      const sc = res.headers['set-cookie'];
      if (sc) for (const c of sc) {
        const kv = c.split(';')[0], name = kv.split('=')[0];
        const parts = (cookie ? cookie.split('; ') : []).filter((x) => x.split('=')[0] !== name);
        parts.push(kv); cookie = parts.join('; ');
      }
      return res;
    },
  };
}

const form = (o) => Object.entries(o).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
const csrfOf = (html) => (html.match(/name="_csrf" value="([a-f0-9]+)"/) || [])[1] || '';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// SETUP — advertiser + 10 publishers + assignments (admin, CSRF)
// ---------------------------------------------------------------------------
async function setup() {
  const admin = makeJar();
  const login = await admin.req('POST', '/admin/login', { body: form({ username: ADMIN_USER, password: ADMIN_PASS }) });
  if (login.status !== 302) throw new Error(`admin login failed (HTTP ${login.status}) — check ADMIN_USER/ADMIN_PASS`);

  // advertiser
  let csrf = csrfOf((await admin.req('GET', '/admin/advertisers/new')).body);
  await admin.req('POST', '/admin/advertisers', { body: form({
    name: ADV.name, slug: ADV.slug, offer_url: `https://${ADV.slug}.example/offer`,
    payout_amount: ADV.payout_amount, payout_type: ADV.payout_type,
    click_lookback_window: 30, monthly_conversion_cap: '', status: 'active', _csrf: csrf,
  }) });

  // publishers — capture numeric id from the create redirect (/admin/publishers/{id}/edit)
  const pubIds = {};
  for (const username of PUBS) {
    csrf = csrfOf((await admin.req('GET', '/admin/publishers/new')).body);
    const res = await admin.req('POST', '/admin/publishers', { body: form({ username, password: PUB_PASS, status: 'active', _csrf: csrf }) });
    const id = (String(res.headers.location || '').match(/\/admin\/publishers\/(\d+)\/edit/) || [])[1];
    if (!id) throw new Error(`could not resolve id for publisher ${username} (HTTP ${res.status})`);
    pubIds[username] = id;
  }

  // resolve advertiser numeric id from a publisher edit page's assign dropdown, then assign all 10
  const firstId = pubIds[PUBS[0]];
  const editHtml = (await admin.req('GET', `/admin/publishers/${firstId}/edit`)).body;
  const advId = (editHtml.match(new RegExp(`<option value="(\\d+)">${ADV.name}</option>`)) || [])[1];
  if (!advId) throw new Error('could not resolve advertiser id from assign dropdown');

  for (const username of PUBS) {
    const id = pubIds[username];
    csrf = csrfOf((await admin.req('GET', `/admin/publishers/${id}/edit`)).body);
    await admin.req('POST', `/admin/publishers/${id}/assign`, { body: form({ advertiser_id: advId, _csrf: csrf }) });
  }

  // smoke-test the click→postback path so we fail fast if wiring is off
  const cid = await fireClick(PUBS[0]);
  if (!cid) throw new Error('setup smoke: click did not return a click_id (is the offer_url/redirect set?)');
  const pb = await firePostback(cid);
  if (pb.status !== 200) throw new Error(`setup smoke: postback returned ${pb.status} ${pb.body.slice(0, 120)} (whitelist off? assigned?)`);

  return { admin, pubIds, advId };
}

async function cleanup(ctx) {
  if (!ctx) return;
  const { pubIds } = ctx;
  // Re-login on a fresh jar: the admin session has a 5-min idle timeout and a
  // long load run leaves it idle, so reusing ctx.admin would 403 every delete
  // (empty CSRF) and silently orphan the test data. Verify each delete landed.
  const admin = makeJar();
  const login = await admin.req('POST', '/admin/login', { body: form({ username: ADMIN_USER, password: ADMIN_PASS }) });
  if (login.status !== 302) throw new Error(`cleanup re-login failed (HTTP ${login.status})`);
  let failed = 0;
  for (const username of PUBS) {
    const id = pubIds[username]; if (!id) continue;
    const csrf = csrfOf((await admin.req('GET', `/admin/publishers/${id}/edit`)).body);
    const res = await admin.req('POST', `/admin/publishers/${id}/delete`, { body: form({ _csrf: csrf }) });
    if (res.status !== 302) failed++;
  }
  const csrf = csrfOf((await admin.req('GET', `/admin/advertisers/${ADV.slug}/edit`)).body);
  const advRes = await admin.req('POST', `/admin/advertisers/${ADV.slug}/delete`, { body: form({ _csrf: csrf }) });
  if (advRes.status !== 302) failed++;
  if (failed) throw new Error(`${failed} delete(s) did not return 302 — manual cleanup may be needed`);
}

// ---------------------------------------------------------------------------
// request factories (round-robin across publishers)
// ---------------------------------------------------------------------------
let rr = 0;
const nextPub = () => PUBS[(rr++) % PUBS.length];

async function fireClick(pub = nextPub()) {
  const res = await request('GET', `/track/${ADV.slug}?pub=${pub}`);
  const cid = (String(res.headers.location || '').match(/click_id=([a-f0-9-]+)/) || [])[1] || null;
  return cid;
}

async function firePostback(clickId) {
  return request('GET', `/postback/${ADV.slug}?click_id=${clickId}&event=${EVENT}&payout=${ADV.payout_amount}`);
}

// ---------------------------------------------------------------------------
// load engine — open-loop, multiple concurrent streams, per-stream rates
// ---------------------------------------------------------------------------
const TICK = 20;            // scheduler granularity (ms)
const MAX_INFLIGHT = 4000;  // local backpressure guard

// streams: [{ label, ratePerSec, run: async () => result }]
// result classification is by label: 'click' ok=302, 'postback' ok=200.
function runWindow(durationMs, streams, { clickPool } = {}) {
  return new Promise((resolve) => {
    const samples = []; // { label, status, ms, err, lock }
    let inflight = 0, dropped = 0;
    const carry = streams.map(() => 0);
    const start = Date.now();

    const classify = (label, r) => {
      const okStatus = label === 'click' ? 302 : 200;
      const lock = r.status >= 500 && /lock|sqlite_busy|busy/i.test(r.body);
      return { label, status: r.status, ms: r.ms, err: r.err || null, ok: r.status === okStatus, lock };
    };

    const launch = (stream) => {
      inflight++;
      stream.run().then((r) => {
        if (r) samples.push(classify(stream.label, r));
      }).catch((e) => {
        samples.push({ label: stream.label, status: 0, ms: 0, err: String(e), ok: false, lock: false });
      }).finally(() => { inflight--; });
    };

    const timer = setInterval(() => {
      const elapsed = Date.now() - start;
      if (elapsed >= durationMs) {
        clearInterval(timer);
        const drain = setInterval(() => { if (inflight <= 0) { clearInterval(drain); resolve({ samples, dropped }); } }, 20);
        return;
      }
      streams.forEach((stream, i) => {
        carry[i] += stream.ratePerSec * (TICK / 1000);
        let n = Math.floor(carry[i]); carry[i] -= n;
        while (n-- > 0) {
          if (inflight >= MAX_INFLIGHT) { dropped++; continue; }
          launch(stream);
        }
      });
    }, TICK);
  });
}

// click stream that records click_ids into a shared pool (for later postbacks)
const clickStream = (ratePerSec, pool) => ({
  label: 'click', ratePerSec,
  run: async () => {
    const res = await request('GET', `/track/${ADV.slug}?pub=${nextPub()}`);
    const cid = (String(res.headers.location || '').match(/click_id=([a-f0-9-]+)/) || [])[1];
    if (cid && pool) pool.push(cid);
    return res;
  },
});
// postback stream that consumes click_ids from the pool (skips if pool empty)
const postbackStream = (ratePerSec, pool) => ({
  label: 'postback', ratePerSec,
  run: async () => {
    const cid = pool && pool.shift();
    if (!cid) return null; // nothing to convert yet → skip (not counted)
    return firePostback(cid);
  },
});

// ---------------------------------------------------------------------------
// stats
// ---------------------------------------------------------------------------
function pct(sortedMs, p) {
  if (!sortedMs.length) return 0;
  const idx = Math.min(sortedMs.length - 1, Math.ceil(p / 100 * sortedMs.length) - 1);
  return sortedMs[Math.max(0, idx)];
}
function summarize(samples) {
  const ok = samples.filter((s) => s.ok);
  const lat = samples.map((s) => s.ms).sort((a, b) => a - b);
  const errs = {};
  for (const s of samples.filter((x) => !x.ok)) {
    const key = s.err ? `net:${s.err}` : `http:${s.status}`;
    errs[key] = (errs[key] || 0) + 1;
  }
  return {
    total: samples.length,
    success: ok.length,
    successRate: samples.length ? ok.length / samples.length : 1,
    p50: pct(lat, 50), p95: pct(lat, 95), p99: pct(lat, 99), max: lat[lat.length - 1] || 0,
    locks: samples.filter((s) => s.lock).length,
    errs,
  };
}
const r2 = (n) => Math.round(n * 100) / 100;
function printSummary(name, s, extra = '') {
  const errStr = Object.keys(s.errs).length ? Object.entries(s.errs).map(([k, v]) => `${k}=${v}`).join(', ') : 'none';
  console.log(`\n## ${name}${extra}`);
  console.log(`   requests:     ${s.total}`);
  console.log(`   success:      ${s.success} (${r2(s.successRate * 100)}%)`);
  console.log(`   latency ms:   p50=${r2(s.p50)}  p95=${r2(s.p95)}  p99=${r2(s.p99)}  max=${r2(s.max)}`);
  console.log(`   errors:       ${errStr}`);
  console.log(`   sqlite locks: ${s.locks}`);
}

// ---------------------------------------------------------------------------
// scenarios
// ---------------------------------------------------------------------------
async function main() {
  console.log(`Komorebi load test → ${BASE}`);
  let ctx = null;
  const report = {};
  try {
    console.log('\nSetup: creating advertiser + 10 publishers + assignments…');
    ctx = await setup();
    console.log('Setup OK (smoke click+postback passed).');

    // SCENARIO 1 — Baseline: 10 clicks/sec for 30s, no postbacks
    {
      const { samples } = await runWindow(30_000, [clickStream(10, null)]);
      report.s1 = summarize(samples);
      printSummary('SCENARIO 1 — Baseline (30s, 10 clicks/sec)', report.s1);
    }

    // SCENARIO 2 — Normal CPI day: 18 clicks/min + 1 postback/min for 60s
    {
      const pool = [];
      const { samples } = await runWindow(60_000, [clickStream(18 / 60, pool), postbackStream(1 / 60, pool)], { clickPool: pool });
      report.s2 = summarize(samples);
      printSummary('SCENARIO 2 — Normal CPI day (60s, 18 clicks/min + 1 pb/min)', report.s2);
    }

    // SCENARIO 3 — Campaign burst: 180 clicks/min + 9 postbacks/min for 60s
    {
      const pool = [];
      const { samples } = await runWindow(60_000, [clickStream(180 / 60, pool), postbackStream(9 / 60, pool)], { clickPool: pool });
      report.s3 = summarize(samples);
      printSummary('SCENARIO 3 — Campaign burst (60s, 180 clicks/min + 9 pb/min)', report.s3);
    }

    // SCENARIO 4 — Stress ramp: find the knee. Mix 70% clicks / 30% postbacks.
    // NOTE: the literal spec ramps in req/MIN (+50/min per 15s); against a local
    // instance that is far below any breaking point and would take ~hours to
    // surface a knee. We ramp in req/SEC so the test finds the real ceiling in a
    // bounded time. Each step runs 15s; stop when error rate >5% OR p99 >5000ms.
    const RAMP_START = 200, RAMP_STEP = 200, RAMP_MAX = 6000, STEP_MS = 15_000;
    let maxRate = RAMP_START, brokeAt = null;
    console.log('\n## SCENARIO 4 — Stress ramp (15s/step, +%d req/s, stop on err>5%% or p99>5000ms)'.replace('%d', RAMP_STEP));
    report.s4steps = [];
    for (let rate = RAMP_START; rate <= RAMP_MAX; rate += RAMP_STEP) {
      const pool = [];
      const { samples, dropped } = await runWindow(STEP_MS, [
        clickStream(rate * 0.7, pool),
        postbackStream(rate * 0.3, pool),
      ], { clickPool: pool });
      const s = summarize(samples);
      report.s4steps.push({ rate, ...s, dropped });
      const errRate = 1 - s.successRate;
      const errStr = Object.keys(s.errs).length ? '  [' + Object.entries(s.errs).map(([k, v]) => `${k}=${v}`).join(', ') + ']' : '';
      console.log(`   ${String(rate).padStart(4)} req/s → ok ${r2(s.successRate * 100)}%  p50=${r2(s.p50)} p95=${r2(s.p95)} p99=${r2(s.p99)} max=${r2(s.max)}  locks=${s.locks}  dropped=${dropped}  n=${s.total}${errStr}`);
      if (errRate > 0.05 || s.p99 > 5000) { brokeAt = { rate, errRate, p99: s.p99 }; break; }
      maxRate = rate;
    }
    report.s4 = { maxSustainedRate: maxRate, brokeAt };
    console.log(brokeAt
      ? `   → breaking point at ${brokeAt.rate} req/s (err ${r2(brokeAt.errRate * 100)}%, p99 ${r2(brokeAt.p99)}ms); last healthy = ${maxRate} req/s`
      : `   → no breaking point up to ${RAMP_MAX} req/s; last healthy = ${maxRate} req/s`);

    // SCENARIO 5 — Sustained at 80% of last-healthy max for 2 min; watch for locks
    {
      const rate = Math.max(1, Math.round(maxRate * 0.8));
      const pool = [];
      console.log(`\n## SCENARIO 5 — Sustained 80%% of max = ${rate} req/s for 120s`);
      const { samples, dropped } = await runWindow(120_000, [
        clickStream(rate * 0.7, pool),
        postbackStream(rate * 0.3, pool),
      ], { clickPool: pool });
      report.s5 = { rate, ...summarize(samples), dropped };
      printSummary(`SCENARIO 5 — Sustained (120s @ ${rate} req/s, 70/30)`, report.s5, ` — dropped=${dropped}`);
      console.log(`   SQLite lock errors over sustained run: ${report.s5.locks} ${report.s5.locks === 0 ? '✓' : '✗'}`);
    }

    // ---- capacity + business projections -------------------------------------
    const safeRate = report.s5.rate; // sustained safe req/s (mix of clicks+postbacks)
    const estimate = (label, conv, payout) => {
      // total req/s = clicks/s * (1 + conv)  → clicks/day at capacity, then PO/day
      const clicksPerSec = safeRate / (1 + conv);
      const clicksPerDay = clicksPerSec * 86_400;
      const convPerDay = clicksPerDay * conv;
      const poPerDay = convPerDay * payout;
      console.log(`   ${label}: ~${Math.round(clicksPerDay).toLocaleString()} clicks/day → ~${Math.round(convPerDay).toLocaleString()} conversions/day → ~$${Math.round(poPerDay).toLocaleString()}/day payout`);
      return { clicksPerDay, convPerDay, poPerDay };
    };
    console.log('\n========================= REPORT =========================');
    console.log(`Server sustained limit (safe):  ${safeRate} req/s  (last-healthy max ${report.s4.maxSustainedRate} req/s${brokeAt ? `, broke at ${brokeAt.rate}` : ', no break observed'})`);
    console.log('Max payout/day at sustained capacity (server-bound; assumes all-day saturation):');
    report.kafi = estimate('Kafi CPA   ($3.00 avg, 2% conv)', 0.02, 3.00);
    report.cpi  = estimate('CPI game   ($0.50 avg, 5% conv)', 0.05, 0.50);
    console.log('==========================================================');
  } catch (e) {
    console.error('\nLOAD TEST ERROR:', e.message);
    process.exitCode = 1;
  } finally {
    console.log('\nCleanup: deleting test advertiser + publishers…');
    try { await cleanup(ctx); console.log('Cleanup done.'); }
    catch (e) { console.error('Cleanup error (manual check may be needed):', e.message); }
  }
}

main();
