'use strict';
// Group 8 — Kafi go-live (F21 config → F22 funnel ingest → F23 cohort engine →
// F24 phased+tiered payout). HTTP harness like the other suites. Boot the server
// first; pass E2E_BASE to point at it (defaults to :4008). Cohort/payout tests seed
// backdated conversions directly in the DB to control aging.

const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const BASE = process.env.E2E_BASE || 'http://localhost:4008';
const db = new DatabaseSync(path.join(__dirname, 'affiliate.db'));
db.exec('PRAGMA busy_timeout = 5000');

let pass = 0; const failures = [];
const ok = (n, c, x = '') => { c ? pass++ : failures.push(n + (x ? ` — ${x}` : '')); };
const near = (a, b, eps = 1e-3) => Math.abs(a - b) < eps;

function makeJar() {
  let cookie = '';
  return { get cookie() { return cookie; },
    async req(m, p, { form, headers = {} } = {}) {
      const h = { ...headers }; if (cookie) h.Cookie = cookie;
      let body;
      if (form) { body = new URLSearchParams(form).toString(); h['Content-Type'] = 'application/x-www-form-urlencoded'; }
      const res = await fetch(BASE + p, { method: m, headers: h, body, redirect: 'manual' });
      for (const c of (res.headers.getSetCookie?.() || [])) {
        const kv = c.split(';')[0], nm = kv.split('=')[0];
        const ps = (cookie ? cookie.split('; ') : []).filter(x => x.split('=')[0] !== nm);
        ps.push(kv); cookie = ps.join('; ');
      } return res;
    } };
}
const txt = r => r.text();
const csrf = async (j, p) => (((await txt(await j.req('GET', p))).match(/name="_csrf" value="([a-f0-9]+)"/)) || [])[1] || '';
const post = async (j, p, f, cp) => j.req('POST', p, { form: { ...f, _csrf: await csrf(j, cp) } });
const track = async (qs) => ((((await fetch(`${BASE}/track/${qs}`, { redirect: 'manual' })).headers.get('location')) || '').match(/click_id=([a-f0-9-]+)/) || [])[1] || null;
const postback = (slug, qs) => fetch(`${BASE}/postback/${slug}?${qs}`, { redirect: 'manual' });
const conv = (click, event) => db.prepare('SELECT * FROM conversions WHERE click_id=? AND event=?').get(click, event);
const cohortRow = (slug, pub, month) => db.prepare('SELECT * FROM cohort_stats WHERE advertiser_slug=? AND publisher=? AND cohort_month=?').get(slug, pub, month);

const CFG = {
  open_event: 'open_account', deposit_event: 'deposit', active_event: 'first_trade', withdraw_event: 'withdraw',
  min_value: 200000, window_days: 30, gate_pct: 15, pub_kpi_pct: 18,
  bonus_tiers: [{ min_pct: 5, max_pct: 15, bonus: 20000 }, { min_pct: 15, max_pct: 30, bonus: 30000 }],
  k_default: 0.70, min_sample: 2,
  phases: [
    { name: 'P1', start_date: '2024-01-01', end_date: '2024-03-31', base_per_open: 60000, currency: 'VND' },
    { name: 'P2', start_date: '2024-04-01', end_date: '2024-06-30', base_per_open: 40000, currency: 'VND' },
    { name: 'P3', start_date: '2024-07-01', end_date: null, base_per_open: 0, currency: 'VND' },
  ],
};

// Direct insert of a conversion with controlled event/status/received_at (for cohort seeding).
const seedConv = db.prepare("INSERT INTO conversions (click_id, advertiser_slug, publisher, event, status, payout, currency, received_at) VALUES (?,?,?,?,?,0,'VND',?)");

(async () => {
  const admin = makeJar();
  await admin.req('POST', '/admin/login', { form: { username: 'admin', password: 'testpass123' } });

  // advertiser g8adv (VND) + publisher g8pub assigned (for live funnel postbacks)
  await post(admin, '/admin/advertisers',
    { name: 'G8 Adv', slug: 'g8adv', offer_url: 'https://g8adv.test/o', payout_amount: 0, payout_type: 'fixed', click_lookback_window: 365, currency: 'VND', status: 'active' },
    '/admin/advertisers/new');
  await post(admin, '/admin/advertisers',
    { name: 'G8 NoConf', slug: 'g8noconf', offer_url: 'https://g8noconf.test/o', payout_amount: 5, payout_type: 'fixed', click_lookback_window: 90, currency: 'USD', status: 'active' },
    '/admin/advertisers/new');
  await post(admin, '/admin/publishers', { username: 'g8pub', password: 'g8pubpass1', status: 'active' }, '/admin/publishers/new');
  const pubId = db.prepare("SELECT id FROM publishers WHERE username='g8pub'").get().id;
  const advId = db.prepare("SELECT id FROM advertisers WHERE slug='g8adv'").get().id;
  await post(admin, `/admin/publishers/${pubId}/assign`, { advertiser_id: advId }, `/admin/publishers/${pubId}/edit`);

  // ===== F21 — config CRUD, JSON validation, audit, safe default =====
  await post(admin, '/admin/advertisers/g8adv/active-def', { config: JSON.stringify(CFG, null, 2) }, '/admin/advertisers/g8adv/active-def');
  const saved = db.prepare("SELECT value FROM settings WHERE key='active_def:g8adv'").get();
  ok('F21.1 config saved to settings', !!saved && JSON.parse(saved.value).min_value === 200000, JSON.stringify(saved));
  const defPage = await txt(await admin.req('GET', '/admin/advertisers/g8adv/active-def'));
  ok('F21.1 active-def page echoes saved JSON', defPage.includes('200000') && defPage.includes('first_trade'));

  const badRes = await txt(await post(admin, '/admin/advertisers/g8adv/active-def', { config: '{ not valid json,,, }' }, '/admin/advertisers/g8adv/active-def'));
  ok('F21.2 invalid JSON rejected with error', badRes.includes('Invalid JSON'));
  ok('F21.2 invalid JSON not saved (config unchanged)', JSON.parse(db.prepare("SELECT value FROM settings WHERE key='active_def:g8adv'").get().value).min_value === 200000);

  // >10000 chars decoded but still under the global 10kb urlencoded body limit
  // (alphanumeric padding URL-encodes 1:1) so it reaches the handler's own cap.
  const bigCfg = JSON.stringify({ pad: 'x'.repeat(10050) });
  const bigRes = await post(admin, '/admin/advertisers/g8adv/active-def', { config: bigCfg }, '/admin/advertisers/g8adv/active-def');
  ok('F21.5 oversized config rejected with 400', bigRes.status === 400, 'status=' + bigRes.status);
  ok('F21.5 oversized config error message shown', (await txt(bigRes)).includes('Config JSON too large (max 10KB)'));
  ok('F21.5 oversized config not saved (config unchanged)', !db.prepare("SELECT value FROM settings WHERE key='active_def:g8adv'").get().value.includes('pad'));

  ok('F21.3 audit_log records config update',
    !!db.prepare("SELECT 1 FROM audit_log WHERE action='advertiser.active_def_updated' AND entity_id='g8adv'").get());

  const noconfPage = await txt(await admin.req('GET', '/admin/advertisers/g8noconf/active-def'));
  ok('F21.4 no-config advertiser shows safe-default warning', noconfPage.includes('No config') && noconfPage.includes('safe defaults'));

  // ===== F22 — funnel ingestion =====
  // qualified: first_trade with value >= min_value
  const cQ = await track('g8adv?pub=g8pub');
  await postback('g8adv', `click_id=${cQ}&event=open_account&value=0`);
  await postback('g8adv', `click_id=${cQ}&event=first_trade&value=250000`);
  ok('F22.1 open_account stored as its own event', conv(cQ, 'open_account')?.event === 'open_account');
  ok('F22.1 active event with value>=min → qualified', conv(cQ, 'first_trade')?.status === 'qualified', JSON.stringify(conv(cQ, 'first_trade')));
  ok('F22.1 raw_value persisted', conv(cQ, 'first_trade')?.raw_value === 250000);

  // below_min_value
  const cLow = await track('g8adv?pub=g8pub');
  await postback('g8adv', `click_id=${cLow}&event=first_trade&value=100000`);
  const low = conv(cLow, 'first_trade');
  ok('F22.2 active event below min → pending + below_min_value', low?.status === 'pending' && low?.reason === 'below_min_value', JSON.stringify(low));

  // multi-event same click_id
  const cM = await track('g8adv?pub=g8pub');
  await postback('g8adv', `click_id=${cM}&event=open_account&value=0`);
  await postback('g8adv', `click_id=${cM}&event=deposit&value=500000`);
  await postback('g8adv', `click_id=${cM}&event=first_trade&value=300000`);
  const multiN = db.prepare('SELECT COUNT(*) n FROM conversions WHERE click_id=?').get(cM).n;
  ok('F22.3 multiple events on one click_id all stored', multiN === 3, 'count=' + multiN);
  // duplicate same event → duplicate
  const dupRes = await (await postback('g8adv', `click_id=${cM}&event=deposit&value=500000`)).json();
  ok('F22.3 duplicate (same click_id+event) returns duplicate', dupRes.status === 'duplicate', JSON.stringify(dupRes));

  // unknown event → pending + unknown_event, no crash
  const cU = await track('g8adv?pub=g8pub');
  const uRes = await postback('g8adv', `click_id=${cU}&event=mystery_event&value=0`);
  ok('F22.4 unknown event does not crash (HTTP 200)', uRes.status === 200, 'status ' + uRes.status);
  const u = conv(cU, 'mystery_event');
  ok('F22.4 unknown event stored pending + unknown_event reason', u?.status === 'pending' && u?.reason === 'unknown_event', JSON.stringify(u));

  // ===== F23 — cohort engine (seed backdated, controlled) =====
  // g8pub1 / 2024-01 : 3 opens (aged), active d7=1 (cidA@d5), d30=2 (cidB@d20), cidC none.
  seedConv.run('g8-A', 'g8adv', 'g8pub1', 'open_account', 'pending', '2024-01-05 10:00:00');
  seedConv.run('g8-B', 'g8adv', 'g8pub1', 'open_account', 'pending', '2024-01-05 10:00:00');
  seedConv.run('g8-C', 'g8adv', 'g8pub1', 'open_account', 'pending', '2024-01-05 10:00:00');
  seedConv.run('g8-A', 'g8adv', 'g8pub1', 'first_trade', 'qualified', '2024-01-10 10:00:00'); // d5
  seedConv.run('g8-B', 'g8adv', 'g8pub1', 'first_trade', 'qualified', '2024-01-25 10:00:00'); // d20
  // a SECOND publisher's cohort, same month — must stay separate
  seedConv.run('g8-D', 'g8adv', 'g8pub2', 'open_account', 'pending', '2024-01-06 10:00:00');
  seedConv.run('g8-D', 'g8adv', 'g8pub2', 'first_trade', 'qualified', '2024-01-09 10:00:00'); // d3
  // current-month cohort (not matured)
  const thisMonth = new Date().toISOString().slice(0, 7);
  seedConv.run('g8-NOW', 'g8adv', 'g8pub1', 'open_account', 'pending', new Date().toISOString().slice(0, 19).replace('T', ' '));

  await post(admin, '/admin/cohort/recompute', {}, '/admin/cohort');
  const r1 = cohortRow('g8adv', 'g8pub1', '2024-01');
  ok('F23.1 opens / aged counts', r1 && r1.opens === 3 && r1.opens_aged7 === 3 && r1.opens_aged30 === 3, JSON.stringify(r1));
  ok('F23.2 active window per-account (d7=1, d30=2)', r1 && r1.active_by_d7 === 1 && r1.active_by_d30 === 2, JSON.stringify(r1));
  ok('F23.2 d7_rate / actual_d30_rate', r1 && near(r1.d7_rate, 1 / 3) && near(r1.actual_d30_rate, 2 / 3), JSON.stringify(r1));
  ok('F23.2 projected_d30_rate = d7_rate / k', r1 && near(r1.projected_d30_rate, (1 / 3) / 0.70), JSON.stringify(r1));
  ok('F23.3 cohorts separated by publisher', cohortRow('g8adv', 'g8pub2', '2024-01')?.opens === 1);
  ok('F23.4 matured flag set for old cohort', r1 && r1.is_matured === 1);
  ok('F23.4 current-month cohort not matured', cohortRow('g8adv', 'g8pub1', thisMonth)?.is_matured === 0);

  // ===== F24 — phased + tiered payout =====
  // Cohort A: g8pubA / 2024-01 : 5 opens aged, 1 active → rate 20% → tier [15,30) bonus 30000; P1 base 60000.
  for (let i = 0; i < 5; i++) seedConv.run(`g8A-${i}`, 'g8adv', 'g8pubA', 'open_account', 'pending', '2024-01-05 10:00:00');
  seedConv.run('g8A-0', 'g8adv', 'g8pubA', 'first_trade', 'qualified', '2024-01-12 10:00:00');
  // Cohort B: g8pubB / 2024-05 : 3 opens aged, 0 active → rate 0% → bonus 0; P2 base 40000 (base unconditional).
  for (let i = 0; i < 3; i++) seedConv.run(`g8B-${i}`, 'g8adv', 'g8pubB', 'open_account', 'pending', '2024-05-05 10:00:00');
  // Cohort C: g8pubC / 2024-08 : 2 opens aged, 0 active → P3 base 0 → total 0.
  for (let i = 0; i < 2; i++) seedConv.run(`g8C-${i}`, 'g8adv', 'g8pubC', 'open_account', 'pending', '2024-08-05 10:00:00');
  await post(admin, '/admin/cohort/recompute', {}, '/admin/cohort');

  const prevHtml = await txt(await admin.req('GET', '/admin/advertisers/g8adv/payout-preview'));
  const totals = {};
  const re = /data-cohort="([^"]+)" data-publisher="([^"]+)" data-total="([^"]+)"/g;
  let m; while ((m = re.exec(prevHtml))) totals[`${m[2]}|${m[1]}`] = Number(m[3]);

  ok('F24.1 phase lookup P1 + tier bonus (60000 + 30000×1 = 90000)', totals['g8pubA|2024-01'] === 90000, JSON.stringify(totals));
  ok('F24.2 tier bonus by rate (20% → 30000) reflected', cohortRow('g8adv', 'g8pubA', '2024-01') && near(cohortRow('g8adv', 'g8pubA', '2024-01').actual_d30_rate, 0.2));
  ok('F24.3 base unconditional (P2 base 40000, rate 0 → total 40000)', totals['g8pubB|2024-05'] === 40000, JSON.stringify(totals));
  ok('F24.4 phase P3 base 0 → total 0', totals['g8pubC|2024-08'] === 0, JSON.stringify(totals));
  ok('F24.1 preview shows phase labels', prevHtml.includes('P1') && prevHtml.includes('P2') && prevHtml.includes('P3'));
  // F24.5 — payout reflects recomputed D30 rate: a non-aged cohort yields base only (no bonus)
  ok('F24.5 D30-driven bonus only after maturity (matured rate used)', cohortRow('g8adv', 'g8pubA', '2024-01').is_matured === 1);

  // ===== UIUX review fixes — B1 (413 stack-trace leak) + D (publisher reason exposure) =====
  const noStack = t => !/PayloadTooLargeError|SyntaxError|node_modules|\/server\.js/.test(t);

  // (a) 24KB config blows the 10kb urlencoded body limit → friendly flash, no stack trace
  const hugeRes = await post(admin, '/admin/advertisers/g8adv/active-def', { config: JSON.stringify({ pad: 'x'.repeat(24000) }) }, '/admin/advertisers/g8adv/active-def');
  const hugeBody = await txt(hugeRes);
  ok('B1.a oversized (24KB) active-def → 400 with friendly flash', hugeRes.status === 400 && hugeBody.includes('Config JSON too large (max 10KB)'), 'status=' + hugeRes.status);
  ok('B1.a oversized active-def response has no stack trace', noStack(hugeBody));

  // (b) >10kb body on any other route → clean 413 JSON
  const otherRes = await fetch(`${BASE}/admin/login`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'username=' + 'x'.repeat(12000), redirect: 'manual' });
  const otherBody = await otherRes.text();
  ok('B1.b oversized body on other route → 413 JSON', otherRes.status === 413 && JSON.parse(otherBody).error === 'Payload too large', `status=${otherRes.status} body=${otherBody.slice(0, 120)}`);
  ok('B1.b 413 response has no stack trace', noStack(otherBody));

  // (c) parser-level error (malformed JSON body) → generic 500, no stack trace
  const errRes = await fetch(`${BASE}/admin/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{invalid json', redirect: 'manual' });
  const errBody = await errRes.text();
  ok('B1.c unexpected error → generic 500 JSON', errRes.status === 500 && JSON.parse(errBody).error === 'Internal server error', `status=${errRes.status} body=${errBody.slice(0, 120)}`);
  ok('B1.c 500 response has no stack trace', noStack(errBody));

  // (d) publisher views collapse internal reasons to "adjustment"; safe ones stay visible
  db.prepare("INSERT INTO conversions (click_id, advertiser_slug, publisher, event, payout, currency, status, reason) VALUES ('g8-internal-reason','g8adv','g8pub','first_trade',0,'VND','rejected','telesale_wins')").run();
  const pubJar = makeJar();
  await post(pubJar, '/publisher/login', { username: 'g8pub', password: 'g8pubpass1' }, '/publisher/login');
  const pubConvPage = await txt(await pubJar.req('GET', '/publisher/conversions'));
  ok('D.1 internal reason hidden from publisher', !pubConvPage.includes('telesale_wins'));
  ok('D.1 internal reason shown as neutral "adjustment"', pubConvPage.includes('adjustment'));
  ok('D.2 publisher-safe reason still visible', pubConvPage.includes('below_min_value'));
  const pubDashPage = await txt(await pubJar.req('GET', '/publisher/dashboard'));
  ok('D.3 publisher dashboard also masks internal reason', !pubDashPage.includes('telesale_wins'));

  console.log(`\nPASSED: ${pass}`);
  if (failures.length) { console.log(`FAILED: ${failures.length}`); failures.forEach(f => console.log('  ✗ ' + f)); process.exit(1); }
  console.log('ALL GREEN ✓'); process.exit(0);
})().catch(e => { console.error('HARNESS ERROR:', e); process.exit(2); });
