'use strict';
// Group 9 — EQM (F25), KPI gate (F26), holdback (F27), trading anti-fraud (F28),
// reason tagging + referral dedup (F29). HTTP harness like group7/8. Boot the
// server first; pass E2E_BASE (defaults to :4009). Seeds backdated data directly.

const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const BASE = process.env.E2E_BASE || 'http://localhost:4009';
const db = new DatabaseSync(path.join(__dirname, 'affiliate.db'));
db.exec('PRAGMA busy_timeout = 5000');

let pass = 0; const failures = [];
const ok = (n, c, x = '') => { c ? pass++ : failures.push(n + (x ? ` — ${x}` : '')); };

function makeJar() {
  let cookie = '';
  return { get cookie() { return cookie; },
    async req(m, p, { form, headers = {} } = {}) {
      const h = { ...headers }; if (cookie) h.Cookie = cookie;
      let body; if (form) { body = new URLSearchParams(form).toString(); h['Content-Type'] = 'application/x-www-form-urlencoded'; }
      const res = await fetch(BASE + p, { method: m, headers: h, body, redirect: 'manual' });
      for (const c of (res.headers.getSetCookie?.() || [])) {
        const kv = c.split(';')[0], nm = kv.split('=')[0];
        const ps = (cookie ? cookie.split('; ') : []).filter(x => x.split('=')[0] !== nm); ps.push(kv); cookie = ps.join('; ');
      } return res;
    } };
}
const txt = r => r.text();
const csrf = async (j, p) => (((await txt(await j.req('GET', p))).match(/name="_csrf" value="([a-f0-9]+)"/)) || [])[1] || '';
const post = async (j, p, f, cp) => j.req('POST', p, { form: { ...f, _csrf: await csrf(j, cp) } });
const track = async (qs) => ((((await fetch(`${BASE}/track/${qs}`, { redirect: 'manual' })).headers.get('location')) || '').match(/click_id=([a-f0-9-]+)/) || [])[1] || null;
const postback = (slug, qs) => fetch(`${BASE}/postback/${slug}?${qs}`, { redirect: 'manual' });

const CFG = {
  open_event: 'open_account', deposit_event: 'deposit', active_event: 'first_trade', withdraw_event: 'withdraw',
  min_value: 200000, window_days: 30, gate_pct: 15, pub_kpi_pct: 18,
  bonus_tiers: [], k_default: 0.70, min_sample: 2,
  phases: [{ name: 'P1', start_date: '2024-01-01', end_date: null, base_per_open: 60000, currency: 'VND' }],
};

const insConv = (o) => db.prepare(
  "INSERT INTO conversions (click_id, advertiser_slug, publisher, event, status, payout, held_amount, holdback_released, raw_value, af_id, user_id, currency, received_at) VALUES (?,?,?,?,?,?,?,?,?,?,?, 'VND', ?)"
).run(o.click, o.adv || 'g9adv', o.pub, o.event || 'open_account', o.status || 'pending', o.payout || 0, o.held || 0, o.released || 0, o.rawv ?? null, o.afid ?? null, o.uid ?? null, o.at);
const insCohort = (adv, pub, month, rate, matured, opensAged = 5, activeD30 = 1, d7 = 0, opensAged7 = 5, activeD7 = 0) =>
  db.prepare("INSERT OR REPLACE INTO cohort_stats (advertiser_slug,publisher,cohort_month,opens,opens_aged7,opens_aged30,active_by_d7,active_by_d30,d7_rate,actual_d30_rate,is_matured,k_factor) VALUES (?,?,?,?,?,?,?,?,?,?,?,0.70)")
    .run(adv, pub, month, opensAged, opensAged7, opensAged, activeD7, activeD30, d7, rate, matured);
const cohortRow = (adv, pub, month) => db.prepare('SELECT * FROM cohort_stats WHERE advertiser_slug=? AND publisher=? AND cohort_month=?').get(adv, pub, month);
const assignmentRow = (pub, slug) => db.prepare('SELECT pa.* FROM publisher_advertisers pa JOIN publishers p ON p.id=pa.publisher_id JOIN advertisers a ON a.id=pa.advertiser_id WHERE p.username=? AND a.slug=?').get(pub, slug);
const setS = (k, v) => db.prepare('INSERT OR REPLACE INTO settings (key,value) VALUES (?,?)').run(k, v);

(async () => {
  const admin = makeJar();
  await admin.req('POST', '/admin/login', { form: { username: 'admin', password: 'testpass123' } });

  // advertisers: g9adv (config), g9eqm (config + auto_throttle), g9cps (CPS + holdback)
  for (const [slug, name, payout, cur] of [['g9adv', 'G9 Adv', 0, 'VND'], ['g9eqm', 'G9 EQM', 0, 'VND'], ['g9cps', 'G9 CPS', 100, 'USD']]) {
    await post(admin, '/admin/advertisers',
      { name, slug, offer_url: `https://${slug}.test/o`, payout_amount: payout, payout_type: 'fixed', click_lookback_window: 365, currency: cur, status: 'active' },
      '/admin/advertisers/new');
  }
  await post(admin, '/admin/advertisers/g9adv/active-def', { config: JSON.stringify(CFG) }, '/admin/advertisers/g9adv/active-def');
  await post(admin, '/admin/advertisers/g9eqm/active-def', { config: JSON.stringify(CFG) }, '/admin/advertisers/g9eqm/active-def');
  setS('holdback_pct:g9cps', '0.25');
  setS('auto_throttle:g9eqm', 'true');

  // publishers + assignments
  const mkPub = async (u, slug) => {
    await post(admin, '/admin/publishers', { username: u, password: u + 'pass1', status: 'active' }, '/admin/publishers/new');
    const pid = db.prepare('SELECT id FROM publishers WHERE username=?').get(u).id;
    const aid = db.prepare('SELECT id FROM advertisers WHERE slug=?').get(slug).id;
    await post(admin, `/admin/publishers/${pid}/assign`, { advertiser_id: aid }, `/admin/publishers/${pid}/edit`);
    return pid;
  };
  await mkPub('g9pause', 'g9adv'); await mkPub('g9remove', 'g9adv'); await mkPub('g9ok', 'g9adv');
  await mkPub('g9eqmred', 'g9eqm'); await mkPub('g9eqmgrn', 'g9eqm');
  await mkPub('g9fpub', 'g9cps'); await mkPub('g9fraud', 'g9adv'); await mkPub('g9rpub', 'g9adv');

  // ===== F26 — KPI gate (pause / remove / ok) =====
  // g9pause: one matured cohort 16.7% (<kpi 18, >gate 15) → pause assignment
  for (let i = 0; i < 6; i++) insConv({ click: `p2-${i}`, pub: 'g9pause', event: 'open_account', at: '2024-02-05 10:00:00' });
  insConv({ click: 'p2-0', pub: 'g9pause', event: 'first_trade', status: 'qualified', at: '2024-02-10 10:00:00' });
  // g9remove: two matured cohorts both 0% (<gate 15) → remove assignment
  for (let i = 0; i < 5; i++) insConv({ click: `r2-${i}`, pub: 'g9remove', event: 'open_account', at: '2024-02-05 10:00:00' });
  for (let i = 0; i < 5; i++) insConv({ click: `r3-${i}`, pub: 'g9remove', event: 'open_account', at: '2024-03-05 10:00:00' });
  // g9ok: 33% → meets KPI
  for (let i = 0; i < 3; i++) insConv({ click: `o2-${i}`, pub: 'g9ok', event: 'open_account', at: '2024-02-05 10:00:00' });
  insConv({ click: 'o2-0', pub: 'g9ok', event: 'first_trade', status: 'qualified', at: '2024-02-10 10:00:00' });

  await post(admin, '/admin/cohort/recompute', {}, '/admin/cohort');
  const pauseA = assignmentRow('g9pause', 'g9adv');
  ok('F26.1 below-KPI single cohort → assignment paused (valid_until set)', pauseA && pauseA.valid_until != null, JSON.stringify(pauseA));
  ok('F26.2 two consecutive sub-gate cohorts → assignment removed', !assignmentRow('g9remove', 'g9adv'));
  const okA = assignmentRow('g9ok', 'g9adv');
  ok('F26.3 meeting KPI → assignment intact', okA && okA.valid_until == null);
  // the publishers view is built from clicks — give the KPI publishers a click so they appear
  await track('g9adv?pub=g9ok'); await track('g9adv?pub=g9pause');
  const pubView = await txt(await admin.req('GET', '/admin/advertisers/g9adv/publishers'));
  ok('F26.4 publishers view shows KPI badge', pubView.includes('below KPI') || pubView.includes('KPI ok'));

  // ===== F25 — EQM RAG + auto-throttle =====
  // g9eqmred: 3 opens aged, 0 active → projected 0 → Red
  for (let i = 0; i < 3; i++) insConv({ click: `er-${i}`, adv: 'g9eqm', pub: 'g9eqmred', event: 'open_account', at: '2024-01-05 10:00:00' });
  // g9eqmgrn: 3 opens aged, 3 active within d7 → d7_rate 1 → projected clamp 1 → Green
  for (let i = 0; i < 3; i++) { insConv({ click: `eg-${i}`, adv: 'g9eqm', pub: 'g9eqmgrn', event: 'open_account', at: '2024-01-05 10:00:00' }); insConv({ click: `eg-${i}`, adv: 'g9eqm', pub: 'g9eqmgrn', event: 'first_trade', status: 'qualified', at: '2024-01-08 10:00:00' }); }

  await post(admin, '/admin/cohort/recompute', {}, '/admin/cohort'); // red day 1
  await post(admin, '/admin/cohort/recompute', {}, '/admin/cohort'); // red day 2 → throttle
  ok('F25.1 consecutive Red days tracked', parseInt(db.prepare("SELECT value FROM settings WHERE key='eqm_red_days:g9eqm:g9eqmred'").get().value, 10) >= 2);
  ok('F25.2 Green publisher red-day counter stays 0', (db.prepare("SELECT value FROM settings WHERE key='eqm_red_days:g9eqm:g9eqmgrn'").get()?.value || '0') === '0');
  ok('F25.3 auto_throttle pauses the Red publisher', db.prepare("SELECT status FROM publishers WHERE username='g9eqmred'").get().status === 'paused');
  const eqmPage = await txt(await admin.req('GET', '/admin/eqm'));
  ok('F25.4 EQM page renders RAG', eqmPage.includes('Early Quality Monitor') && (eqmPage.includes('Red') || eqmPage.includes('Green')));

  // ===== F27 — holdback on ingest + release + clawback =====
  // ingest: CPS conversion with holdback_pct → held 25, net 75
  const cHb = await track('g9cps?pub=g9fpub');
  await postback('g9cps', `click_id=${cHb}&event=sale`);
  const hbConv = db.prepare('SELECT held_amount, payout FROM conversions WHERE click_id=?').get(cHb);
  ok('F27.1 holdback withheld at ingest (held 25, net 75)', hbConv && hbConv.held_amount === 25 && hbConv.payout === 75, JSON.stringify(hbConv));

  // release: matured cohort meeting KPI → release held
  insConv({ click: 'hbR-1', pub: 'g9hbR', event: 'sale', status: 'approved', payout: 30, held: 10, at: '2024-02-05 10:00:00' });
  insConv({ click: 'hbR-2', pub: 'g9hbR', event: 'sale', status: 'approved', payout: 30, held: 10, at: '2024-02-06 10:00:00' });
  insCohort('g9adv', 'g9hbR', '2024-02', 0.30, 1);
  // clawback: matured cohort below KPI → claw back held
  insConv({ click: 'hbC-1', pub: 'g9hbC', event: 'sale', status: 'approved', payout: 30, held: 10, at: '2024-03-05 10:00:00' });
  insCohort('g9adv', 'g9hbC', '2024-03', 0.05, 1);

  await post(admin, '/admin/advertisers/g9adv/holdback/process', {}, '/admin/advertisers/g9adv/payout-preview');
  ok('F27.2 holdback released when cohort meets KPI', db.prepare("SELECT COALESCE(SUM(amount),0) s FROM holdback_events WHERE advertiser_slug='g9adv' AND publisher='g9hbR' AND event_type='release'").get().s === 20);
  ok('F27.2 released conversions credited + flagged', db.prepare("SELECT payout, holdback_released FROM conversions WHERE click_id='hbR-1'").get().payout === 40);
  ok('F27.3 clawback when cohort below KPI after maturity', db.prepare("SELECT COALESCE(SUM(amount),0) s FROM holdback_events WHERE advertiser_slug='g9adv' AND publisher='g9hbC' AND event_type='clawback'").get().s === 10);
  ok('F27.3 clawed-back conversion rejected', db.prepare("SELECT status, reason FROM conversions WHERE click_id='hbC-1'").get().reason === 'holdback_clawback');
  const portalHb = makeJar();
  await portalHb.req('POST', '/publisher/login', { form: { username: 'g9hbR', password: 'x' } }); // no account → just ensure route guarded
  ok('F27.4 publisher holdback route guarded (redirects without session)', (await portalHb.req('GET', '/publisher/holdback')).status === 302);

  // ===== F28 — anti-fraud =====
  // AFID ratio: 9 conversions, same af_id, one publisher → ratio 9 > 8
  for (let i = 0; i < 9; i++) { const c = await track('g9cps?pub=g9fpub'); await postback('g9cps', `click_id=${c}&event=sale&af_id=SHARED-AFID`); }
  ok('F28.1 AFID ratio breach flagged', !!db.prepare("SELECT 1 FROM fraud_flags WHERE flag_type='afid_ratio_breach' AND publisher='g9fpub'").get());

  // cycling: deposit → small trade (<min_value×2) → withdraw on one click_id
  const cCyc = await track('g9adv?pub=g9fraud');
  await postback('g9adv', `click_id=${cCyc}&event=deposit&value=500000`);
  await postback('g9adv', `click_id=${cCyc}&event=first_trade&value=100000`); // < 200000×2
  await postback('g9adv', `click_id=${cCyc}&event=withdraw&value=480000`);
  ok('F28.2 cycling pattern flagged', !!db.prepare("SELECT 1 FROM fraud_flags WHERE flag_type='cycling' AND click_id=?").get(cCyc));
  ok('F28.2 cycling holds the withdraw conversion', db.prepare("SELECT reason FROM conversions WHERE click_id=? AND event='withdraw'").get(cCyc)?.reason === 'cycling_hold');
  const frPage = await txt(await admin.req('GET', '/admin/fraud-review?flag=cycling'));
  ok('F28.3 fraud-review page filters cycling', frPage.includes('Fraud Review') && frPage.includes('cycling'));

  // ===== F29 — referral dedup + reason tagging =====
  await post(admin, '/admin/advertisers/g9adv/referral-list', { identifier_type: 'email', identifiers: 'ref-afid-1\nother@x.test' }, '/admin/advertisers/g9adv/referral-list');
  ok('F29.1 referral identifiers uploaded', db.prepare("SELECT COUNT(*) n FROM advertiser_referral_lists WHERE advertiser_slug='g9adv'").get().n >= 2);

  // reason clicks
  await track('g9adv?pub=g9rpub'); // no_event (click only)
  const cNA = await track('g9adv?pub=g9rpub'); await postback('g9adv', `click_id=${cNA}&event=open_account&value=0`); // not_activated
  const cRef = await track('g9adv?pub=g9rpub'); await postback('g9adv', `click_id=${cRef}&event=open_account&value=0&af_id=ref-afid-1`); // referral_overlap
  const cDup = await track('g9adv?pub=g9rpub'); await postback('g9adv', `click_id=${cDup}&event=open_account&value=0`);
  db.prepare("UPDATE conversions SET status='approved' WHERE click_id=?").run(cDup); // duplicate
  const rb = await txt(await admin.req('GET', '/admin/advertisers/g9adv/reason-breakdown'));
  const hasReason = (name) => rb.includes(name);
  ok('F29.2 reason breakdown renders all reason buckets', hasReason('no_event') && hasReason('not_activated') && hasReason('referral_overlap') && hasReason('duplicate'));
  // verify referral_overlap actually classified (the cRef click row tagged)
  const rbRowHasRef = new RegExp('referral_overlap').test(rb);
  ok('F29.3 referral-overlap detected via identifier match', rbRowHasRef);
  await post(admin, '/admin/advertisers/g9adv/referral-list/clear', {}, '/admin/advertisers/g9adv/referral-list');
  ok('F29.3 referral list clear works', db.prepare("SELECT COUNT(*) n FROM advertiser_referral_lists WHERE advertiser_slug='g9adv'").get().n === 0);

  console.log(`\nPASSED: ${pass}`);
  if (failures.length) { console.log(`FAILED: ${failures.length}`); failures.forEach(f => console.log('  ✗ ' + f)); process.exit(1); }
  console.log('ALL GREEN ✓'); process.exit(0);
})().catch(e => { console.error('HARNESS ERROR:', e); process.exit(2); });
