'use strict';
// Group 10 — pacing/margin (F30), attribution rules (F31), Adjust S2S (F32),
// custom domains (F33), multi-currency FX (F34). HTTP harness like group8/9.

const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const BASE = process.env.E2E_BASE || 'http://localhost:4010';
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
const convOf = (click, event) => db.prepare('SELECT * FROM conversions WHERE click_id=? AND event=?').get(click, event);
const insConv = (o) => db.prepare("INSERT INTO conversions (click_id, advertiser_slug, publisher, event, status, payout, revenue, currency, received_at) VALUES (?,?,?,?,?,?,?,?,?)")
  .run(o.click, o.adv, o.pub, o.event || 'open_account', o.status || 'pending', o.payout || 0, o.revenue ?? null, o.cur || 'VND', o.at);

const CFG = {
  open_event: 'open_account', deposit_event: 'deposit', active_event: 'first_trade', withdraw_event: 'withdraw',
  min_value: 200000, window_days: 30, gate_pct: 15, pub_kpi_pct: 18, bonus_tiers: [], k_default: 0.70, min_sample: 2,
  phases: [{ name: 'P1', start_date: '2024-01-01', end_date: '2024-06-30', base_per_open: 60000, currency: 'VND' }],
};

(async () => {
  const admin = makeJar();
  await admin.req('POST', '/admin/login', { form: { username: 'admin', password: 'testpass123' } });

  for (const [slug, name, payout, cur] of [['g10adv', 'G10 Adv', 0, 'VND'], ['g10cps', 'G10 CPS', 100, 'USD'], ['g10fx', 'G10 FX', 100, 'VND']]) {
    await post(admin, '/admin/advertisers', { name, slug, offer_url: `https://${slug}.test/o`, payout_amount: payout, payout_type: 'fixed', click_lookback_window: 365, currency: cur, status: 'active' }, '/admin/advertisers/new');
  }
  await post(admin, '/admin/advertisers/g10adv/active-def', { config: JSON.stringify(CFG) }, '/admin/advertisers/g10adv/active-def');
  const mkPub = async (u, slug) => {
    await post(admin, '/admin/publishers', { username: u, password: u + 'pass1', status: 'active' }, '/admin/publishers/new');
    const pid = db.prepare('SELECT id FROM publishers WHERE username=?').get(u).id;
    const aid = db.prepare('SELECT id FROM advertisers WHERE slug=?').get(slug).id;
    await post(admin, `/admin/publishers/${pid}/assign`, { advertiser_id: aid }, `/admin/publishers/${pid}/edit`);
    return pid;
  };
  await mkPub('g10pub', 'g10adv'); await mkPub('g10cpsp', 'g10cps'); await mkPub('g10fxp', 'g10fx');

  // ===== F30 — pacing / margin =====
  await post(admin, '/admin/advertisers/g10adv/quota', { quota_P1: 10 }, '/admin/advertisers/g10adv/quota');
  ok('F30.1 quota saved to settings', db.prepare("SELECT value FROM settings WHERE key='quota:g10adv:P1'").get().value === '10');
  for (let i = 0; i < 4; i++) insConv({ click: `pace-${i}`, adv: 'g10adv', pub: 'g10pub', event: 'open_account', at: '2024-02-10 10:00:00' });
  insConv({ click: 'pace-rev', adv: 'g10adv', pub: 'g10pub', event: 'sale', status: 'approved', payout: 100, revenue: 150, at: '2024-02-10 10:00:00' });
  const pacing = await txt(await admin.req('GET', '/admin/pacing'));
  const sec = (pacing.match(/data-advertiser="g10adv"[^>]*data-margin="([^"]+)"[^>]*data-revenue="([^"]+)"[^>]*data-payout="([^"]+)"/) || []);
  ok('F30.2 margin = revenue − payout (150 − 100 = 50)', Number(sec[1]) === 50, JSON.stringify(sec));
  const ph = (pacing.match(/data-phase="P1" data-opens="([^"]+)" data-quota="([^"]+)"/) || []);
  ok('F30.3 phase pacing actual/quota (4 opens / quota 10)', Number(ph[1]) === 4 && Number(ph[2]) === 10, JSON.stringify(ph));
  ok('F30.4 pacing page shows blended D30 vs gate', pacing.includes('blended D30') && pacing.includes('vs gate'));

  // ===== F31 — attribution rules =====
  await post(admin, '/admin/advertisers/g10adv/attribution', { rule_type: 'telesale_wins', window_days: 7 }, '/admin/advertisers/g10adv/attribution');
  ok('F31.1 attribution rule saved', db.prepare("SELECT rule_type FROM attribution_rules WHERE advertiser_slug='g10adv' ORDER BY id DESC LIMIT 1").get().rule_type === 'telesale_wins');
  ok('F31.1 rule change audited', !!db.prepare("SELECT 1 FROM audit_log WHERE action='advertiser.attribution_rule_set' AND entity_id='g10adv'").get());
  const cTel = await track('g10adv?pub=g10pub');
  await postback('g10adv', `click_id=${cTel}&event=open_account&value=0&source=telesale`);
  ok('F31.2 telesale_wins rejects telesale-sourced conversion', convOf(cTel, 'open_account')?.status === 'rejected' && convOf(cTel, 'open_account')?.reason === 'telesale_wins', JSON.stringify(convOf(cTel, 'open_account')));
  const cKom = await track('g10adv?pub=g10pub');
  await postback('g10adv', `click_id=${cKom}&event=open_account&value=0`);
  ok('F31.2 non-telesale conversion unaffected', convOf(cKom, 'open_account')?.status !== 'rejected');
  // split on a CPS advertiser
  await post(admin, '/admin/advertisers/g10cps/attribution', { rule_type: 'split', window_days: 7 }, '/admin/advertisers/g10cps/attribution');
  const cSplit = await track('g10cps?pub=g10cpsp');
  await postback('g10cps', `click_id=${cSplit}&event=sale`);
  ok('F31.3 split halves payout (100 → 50)', convOf(cSplit, 'sale')?.payout === 50, JSON.stringify(convOf(cSplit, 'sale')));

  // ===== F32 — Adjust S2S =====
  db.prepare("UPDATE advertisers SET mmp_type='adjust' WHERE slug='g10adv'").run();
  const mmpPage = await txt(await admin.req('GET', '/admin/advertisers/g10adv/mmp'));
  ok('F32.1 MMP page shows Adjust setup', mmpPage.includes('Adjust') && mmpPage.includes('/postback/g10adv'));
  const mmpTest = await post(admin, '/admin/advertisers/g10adv/mmp/test', {}, '/admin/advertisers/g10adv/mmp');
  ok('F32.2 Adjust test connection ok', mmpTest.status === 302 && (mmpTest.headers.get('location') || '').includes('ok=1'), mmpTest.headers.get('location'));
  const cAdj = await track('g10adv?pub=g10pub');
  await postback('g10adv', `click_id=${cAdj}&event=first_trade&value=250000`);
  ok('F32.3 Adjust postback maps event via config (first_trade → qualified)', convOf(cAdj, 'first_trade')?.status === 'qualified');

  // ===== F33 — custom domain branded links =====
  db.prepare("UPDATE publishers SET custom_domain='go.g10.test' WHERE username='g10pub'").run();
  const pj = makeJar();
  await pj.req('POST', '/publisher/login', { form: { username: 'g10pub', password: 'g10pubpass1' } });
  const lg = await txt(await pj.req('GET', '/publisher/link-generator'));
  ok('F33.1 link generator renders under the custom domain', lg.includes('go.g10.test'), '');
  // a publisher without a custom domain falls back to the platform default
  const pj2 = makeJar();
  await pj2.req('POST', '/publisher/login', { form: { username: 'g10cpsp', password: 'g10cpsppass1' } });
  const lg2 = await txt(await pj2.req('GET', '/publisher/link-generator'));
  ok('F33.2 no custom domain → platform default base', !lg2.includes('go.g10.test'));

  // ===== F34 — multi-currency FX =====
  await post(admin, '/admin/fx-rates', { from_currency: 'VND', to_currency: 'USD', rate: 0.00004, reconciliation_period: '2024-02' }, '/admin/fx-rates');
  await post(admin, '/admin/fx-rates', { from_currency: 'VND', to_currency: 'USD', rate: 0.00005 }, '/admin/fx-rates');
  const locked = db.prepare("SELECT rate FROM fx_rates WHERE from_currency='VND' AND to_currency='USD' AND reconciliation_period='2024-02'").get();
  const current = db.prepare("SELECT rate FROM fx_rates WHERE from_currency='VND' AND to_currency='USD' AND reconciliation_period IS NULL").get();
  ok('F34.1 FX rate locked for a reconciliation period', locked && locked.rate === 0.00004, JSON.stringify(locked));
  ok('F34.1 separate current (unlocked) rate stored', current && current.rate === 0.00005);
  const fxPage = await txt(await admin.req('GET', '/admin/fx-rates'));
  ok('F34.2 FX page shows locked vs current', fxPage.includes('locked 2024-02') && fxPage.includes('current'));
  // conversion preserves original currency + amount
  const cFx = await track('g10fx?pub=g10fxp');
  await postback('g10fx', `click_id=${cFx}&event=sale`);
  const fxConv = convOf(cFx, 'sale');
  ok('F34.3 conversion stores original currency + amount (VND 100)', fxConv && fxConv.original_currency === 'VND' && fxConv.original_amount === 100, JSON.stringify(fxConv));

  console.log(`\nPASSED: ${pass}`);
  if (failures.length) { console.log(`FAILED: ${failures.length}`); failures.forEach(f => console.log('  ✗ ' + f)); process.exit(1); }
  console.log('ALL GREEN ✓'); process.exit(0);
})().catch(e => { console.error('HARNESS ERROR:', e); process.exit(2); });
