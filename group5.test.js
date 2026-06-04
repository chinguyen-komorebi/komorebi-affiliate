'use strict';
// Group 5 — multi-currency, white-label, traffic AI, multi-touch attribution.
// Drives the running server over HTTP (boot like the other suites on :3999).
// 1 multi-currency  2 exchange-rate update  3 white-label via Host  4 AI distribution
// 5 multi-touch linear split  6 attribution model switch (last vs first click)

const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const BASE = process.env.E2E_BASE || 'http://localhost:3999';
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
const near = (a, b, eps = 1e-4) => Math.abs(a - b) < eps;

(async () => {
  const admin = makeJar();
  await admin.req('POST', '/admin/login', { form: { username: 'admin', password: 'testpass123' } });
  // advertisers: g5a/g5b (USD, for AI), g5vnd (VND)
  for (const [slug, name, cur] of [['g5a', 'G5 A', 'USD'], ['g5b', 'G5 B', 'USD'], ['g5vnd', 'G5 VND', 'VND']]) {
    await post(admin, '/admin/advertisers',
      { name, slug, offer_url: `https://${slug}.test/o`, payout_amount: 10, payout_type: 'fixed', click_lookback_window: 90, currency: cur, status: 'active' },
      '/admin/advertisers/new');
  }
  await post(admin, '/admin/publishers', { username: 'g5p', password: 'g5ppass12', status: 'active' }, '/admin/publishers/new');
  const pubId = db.prepare("SELECT id FROM publishers WHERE username='g5p'").get().id;
  for (const s of ['g5a', 'g5b', 'g5vnd']) {
    const aid = db.prepare('SELECT id FROM advertisers WHERE slug=?').get(s).id;
    await post(admin, `/admin/publishers/${pubId}/assign`, { advertiser_id: aid }, `/admin/publishers/${pubId}/edit`);
  }

  // ===== (1) multi-currency =====
  const cV = await track('g5vnd?pub=g5p');
  const rV = await (await postback('g5vnd', `click_id=${cV}&event=sale`)).json();
  const convV = db.prepare('SELECT currency, payout, payout_local, payout_usd FROM conversions WHERE click_id=?').get(cV);
  ok('(1) VND conversion stored in advertiser currency', convV.currency === 'VND' && convV.payout_local === 10, JSON.stringify(convV));
  ok('(1) payout_usd = local × rate (10 × 0.000040)', near(convV.payout_usd, 10 * 0.000040), JSON.stringify(convV));
  ok('(1) payout column stays local (additive)', convV.payout === 10 && rV.payout === 10);

  // ===== (2) exchange-rate update via admin =====
  await post(admin, '/admin/exchange-rates', { base: 'VND', rate: 0.00005 }, '/admin/exchange-rates');
  ok('(2) admin updated the VND rate', db.prepare("SELECT rate FROM exchange_rates WHERE base='VND'").get().rate === 0.00005);
  const cV2 = await track('g5vnd?pub=g5p');
  await postback('g5vnd', `click_id=${cV2}&event=sale`);
  ok('(2) new conversion uses the updated rate', near(db.prepare('SELECT payout_usd FROM conversions WHERE click_id=?').get(cV2).payout_usd, 10 * 0.00005));

  // ===== (3) white-label via Host header =====
  await post(admin, '/admin/advertisers/g5a/branding',
    { company_name: 'Acme Partners', primary_color: '#ff0000', custom_domain: 'portal.g5acme.com' }, '/admin/advertisers/g5a/branding');
  const branded = await txt(await fetch(`${BASE}/publisher/login`, { headers: { 'X-Forwarded-Host': 'portal.g5acme.com' }, redirect: 'manual' }));
  ok('(3) custom domain → branding company injected', branded.includes('name="x-brand-company" content="Acme Partners"'), branded.slice(0, 0));
  ok('(3) custom domain → primary color CSS var injected', branded.includes('--brand-primary:#ff0000'));
  const plain = await txt(await fetch(`${BASE}/publisher/login`, { redirect: 'manual' }));
  ok('(3) no custom domain → no branding', !plain.includes('x-brand-company'));

  // ===== (4) smart-link AI distribution by performance =====
  await post(admin, '/admin/smart-links', { name: 'G5 SL', slug: 'g5sl' }, '/admin/smart-links/new');
  const slId = db.prepare("SELECT id FROM smart_links WHERE slug='g5sl'").get().id;
  await post(admin, `/admin/smart-links/${slId}/rules`, { advertiser_slug: 'g5a', priority: 0 }, `/admin/smart-links/${slId}`);
  await post(admin, `/admin/smart-links/${slId}/rules`, { advertiser_slug: 'g5b', priority: 1 }, `/admin/smart-links/${slId}`);
  // seed stats past the exploration phase: g5a EPC 5, g5b EPC 0.1
  db.prepare('INSERT OR REPLACE INTO smart_link_stats (smart_link_id, advertiser_slug, clicks, conversions, revenue) VALUES (?,?,?,?,?)').run(slId, 'g5a', 20, 10, 100);
  db.prepare('INSERT OR REPLACE INTO smart_link_stats (smart_link_id, advertiser_slug, clicks, conversions, revenue) VALUES (?,?,?,?,?)').run(slId, 'g5b', 20, 1, 2);
  await post(admin, `/admin/smart-links/${slId}/toggle-ai`, {}, `/admin/smart-links/${slId}`);
  ok('(4) AI mode enabled', db.prepare("SELECT ai_mode FROM smart_links WHERE slug='g5sl'").get().ai_mode === 1);
  let toA = 0, toB = 0;
  for (let i = 0; i < 30; i++) {
    const loc = (await fetch(`${BASE}/smart/g5sl?pub=g5p`, { redirect: 'manual' })).headers.get('location') || '';
    if (loc.startsWith('https://g5a.test')) toA++; else if (loc.startsWith('https://g5b.test')) toB++;
  }
  ok('(4) traffic skews to the higher performer (g5a > g5b)', toA > toB, `g5a=${toA} g5b=${toB}`);

  // ===== (5) multi-touch: 3 touchpoints (same user) → linear splits credit =====
  const u = 'JOURNEY-LIN';
  let lastClick;
  for (let i = 0; i < 3; i++) lastClick = await track(`g5a?pub=g5p&user_id=${u}`);
  await postback('g5a', `click_id=${lastClick}&event=sale&user_id=${u}&attribution_model=linear`);
  const convL = db.prepare("SELECT id, attribution_model FROM conversions WHERE click_id=?").get(lastClick);
  const tps = db.prepare('SELECT position, credit FROM attribution_touchpoints WHERE conversion_id=? ORDER BY position').all(convL.id);
  ok('(5) all 3 touchpoints linked to the conversion', tps.length === 3, JSON.stringify(tps));
  ok('(5) linear model splits credit equally (~0.333 each)', tps.every(t => near(t.credit, 1 / 3)), JSON.stringify(tps));
  ok('(5) conversion records the model', convL.attribution_model === 'linear');

  // ===== (6) attribution model switch: last_click vs first_click =====
  const uLC = 'J-LAST';
  let lc; for (let i = 0; i < 2; i++) lc = await track(`g5a?pub=g5p&user_id=${uLC}`);
  await postback('g5a', `click_id=${lc}&event=sale&user_id=${uLC}&attribution_model=last_click`);
  const lcId = db.prepare('SELECT id FROM conversions WHERE click_id=?').get(lc).id;
  const lcTp = db.prepare('SELECT position, credit FROM attribution_touchpoints WHERE conversion_id=? ORDER BY position').all(lcId);
  ok('(6) last_click → credit on last touchpoint only', lcTp.length === 2 && lcTp[0].credit === 0 && lcTp[1].credit === 1, JSON.stringify(lcTp));

  const uFC = 'J-FIRST';
  let fc; for (let i = 0; i < 2; i++) fc = await track(`g5a?pub=g5p&user_id=${uFC}`);
  await postback('g5a', `click_id=${fc}&event=sale&user_id=${uFC}&attribution_model=first_click`);
  const fcId = db.prepare('SELECT id FROM conversions WHERE click_id=?').get(fc).id;
  const fcTp = db.prepare('SELECT position, credit FROM attribution_touchpoints WHERE conversion_id=? ORDER BY position').all(fcId);
  ok('(6) first_click → credit on first touchpoint only', fcTp.length === 2 && fcTp[0].credit === 1 && fcTp[1].credit === 0, JSON.stringify(fcTp));

  console.log(`\nPASSED: ${pass}`);
  if (failures.length) { console.log(`FAILED: ${failures.length}`); failures.forEach(f => console.log('  ✗ ' + f)); process.exit(1); }
  console.log('ALL GREEN ✓'); process.exit(0);
})().catch(e => { console.error('HARNESS ERROR:', e); process.exit(2); });
