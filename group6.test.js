'use strict';
// Group 6 — Operational & Campaign Management. Drives the running server over HTTP
// (boot like the other suites on :3999, admin pass testpass123).
//   1 campaign CRUD + tracking attributes campaign_id + campaign payout
//   2 campaign monthly cap → 429 + auto-pause
//   3 publisher↔campaign mapping views
//   4 bulk approve (3 conversions in one request)
//   5 publisher tracking-link generator page renders

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
    async req(m, p, { form, json, headers = {} } = {}) {
      const h = { ...headers }; if (cookie) h.Cookie = cookie;
      let body;
      if (form) { body = new URLSearchParams(form).toString(); h['Content-Type'] = 'application/x-www-form-urlencoded'; }
      else if (json) { body = JSON.stringify(json); h['Content-Type'] = 'application/json'; }
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
const campId = (slug, name) => (db.prepare('SELECT id FROM campaigns WHERE advertiser_slug=? AND name=? ORDER BY id DESC').get(slug, name) || {}).id;

(async () => {
  const admin = makeJar();
  await admin.req('POST', '/admin/login', { form: { username: 'admin', password: 'testpass123' } });

  // advertiser g6a (default payout 5) + publisher g6p, assigned.
  await post(admin, '/admin/advertisers',
    { name: 'G6 A', slug: 'g6a', offer_url: 'https://g6a.test/o', payout_amount: 5, payout_type: 'fixed', click_lookback_window: 90, currency: 'USD', status: 'active' },
    '/admin/advertisers/new');
  await post(admin, '/admin/publishers', { username: 'g6p', password: 'g6ppass12', status: 'active' }, '/admin/publishers/new');
  const pubId = db.prepare("SELECT id FROM publishers WHERE username='g6p'").get().id;
  const advId = db.prepare("SELECT id FROM advertisers WHERE slug='g6a'").get().id;
  await post(admin, `/admin/publishers/${pubId}/assign`, { advertiser_id: advId }, `/admin/publishers/${pubId}/edit`);

  // ===== (1) campaign CRUD + tracking attributes campaign_id + campaign payout =====
  await post(admin, '/admin/advertisers/g6a/campaigns',
    { name: 'Camp1', offer_url: 'https://g6a.test/camp1', payout: 7, currency: 'USD', event: 'sale', cap_monthly: '' },
    '/admin/advertisers/g6a/campaigns');
  const c1 = campId('g6a', 'Camp1');
  ok('(1) campaign created', !!c1, String(c1));

  const clk1 = await track(`g6a/${c1}?pub=g6p`);
  const clickRow = db.prepare('SELECT campaign_id FROM clicks WHERE click_id=?').get(clk1);
  ok('(1) click stored campaign_id', clickRow && clickRow.campaign_id === c1, JSON.stringify(clickRow));

  const r1 = await (await postback('g6a', `click_id=${clk1}&event=sale`)).json();
  const conv1 = db.prepare('SELECT campaign_id, payout, currency, status FROM conversions WHERE click_id=?').get(clk1);
  ok('(1) conversion stored campaign_id', conv1 && conv1.campaign_id === c1, JSON.stringify(conv1));
  ok('(1) campaign payout (7) overrides advertiser default (5)', conv1 && conv1.payout === 7 && r1.payout === 7, JSON.stringify(r1));

  // edit + pause round-trips
  await post(admin, `/admin/advertisers/g6a/campaigns/${c1}`,
    { name: 'Camp1', offer_url: 'https://g6a.test/camp1', payout: 9, currency: 'USD', event: 'sale', cap_monthly: '', status: 'active' },
    `/admin/advertisers/g6a/campaigns/${c1}/edit`);
  ok('(1) campaign update persisted (payout 9)', db.prepare('SELECT payout FROM campaigns WHERE id=?').get(c1).payout === 9);
  await post(admin, `/admin/advertisers/g6a/campaigns/${c1}/pause`, {}, '/admin/advertisers/g6a/campaigns');
  ok('(1) campaign pause toggled', db.prepare('SELECT status FROM campaigns WHERE id=?').get(c1).status === 'paused');
  await post(admin, `/admin/advertisers/g6a/campaigns/${c1}/pause`, {}, '/admin/advertisers/g6a/campaigns'); // reactivate

  // ===== (2) campaign monthly cap → 429 + auto-pause =====
  await post(admin, '/admin/advertisers/g6a/campaigns',
    { name: 'CapCamp', offer_url: 'https://g6a.test/cap', payout: 3, currency: 'USD', event: 'sale', cap_monthly: 1 },
    '/admin/advertisers/g6a/campaigns');
  const cap = campId('g6a', 'CapCamp');
  const cclk1 = await track(`g6a/${cap}?pub=g6p`);
  const cap1 = await postback('g6a', `click_id=${cclk1}&event=sale`);
  ok('(2) first conversion under cap accepted', cap1.status === 200, 'status ' + cap1.status);

  const cclk2 = await track(`g6a/${cap}?pub=g6p`);
  const cap2 = await postback('g6a', `click_id=${cclk2}&event=sale`);
  const cap2body = await cap2.json();
  ok('(2) second conversion over cap → 429', cap2.status === 429, 'status ' + cap2.status);
  ok('(2) error is campaign_cap_reached', cap2body.error === 'campaign_cap_reached', JSON.stringify(cap2body));
  ok('(2) campaign auto-paused', db.prepare('SELECT status FROM campaigns WHERE id=?').get(cap).status === 'paused');

  // ===== (3) publisher ↔ campaign mapping views =====
  const advPubs = await txt(await admin.req('GET', '/admin/advertisers/g6a/publishers'));
  ok('(3) advertiser→publishers view lists g6p', advPubs.includes('g6p'));
  ok('(3) advertiser→publishers view lists campaign Camp1', advPubs.includes('Camp1'));

  const pubCamps = await txt(await admin.req('GET', '/admin/publishers/g6p/campaigns'));
  ok('(3) publisher→campaigns view lists advertiser G6 A', pubCamps.includes('G6 A'));
  ok('(3) publisher→campaigns view lists campaign Camp1', pubCamps.includes('Camp1'));

  // ===== (4) bulk approve — 3 conversions in one request =====
  await post(admin, '/admin/advertisers/g6a/campaigns',
    { name: 'BulkCamp', offer_url: 'https://g6a.test/bulk', payout: 2, currency: 'USD', event: 'sale', cap_monthly: '' },
    '/admin/advertisers/g6a/campaigns');
  const bc = campId('g6a', 'BulkCamp');
  const bulkIds = [];
  for (let i = 0; i < 3; i++) {
    const ck = await track(`g6a/${bc}?pub=g6p`);
    await postback('g6a', `click_id=${ck}&event=sale`);
    bulkIds.push(db.prepare('SELECT id FROM conversions WHERE click_id=?').get(ck).id);
  }
  ok('(4) 3 bulk conversions created pending',
    bulkIds.length === 3 && bulkIds.every(id => db.prepare('SELECT status FROM conversions WHERE id=?').get(id).status === 'pending'));
  const bulkRes = await (await admin.req('POST', '/admin/conversions/bulk-approve', { json: { ids: bulkIds, _csrf: await csrf(admin, '/admin') } })).json();
  ok('(4) bulk-approve reports 3 approved', bulkRes.ok === true && bulkRes.approved === 3, JSON.stringify(bulkRes));
  ok('(4) all 3 now approved in db', bulkIds.every(id => db.prepare('SELECT status FROM conversions WHERE id=?').get(id).status === 'approved'));

  // bulk reject too
  const rejRes = await (await admin.req('POST', '/admin/conversions/bulk-reject', { json: { ids: [bulkIds[0]], reason: 'qa', _csrf: await csrf(admin, '/admin') } })).json();
  ok('(4) bulk-reject reports 1 rejected', rejRes.ok === true && rejRes.rejected === 1, JSON.stringify(rejRes));
  ok('(4) rejected row carries reason', db.prepare('SELECT status, reason FROM conversions WHERE id=?').get(bulkIds[0]).reason === 'qa');

  // ===== (5) publisher tracking-link generator page renders =====
  const pub = makeJar();
  await pub.req('POST', '/publisher/login', { form: { username: 'g6p', password: 'g6ppass12' } });
  const lg = await pub.req('GET', '/publisher/link-generator');
  const lgHtml = await txt(lg);
  ok('(5) link-generator page loads (200)', lg.status === 200, 'status ' + lg.status);
  ok('(5) form renders (advertiser + campaign selects)', lgHtml.includes('id="lg-adv"') && lgHtml.includes('id="lg-camp"'), '');
  ok('(5) form has af_sub + UTM inputs', lgHtml.includes('id="lg-sub1"') && lgHtml.includes('id="lg-utm-source"') && lgHtml.includes('id="lg-utm-campaign"'));
  ok('(5) generate + copy + QR controls present', lgHtml.includes('id="lg-gen"') && lgHtml.includes('id="lg-copy"') && lgHtml.includes('id="lg-qr-img"'));
  ok('(5) assigned advertiser appears as an option', lgHtml.includes('>G6 A<'));

  console.log(`\nPASSED: ${pass}`);
  if (failures.length) { console.log(`FAILED: ${failures.length}`); failures.forEach(f => console.log('  ✗ ' + f)); process.exit(1); }
  console.log('ALL GREEN ✓'); process.exit(0);
})().catch(e => { console.error('HARNESS ERROR:', e); process.exit(2); });
