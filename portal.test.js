'use strict';
// Advertiser Portal security tests (Backlog #11 / feat/backlog-5e).
// Boot the server like the other suites (PORT=3999, ADMIN_PASS=testpass123) then:
//   node portal.test.js
// Covers the QA-blocking requirements:
//   (a) Login  — scrypt auth (correct vs wrong), session.regenerate (session-fixation),
//                lockout after 5 failed attempts (HTTP 429).
//   (b) IDOR   — advertiser A uploads a reconciliation CSV referencing advertiser B's
//                click_ids -> all unmatched, B's conversions untouched, A cannot see B's data.
// NOTE: the lockout group is run LAST because it blocks the test IP's publisher-login
// counter for 15 minutes; nothing after it performs a portal/publisher login.

const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const BASE = process.env.E2E_BASE || 'http://localhost:3999';
const db = new DatabaseSync(path.join(__dirname, 'affiliate.db'));
db.exec('PRAGMA busy_timeout = 5000');

let pass = 0; const failures = [];
const ok = (n, c, x = '') => { c ? pass++ : failures.push(n + (x ? ` — ${x}` : '')); };

function makeJar() {
  let cookie = '';
  return {
    get cookie() { return cookie; },
    get sid() { return (cookie.match(/connect\.sid=([^;]+)/) || [])[1] || ''; },
    async req(method, p, { form, headers = {} } = {}) {
      const h = { ...headers }; if (cookie) h.Cookie = cookie;
      let body; if (form) { body = new URLSearchParams(form).toString(); h['Content-Type'] = 'application/x-www-form-urlencoded'; }
      const res = await fetch(BASE + p, { method, headers: h, body, redirect: 'manual' });
      for (const c of (res.headers.getSetCookie?.() || [])) {
        const kv = c.split(';')[0], name = kv.split('=')[0];
        const parts = (cookie ? cookie.split('; ') : []).filter(x => x.split('=')[0] !== name);
        parts.push(kv); cookie = parts.join('; ');
      }
      return res;
    },
  };
}
const txt = r => r.text();
async function csrf(jar, p) { return (((await txt(await jar.req('GET', p))).match(/name="_csrf" value="([a-f0-9]+)"/)) || [])[1] || ''; }
async function post(jar, p, form, csrfPage) { return jar.req('POST', p, { form: { ...form, _csrf: await csrf(jar, csrfPage) } }); }
async function track(slug, pub) {
  const res = await fetch(`${BASE}/track/${slug}?pub=${pub}`, { redirect: 'manual' });
  return ((res.headers.get('location') || '').match(/click_id=([a-f0-9-]+)/) || [])[1] || null;
}
async function postback(slug, qs) { return fetch(`${BASE}/postback/${slug}?${qs}`, { redirect: 'manual' }); }

(async () => {
  // ---- setup: admin creates advertisers A + B, a publisher assigned to both ----
  const admin = makeJar();
  await admin.req('POST', '/admin/login', { form: { username: 'admin', password: 'testpass123' } });
  for (const [slug, name] of [['g5ea', 'Adv A'], ['g5eb', 'Adv B']]) {
    await post(admin, '/admin/advertisers',
      { name, slug, offer_url: `https://${slug}.test/o`, payout_amount: 10, payout_type: 'fixed', click_lookback_window: 90, status: 'active' },
      '/admin/advertisers/new');
  }
  await post(admin, '/admin/publishers', { username: 'g5epub', password: 'g5epubpass1', status: 'active' }, '/admin/publishers/new');
  const aId = db.prepare("SELECT id FROM advertisers WHERE slug='g5ea'").get().id;
  const bId = db.prepare("SELECT id FROM advertisers WHERE slug='g5eb'").get().id;
  const pId = db.prepare("SELECT id FROM publishers WHERE username='g5epub'").get().id;
  await post(admin, `/admin/publishers/${pId}/assign`, { advertiser_id: aId }, `/admin/publishers/${pId}/edit`);
  await post(admin, `/admin/publishers/${pId}/assign`, { advertiser_id: bId }, `/admin/publishers/${pId}/edit`);
  // enable portal access (admin sets portal passwords; >=8 chars)
  await post(admin, '/admin/advertisers/g5ea/portal-password', { portal_password: 'portalApass1' }, '/admin/advertisers/g5ea/edit');
  await post(admin, '/admin/advertisers/g5eb/portal-password', { portal_password: 'portalBpass1' }, '/admin/advertisers/g5eb/edit');

  // create one pending conversion for A and two for B
  const cA = await track('g5ea', 'g5epub'); await postback('g5ea', `click_id=${cA}&event=sale`);
  const cB1 = await track('g5eb', 'g5epub'); await postback('g5eb', `click_id=${cB1}&event=sale`);
  const cB2 = await track('g5eb', 'g5epub'); await postback('g5eb', `click_id=${cB2}&event=sale`);

  // =====================================================================
  // (a) LOGIN — scrypt auth + session.regenerate
  // =====================================================================
  const aJar = makeJar();
  const login1 = await aJar.req('POST', '/advertiser/login', { form: { username: 'g5ea', password: 'portalApass1' } });
  ok('(a) scrypt auth: correct password -> 302 dashboard', (login1.headers.get('location') || '').includes('/advertiser/dashboard'));
  ok('(a) authenticated session cookie set', !!aJar.sid);
  const dash = await txt(await aJar.req('GET', '/advertiser/dashboard'));
  ok('(a) dashboard reachable after login', dash.includes('Adv A'));
  // session.regenerate: a second login in the SAME jar must rotate the session id
  const sidBefore = aJar.sid;
  await aJar.req('POST', '/advertiser/login', { form: { username: 'g5ea', password: 'portalApass1' } });
  ok('(a) session.regenerate rotates session id on login (anti-fixation)', !!aJar.sid && aJar.sid !== sidBefore, `before=${sidBefore.slice(0,10)} after=${aJar.sid.slice(0,10)}`);

  // =====================================================================
  // (b) IDOR — A's reconcile CSV referencing B's click_ids must not touch B
  // =====================================================================
  // record B's current state
  const bBefore = db.prepare("SELECT click_id, status FROM conversions WHERE advertiser_slug='g5eb' ORDER BY click_id").all();
  // A (logged in) uploads a CSV trying to approve B's conversions
  {
    const _csrf = await csrf(aJar, '/advertiser/reconcile');
    const fd = new FormData();
    fd.append('_csrf', _csrf);
    fd.append('csv_file', new Blob([`click_id,status,payout\n${cB1},approved,999\n${cB2},approved,999\n`], { type: 'text/csv' }), 'idor.csv');
    await fetch(`${BASE}/advertiser/reconcile`, { method: 'POST', headers: { Cookie: aJar.cookie }, body: fd, redirect: 'manual' });
  }
  const lastRunA = db.prepare("SELECT * FROM reconciliation_runs WHERE advertiser_slug='g5ea' ORDER BY id DESC LIMIT 1").get();
  ok('(b) IDOR: A\'s run matched 0 of B\'s click_ids', lastRunA && lastRunA.matched === 0 && lastRunA.unmatched === 2,
    JSON.stringify({ matched: lastRunA && lastRunA.matched, unmatched: lastRunA && lastRunA.unmatched }));
  const bAfter = db.prepare("SELECT click_id, status FROM conversions WHERE advertiser_slug='g5eb' ORDER BY click_id").all();
  ok('(b) IDOR: B\'s conversions are completely untouched',
    JSON.stringify(bBefore) === JSON.stringify(bAfter) && bAfter.every(c => c.status === 'pending'), JSON.stringify(bAfter));
  ok('(b) IDOR: B\'s payouts not overwritten by A\'s CSV',
    db.prepare("SELECT COUNT(*) n FROM conversions WHERE advertiser_slug='g5eb' AND payout=999").get().n === 0);
  // A's portal views are scoped to A only — B's click_ids never appear
  const aConvHtml = await txt(await aJar.req('GET', '/advertiser/conversions'));
  ok('(b) scoping: A\'s conversions page shows A\'s data', aConvHtml.includes(cA));
  ok('(b) scoping: A\'s conversions page does NOT leak B\'s click_ids', !aConvHtml.includes(cB1) && !aConvHtml.includes(cB2));

  // =====================================================================
  // (a, cont.) LOCKOUT — 5 failed logins -> 429 (run last; blocks the IP)
  // =====================================================================
  const lockJar = makeJar();
  let firstMsg = '', lockedStatus = 0;
  for (let i = 1; i <= 6; i++) {
    const r = await lockJar.req('POST', '/advertiser/login', { form: { username: 'g5ea', password: 'WRONG-pw' } });
    if (i === 1) firstMsg = await txt(r);
    if (i === 6) lockedStatus = r.status;
  }
  ok('(a) scrypt auth: wrong password rejected', firstMsg.includes('Invalid advertiser slug or password'));
  ok('(a) lockout after 5 failed attempts -> HTTP 429', lockedStatus === 429, `status=${lockedStatus}`);

  console.log(`\nPASSED: ${pass}`);
  if (failures.length) { console.log(`FAILED: ${failures.length}`); failures.forEach(f => console.log('  ✗ ' + f)); process.exit(1); }
  console.log('ALL GREEN ✓'); process.exit(0);
})().catch(e => { console.error('HARNESS ERROR:', e); process.exit(2); });
