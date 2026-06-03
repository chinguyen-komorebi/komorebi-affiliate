'use strict';
// Smoke test — feat/backlog-5b (Postback test tool + HMAC docs, item 8).
// Includes the QA SSRF requirement (c): the postback test tool must self-target
// BASE_URL — attacker-controlled input can never redirect the outbound request to
// an arbitrary host. Run with the server listening on :3999.
const BASE = process.env.E2E_BASE || 'http://localhost:3999';
let pass = 0; const fail = [];
const ok = (n, c, x = '') => { c ? pass++ : fail.push(n + (x ? ` — ${x}` : '')); };
function jar() { let ck = ''; return { get cookie() { return ck; }, async req(m, p, o = {}) { const h = { ...(o.headers || {}) }; if (ck) h.Cookie = ck; let b; if (o.form) { b = new URLSearchParams(o.form).toString(); h['Content-Type'] = 'application/x-www-form-urlencoded'; } const r = await fetch(BASE + p, { method: m, headers: h, body: b, redirect: 'manual' }); for (const c of (r.headers.getSetCookie?.() || [])) { const kv = c.split(';')[0], nm = kv.split('=')[0]; const ps = (ck ? ck.split('; ') : []).filter(x => x.split('=')[0] !== nm); ps.push(kv); ck = ps.join('; '); } return r; } }; }
const txt = r => r.text();
const csrf = async (j, p) => (((await txt(await j.req('GET', p))).match(/name="_csrf" value="([a-f0-9]+)"/)) || [])[1] || '';
const post = async (j, p, f, cp) => j.req('POST', p, { form: { ...f, _csrf: await csrf(j, cp) } });
const track = async (s, pu) => ((((await fetch(`${BASE}/track/${s}?pub=${pu}`, { redirect: 'manual' })).headers.get('location')) || '').match(/click_id=([a-f0-9-]+)/) || [])[1] || null;

(async () => {
  const a = jar();
  await a.req('POST', '/admin/login', { form: { username: 'admin', password: 'testpass123' } });
  await post(a, '/admin/advertisers', { name: 'Smoke5b', slug: 'sm5b', offer_url: 'https://sm5b.test/o', payout_amount: 5, payout_type: 'fixed', click_lookback_window: 90, status: 'active' }, '/admin/advertisers/new');
  await post(a, '/admin/publishers', { username: 'sm5bpub', password: 'sm5bpass1', status: 'active' }, '/admin/publishers/new');
  const { DatabaseSync } = require('node:sqlite'); const path = require('node:path');
  const db = new DatabaseSync(path.join(__dirname, 'affiliate.db'));
  const aid = db.prepare("SELECT id FROM advertisers WHERE slug='sm5b'").get().id;
  const pid = db.prepare("SELECT id FROM publishers WHERE username='sm5bpub'").get().id;
  await post(a, `/admin/publishers/${pid}/assign`, { advertiser_id: aid }, `/admin/publishers/${pid}/edit`);

  // form renders
  const form = await txt(await a.req('GET', '/admin/advertisers/sm5b/postback-test'));
  ok('postback test form renders', form.includes('Postback Test Tool') && form.includes('Send Test Postback'));

  // normal test fires and self-targets BASE_URL
  const cid = await track('sm5b', 'sm5bpub');
  const res = await txt(await post(a, '/admin/advertisers/sm5b/postback-test', { click_id: cid, event: 'sale' }, '/admin/advertisers/sm5b/postback-test'));
  ok('test fires -> HTTP 200', res.includes('Test Result — HTTP 200'));
  ok('request URL self-targets BASE_URL', res.includes(`${BASE}/postback/sm5b?`));

  // (c) SSRF: a malicious click_id cannot move the request host off BASE_URL
  const evil = 'http://169.254.169.254/latest/meta-data';
  const res2 = await txt(await post(a, '/admin/advertisers/sm5b/postback-test', { click_id: evil, event: 'sale' }, '/admin/advertisers/sm5b/postback-test'));
  const urlInPage = (res2.match(/data-copy="([^"]+)"/) || [])[1] || '';
  ok('(c) SSRF: outbound URL still starts with BASE_URL', urlInPage.startsWith(`${BASE}/postback/sm5b?`), urlInPage.slice(0, 60));
  ok('(c) SSRF: attacker host never becomes the request target', !urlInPage.startsWith('http://169.254') && !/^https?:\/\/169\.254/.test(urlInPage));

  console.log(`\nPASSED: ${pass}`);
  if (fail.length) { console.log(`FAILED: ${fail.length}`); fail.forEach(f => console.log('  ✗ ' + f)); process.exit(1); }
  console.log('ALL GREEN ✓'); process.exit(0);
})().catch(e => { console.error('HARNESS ERROR:', e); process.exit(2); });
