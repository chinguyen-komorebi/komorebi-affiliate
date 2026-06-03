'use strict';
// Smoke test — feat/backlog-5f (Custom domain per publisher, item 12).
const BASE = process.env.E2E_BASE || 'http://localhost:3999';
let pass = 0; const fail = [];
const ok = (n, c, x = '') => { c ? pass++ : fail.push(n + (x ? ` — ${x}` : '')); };
function jar() { let ck = ''; return { get cookie() { return ck; }, async req(m, p, o = {}) { const h = { ...(o.headers || {}) }; if (ck) h.Cookie = ck; let b; if (o.form) { b = new URLSearchParams(o.form).toString(); h['Content-Type'] = 'application/x-www-form-urlencoded'; } const r = await fetch(BASE + p, { method: m, headers: h, body: b, redirect: 'manual' }); for (const c of (r.headers.getSetCookie?.() || [])) { const kv = c.split(';')[0], nm = kv.split('=')[0]; const ps = (ck ? ck.split('; ') : []).filter(x => x.split('=')[0] !== nm); ps.push(kv); ck = ps.join('; '); } return r; } }; }
const txt = r => r.text();
const csrf = async (j, p) => (((await txt(await j.req('GET', p))).match(/name="_csrf" value="([a-f0-9]+)"/)) || [])[1] || '';
const post = async (j, p, f, cp) => j.req('POST', p, { form: { ...f, _csrf: await csrf(j, cp) } });

(async () => {
  const { DatabaseSync } = require('node:sqlite'); const path = require('node:path');
  const db = new DatabaseSync(path.join(__dirname, 'affiliate.db'));
  const a = jar();
  await a.req('POST', '/admin/login', { form: { username: 'admin', password: 'testpass123' } });
  await post(a, '/admin/publishers', { username: 'sm5fpub', password: 'sm5fpass1', status: 'active', custom_domain: 'https://go.sm5f.com/path' }, '/admin/publishers/new');
  const pid = db.prepare("SELECT id FROM publishers WHERE username='sm5fpub'").get().id;
  ok('#12 custom domain normalized to bare host on create', db.prepare('SELECT custom_domain FROM publishers WHERE id=?').get(pid).custom_domain === 'go.sm5f.com');
  await post(a, `/admin/publishers/${pid}/update`, { status: 'active', minimum_payout: 50, postback_url: '', custom_domain: 'not a domain' }, `/admin/publishers/${pid}/edit`);
  ok('#12 invalid custom domain rejected -> null', db.prepare('SELECT custom_domain FROM publishers WHERE id=?').get(pid).custom_domain === null);
  await post(a, `/admin/publishers/${pid}/update`, { status: 'active', minimum_payout: 50, postback_url: '', custom_domain: 'GO.Partner.COM' }, `/admin/publishers/${pid}/edit`);
  ok('#12 domain lowercased + stored', db.prepare('SELECT custom_domain FROM publishers WHERE id=?').get(pid).custom_domain === 'go.partner.com');
  console.log(`\nPASSED: ${pass}`);
  if (fail.length) { console.log(`FAILED: ${fail.length}`); fail.forEach(f => console.log('  ✗ ' + f)); process.exit(1); }
  console.log('ALL GREEN ✓'); process.exit(0);
})().catch(e => { console.error('HARNESS ERROR:', e); process.exit(2); });
