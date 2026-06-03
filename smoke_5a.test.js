'use strict';
// Smoke test — feat/backlog-5a (Partner-link macro + Event name mapping, items 5 & 7).
const BASE = process.env.E2E_BASE || 'http://localhost:3999';
let pass = 0; const fail = [];
const ok = (n, c, x = '') => { c ? pass++ : fail.push(n + (x ? ` — ${x}` : '')); };
function jar() { let ck = ''; return { get cookie() { return ck; }, async req(m, p, o = {}) { const h = { ...(o.headers || {}) }; if (ck) h.Cookie = ck; let b; if (o.form) { b = new URLSearchParams(o.form).toString(); h['Content-Type'] = 'application/x-www-form-urlencoded'; } const r = await fetch(BASE + p, { method: m, headers: h, body: b, redirect: 'manual' }); for (const c of (r.headers.getSetCookie?.() || [])) { const kv = c.split(';')[0], nm = kv.split('=')[0]; const ps = (ck ? ck.split('; ') : []).filter(x => x.split('=')[0] !== nm); ps.push(kv); ck = ps.join('; '); } return r; } }; }
const txt = r => r.text();
const csrf = async (j, p) => (((await txt(await j.req('GET', p))).match(/name="_csrf" value="([a-f0-9]+)"/)) || [])[1] || '';
const post = async (j, p, f, cp) => j.req('POST', p, { form: { ...f, _csrf: await csrf(j, cp) } });
const track = async (s, pu) => ((((await fetch(`${BASE}/track/${s}?pub=${pu}`, { redirect: 'manual' })).headers.get('location')) || '').match(/click_id=([a-f0-9-]+)/) || [])[1] || null;

(async () => {
  const { DatabaseSync } = require('node:sqlite'); const path = require('node:path');
  const db = new DatabaseSync(path.join(__dirname, 'affiliate.db'));
  const a = jar();
  await a.req('POST', '/admin/login', { form: { username: 'admin', password: 'testpass123' } });
  await post(a, '/admin/advertisers', { name: 'Smoke5a', slug: 'sm5a', offer_url: 'https://sm5a.test/o', payout_amount: 10, payout_type: 'fixed', click_lookback_window: 90, status: 'active' }, '/admin/advertisers/new');
  await post(a, '/admin/publishers', { username: 'sm5apub', password: 'sm5apass1', status: 'active' }, '/admin/publishers/new');
  const aid = db.prepare("SELECT id FROM advertisers WHERE slug='sm5a'").get().id;
  const pid = db.prepare("SELECT id FROM publishers WHERE username='sm5apub'").get().id;
  await post(a, `/admin/publishers/${pid}/assign`, { advertiser_id: aid }, `/admin/publishers/${pid}/edit`);

  // #5 partner-link template stored + copy block on edit page
  await post(a, '/admin/advertisers/sm5a/partner-link', { partner_link_template: 'https://t/x?customer_user_id={click_id}' }, '/admin/advertisers/sm5a/edit');
  ok('#5 partner-link template stored', db.prepare("SELECT partner_link_template FROM advertisers WHERE slug='sm5a'").get().partner_link_template.includes('customer_user_id'));
  ok('#5 copy-paste setup block on edit page', (await txt(await a.req('GET', '/admin/advertisers/sm5a/edit'))).includes('Copy-paste AppsFlyer setup block'));

  // #7 event mapping affects goal resolution
  await post(a, '/admin/advertisers/sm5a/goals', { name: 'Bonus', event_token: 'bonus', payout: 40, payout_type: 'fixed', description: '' }, '/admin/advertisers/sm5a/edit');
  await post(a, '/admin/advertisers/sm5a/event-mappings', { source_event: 'af_bonus', mapped_event: 'bonus' }, '/admin/advertisers/sm5a/edit');
  const cid = await track('sm5a', 'sm5apub');
  const r = await (await fetch(`${BASE}/postback/sm5a?click_id=${cid}&event=af_bonus`, { redirect: 'manual' })).json();
  ok('#7 mapped event resolves goal payout (af_bonus->bonus->40)', r.payout === 40, JSON.stringify(r));
  ok('#7 conversion stored with mapped event', db.prepare('SELECT event FROM conversions WHERE click_id=?').get(cid).event === 'bonus');

  console.log(`\nPASSED: ${pass}`);
  if (fail.length) { console.log(`FAILED: ${fail.length}`); fail.forEach(f => console.log('  ✗ ' + f)); process.exit(1); }
  console.log('ALL GREEN ✓'); process.exit(0);
})().catch(e => { console.error('HARNESS ERROR:', e); process.exit(2); });
