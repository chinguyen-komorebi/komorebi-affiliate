'use strict';
// Backlog Group 1 (Critical, items 1–4) — drives the running server over HTTP.
// Boot server like the other suites (PORT=3999, ADMIN_PASS=testpass123) then:
//   node group1.test.js
// Items: #1 Reconciliation Report (discrepancy + dispute/adjustment), #2 Postback
// Delivery Log, #3 Attribution Window default 90, #4 Timezone + Currency per advertiser.

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
async function adminPost(jar, p, form, csrfPage) { return jar.req('POST', p, { form: { ...form, _csrf: await csrf(jar, csrfPage) } }); }
async function track(slug, pub) {
  const res = await fetch(`${BASE}/track/${slug}?pub=${pub}`, { redirect: 'manual' });
  return ((res.headers.get('location') || '').match(/click_id=([a-f0-9-]+)/) || [])[1] || null;
}
async function uploadReconcile(jar, slug, csvText) {
  const _csrf = await csrf(jar, `/admin/advertisers/${slug}/reconcile`);
  const fd = new FormData();
  fd.append('_csrf', _csrf);
  fd.append('csv_file', new Blob([csvText], { type: 'text/csv' }), 'r.csv');
  return fetch(`${BASE}/admin/advertisers/${slug}/reconcile`, { method: 'POST', headers: { Cookie: jar.cookie }, body: fd, redirect: 'manual' });
}

(async () => {
  const admin = makeJar();
  await admin.req('POST', '/admin/login', { form: { username: 'admin', password: 'testpass123' } });

  // ===== Item #3 — attribution window defaults to 90 when omitted =====
  await adminPost(admin, '/admin/advertisers',
    { name: 'G1 Default Win', slug: 'g1win', offer_url: 'https://g1.test/o', payout_amount: 10, payout_type: 'fixed', status: 'active' },
    '/admin/advertisers/new'); // note: click_lookback_window intentionally omitted
  const winAdv = db.prepare("SELECT click_lookback_window FROM advertisers WHERE slug='g1win'").get();
  ok('#3 omitted lookback window defaults to 90', winAdv && winAdv.click_lookback_window === 90, JSON.stringify(winAdv));
  const newForm = await txt(await admin.req('GET', '/admin/advertisers/new'));
  ok('#3 form references AppsFlyer attribution window', /AppsFlyer attribution window/i.test(newForm));

  // ===== Item #4 — timezone + currency per advertiser =====
  await adminPost(admin, '/admin/advertisers',
    { name: 'G1 TZ', slug: 'g1adv', offer_url: 'https://g1.test/o', payout_amount: 5, payout_type: 'fixed',
      click_lookback_window: 90, timezone: 'Asia/Bangkok', currency: 'THB', status: 'active' },
    '/admin/advertisers/new');
  const tzAdv = db.prepare("SELECT timezone, currency FROM advertisers WHERE slug='g1adv'").get();
  ok('#4 timezone stored', tzAdv && tzAdv.timezone === 'Asia/Bangkok', JSON.stringify(tzAdv));
  ok('#4 currency stored', tzAdv && tzAdv.currency === 'THB', JSON.stringify(tzAdv));
  const editForm = await txt(await admin.req('GET', '/admin/advertisers/g1adv/edit'));
  ok('#4 edit form shows saved timezone', editForm.includes('value="Asia/Bangkok"'));
  ok('#4 edit form shows currency selected', /<option value="THB" selected>/.test(editForm));
  // invalid timezone is rejected → null
  await adminPost(admin, '/admin/advertisers/g1adv/update',
    { name: 'G1 TZ', offer_url: 'https://g1.test/o', payout_amount: 5, payout_type: 'fixed', click_lookback_window: 90,
      timezone: 'Not/AReal_Zone', currency: 'usd', status: 'active' }, '/admin/advertisers/g1adv/edit');
  const tzAdv2 = db.prepare("SELECT timezone, currency FROM advertisers WHERE slug='g1adv'").get();
  ok('#4 invalid timezone stored as null', tzAdv2.timezone === null, JSON.stringify(tzAdv2));
  ok('#4 currency normalized to uppercase', tzAdv2.currency === 'USD', JSON.stringify(tzAdv2));

  // ===== Item #1 — reconciliation report: discrepancy + dispute/adjustment =====
  await adminPost(admin, '/admin/publishers', { username: 'g1pub', password: 'g1pubpass1', status: 'active' }, '/admin/publishers/new');
  const advId = db.prepare("SELECT id FROM advertisers WHERE slug='g1adv'").get().id;
  const pubId = db.prepare("SELECT id FROM publishers WHERE username='g1pub'").get().id;
  await adminPost(admin, `/admin/publishers/${pubId}/assign`, { advertiser_id: advId }, `/admin/publishers/${pubId}/edit`);

  const cA = await track('g1adv', 'g1pub');
  await fetch(`${BASE}/postback/g1adv?click_id=${cA}&event=sale`, { redirect: 'manual' });
  // First run approves it
  await uploadReconcile(admin, 'g1adv', `click_id,status\n${cA},approved\n`);
  ok('#1 first run approves conversion', db.prepare('SELECT status FROM conversions WHERE click_id=?').get(cA).status === 'approved');
  // Second run REJECTS the same conversion → discrepancy + disputed
  await uploadReconcile(admin, 'g1adv', `click_id,status,reason\n${cA},rejected,advertiser clawback\n`);
  const convAfter = db.prepare('SELECT status, dispute_state, reconciliation_run_id FROM conversions WHERE click_id=?').get(cA);
  ok('#1 overturn flips status to rejected', convAfter.status === 'rejected', JSON.stringify(convAfter));
  ok('#1 overturn flags conversion disputed', convAfter.dispute_state === 'disputed', JSON.stringify(convAfter));
  const lastRun = db.prepare("SELECT * FROM reconciliation_runs WHERE advertiser_slug='g1adv' ORDER BY id DESC LIMIT 1").get();
  ok('#1 run records discrepancy=1', lastRun.discrepancy === 1, JSON.stringify({ d: lastRun.discrepancy }));
  const reportHtml = await txt(await admin.req('GET', `/admin/advertisers/g1adv/reconcile?run=${lastRun.id}`));
  ok('#1 report shows Discrepancies card', reportHtml.includes('Discrepancies'));
  ok('#1 report shows Disputed section', reportHtml.includes('Disputed / Discrepant Conversions'));
  ok('#1 report shows match key click_id ↔ customer_user_id', reportHtml.includes('customer_user_id'));
  // dispute/adjustment endpoint
  const convId = db.prepare('SELECT id FROM conversions WHERE click_id=?').get(cA).id;
  await adminPost(admin, `/admin/conversions/${convId}/dispute`,
    { dispute_state: 'resolved', adjustment: '-5.00', adjustment_note: 'clawback agreed' }, `/admin/advertisers/g1adv/reconcile?run=${lastRun.id}`);
  const disp = db.prepare('SELECT dispute_state, adjustment, adjustment_note FROM conversions WHERE id=?').get(convId);
  ok('#1 dispute resolved + adjustment stored', disp.dispute_state === 'resolved' && disp.adjustment === -5 && disp.adjustment_note === 'clawback agreed', JSON.stringify(disp));

  // ===== Item #2 — global postback delivery log =====
  // received view shows our conversion
  const recv = await txt(await admin.req('GET', '/admin/postback-log?dir=received'));
  ok('#2 received log renders + shows click_id', recv.includes('Postback Delivery Log') && recv.includes(cA));
  ok('#2 log has Sent/Received tabs', recv.includes('Sent (S2S') && recv.includes('Received ('));
  // duplicate received: 2nd event on same click_id
  await fetch(`${BASE}/postback/g1adv?click_id=${cA}&event=purchase`, { redirect: 'manual' });
  const dupCount = db.prepare('SELECT COUNT(*) n FROM (SELECT click_id FROM conversions GROUP BY click_id HAVING COUNT(*)>1)').get().n;
  ok('#2 duplicate click_id detectable in conversions', dupCount >= 1, `dups=${dupCount}`);
  const recvDup = await txt(await admin.req('GET', `/admin/postback-log?dir=received&q=${cA}`));
  ok('#2 received log flags duplicate click_id', recvDup.includes('>dup<') || recvDup.includes('dup</span>'), 'expected dup badge');
  // sent view renders (may be empty — no publisher postback_url set) but must not error
  const sent = await fetch(`${BASE}/admin/postback-log?dir=sent`, { headers: { Cookie: admin.cookie }, redirect: 'manual' });
  ok('#2 sent view returns 200', sent.status === 200);
  // status filter renders
  const failView = await fetch(`${BASE}/admin/postback-log?dir=received&status=fail`, { headers: { Cookie: admin.cookie }, redirect: 'manual' });
  ok('#2 status filter returns 200', failView.status === 200);

  console.log(`\nPASSED: ${pass}`);
  if (failures.length) { console.log(`FAILED: ${failures.length}`); failures.forEach(f => console.log('  ✗ ' + f)); process.exit(1); }
  console.log('ALL GREEN ✓'); process.exit(0);
})().catch(e => { console.error('HARNESS ERROR:', e); process.exit(2); });
