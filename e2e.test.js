'use strict';
// Consolidated end-to-end test for F1–F17. Drives the running server over HTTP
// with real sessions + CSRF, plus a local S2S receiver to verify postback macros.
// Run: node e2e.test.js   (server must be listening on BASE)

const http = require('node:http');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const BASE = process.env.E2E_BASE || 'http://localhost:3999';
const DB_PATH = path.join(__dirname, 'affiliate.db');

const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA busy_timeout = 5000');

let pass = 0; const failures = [];
function ok(name, cond, extra = '') {
  if (cond) { pass++; }
  else { failures.push(name + (extra ? ` — ${extra}` : '')); }
}
const sleep = ms => new Promise(r => setTimeout(r, ms));

// ---- cookie-jar HTTP client ------------------------------------------------
function makeJar() {
  let cookie = '';
  return {
    get cookie() { return cookie; },
    async req(method, p, { form, headers = {} } = {}) {
      const h = { ...headers };
      if (cookie) h.Cookie = cookie;
      let body;
      if (form) { body = new URLSearchParams(form).toString(); h['Content-Type'] = 'application/x-www-form-urlencoded'; }
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
async function text(res) { return await res.text(); }
async function csrf(jar, p) {
  const html = await text(await jar.req('GET', p));
  return (html.match(/name="_csrf" value="([a-f0-9]+)"/) || [])[1] || '';
}
async function adminPost(jar, p, form, csrfPage) {
  const _csrf = await csrf(jar, csrfPage);
  return jar.req('POST', p, { form: { ...form, _csrf } });
}
async function track(slug, pub, qs = '', headers = {}) {
  const res = await fetch(`${BASE}/track/${slug}?pub=${pub}${qs}`, { redirect: 'manual', headers });
  return ((res.headers.get('location') || '').match(/click_id=([a-f0-9-]+)/) || [])[1] || null;
}
async function postback(slug, qs) {
  const res = await fetch(`${BASE}/postback/${slug}?${qs}`, { redirect: 'manual' });
  let json = null; try { json = await res.json(); } catch {}
  return { status: res.status, json };
}

(async () => {
  // ---- S2S receiver (for F7/F10 macro verification) ----
  const s2s = [];
  const recv = http.createServer((req, res) => { s2s.push(req.url); res.end('ok'); });
  await new Promise(r => recv.listen(4555, r));

  const admin = makeJar();
  await admin.req('POST', '/admin/login', { form: { username: 'admin', password: 'testpass123' } });
  ok('admin login', !!admin.cookie.includes('connect.sid') || admin.cookie.length > 0);

  // ---- seed advertisers ----
  const advs = {
    basic:    { slug: 'adv-basic',  name: 'Basic',  payout_amount: 10, payout_type: 'fixed' },
    pct:      { slug: 'adv-pct',    name: 'Pct',    payout_amount: 10, payout_type: 'percent' },
    override: { slug: 'adv-ovr',    name: 'Ovr',    payout_amount: 10, payout_type: 'fixed' },
    window:   { slug: 'adv-win',    name: 'Win',    payout_amount: 10, payout_type: 'fixed' },
    cap:      { slug: 'adv-cap',    name: 'Cap',    payout_amount: 5,  payout_type: 'fixed', monthly_conversion_cap: 2 },
  };
  for (const k of Object.keys(advs)) {
    const a = advs[k];
    await adminPost(admin, '/admin/advertisers',
      { name: a.name, slug: a.slug, offer_url: `https://${a.slug}.test/o`, payout_amount: a.payout_amount,
        payout_type: a.payout_type, click_lookback_window: 30, monthly_conversion_cap: a.monthly_conversion_cap || '', status: 'active' },
      '/admin/advertisers/new');
    a.id = db.prepare('SELECT id FROM advertisers WHERE slug=?').get(a.slug).id;
  }
  ok('5 advertisers created', Object.values(advs).every(a => a.id));

  // ---- seed publishers ----
  await adminPost(admin, '/admin/publishers', { username: 'p1', password: 'p1password', status: 'active' }, '/admin/publishers/new');
  await adminPost(admin, '/admin/publishers', { username: 'p2', password: 'p2password', status: 'active' }, '/admin/publishers/new');
  const p1 = db.prepare("SELECT id FROM publishers WHERE username='p1'").get().id;
  const p2 = db.prepare("SELECT id FROM publishers WHERE username='p2'").get().id;
  ok('2 publishers created', !!p1 && !!p2);

  // assign p1 to all advertisers; set p1 S2S postback_url with macros
  for (const a of Object.values(advs)) {
    await adminPost(admin, `/admin/publishers/${p1}/assign`, { advertiser_id: a.id }, `/admin/publishers/${p1}/edit`);
  }
  const pbUrl = 'http://localhost:4555/s2s?cid={click_id}&p={payout}&s1={sub1}&sp={subpub}&camp={campaign}&net={network}&ev={event}';
  await adminPost(admin, `/admin/publishers/${p1}/update`, { status: 'active', minimum_payout: 50, postback_url: pbUrl }, `/admin/publishers/${p1}/edit`);
  ok('p1 assigned to all + postback_url set',
    db.prepare('SELECT COUNT(*) n FROM publisher_advertisers WHERE publisher_id=?').get(p1).n === 5);

  // =====================================================================
  // F3 — assignment gating, payout, override, window
  // =====================================================================
  const cPgate = await track('adv-basic', 'p2');                  // p2 NOT assigned
  ok('F3 unassigned postback → 403', (await postback('adv-basic', `click_id=${cPgate}&event=sale`)).status === 403);

  const c1 = await track('adv-basic', 'p1');
  const r1 = await postback('adv-basic', `click_id=${c1}&event=sale`);
  ok('F3 assigned postback → 200 + fixed payout 10', r1.status === 200 && r1.json.payout === 10);

  // override
  await adminPost(admin, `/admin/publishers/${p1}/assign`, { advertiser_id: advs.override.id, payout_override: 25 }, `/admin/publishers/${p1}/edit`);
  const cO = await track('adv-ovr', 'p1');
  ok('F3 payout_override wins → 25', (await postback('adv-ovr', `click_id=${cO}&event=sale`)).json.payout === 25);

  // validity window (dedicated advertiser)
  const tomorrow = new Date(Date.now() + 864e5).toISOString().slice(0, 10);
  const yesterday = new Date(Date.now() - 864e5).toISOString().slice(0, 10);
  await adminPost(admin, `/admin/publishers/${p1}/assign`, { advertiser_id: advs.window.id, valid_from: tomorrow }, `/admin/publishers/${p1}/edit`);
  const cW1 = await track('adv-win', 'p1');
  ok('F3 valid_from future → 403', (await postback('adv-win', `click_id=${cW1}&event=sale`)).status === 403);
  await adminPost(admin, `/admin/publishers/${p1}/assign`, { advertiser_id: advs.window.id, valid_until: yesterday }, `/admin/publishers/${p1}/edit`);
  const cW2 = await track('adv-win', 'p1');
  ok('F3 valid_until past → 403', (await postback('adv-win', `click_id=${cW2}&event=sale`)).status === 403);

  // =====================================================================
  // F4 — conversion goals
  // =====================================================================
  await adminPost(admin, '/admin/advertisers/adv-basic/goals', { name: 'FTD', event_token: 'ftd', payout: 50, payout_type: 'fixed', description: '' }, '/admin/advertisers/adv-basic/edit');
  const cG = await track('adv-basic', 'p1');
  ok('F4 goal payout (ftd → 50)', (await postback('adv-basic', `click_id=${cG}&event=ftd`)).json.payout === 50);
  const dupGoal = await adminPost(admin, '/admin/advertisers/adv-basic/goals', { name: 'Dup', event_token: 'ftd', payout: 1, payout_type: 'fixed' }, '/admin/advertisers/adv-basic/edit');
  ok('F4 duplicate goal token rejected', db.prepare("SELECT COUNT(*) n FROM goals WHERE event_token='ftd'").get().n === 1);

  // =====================================================================
  // F13/F14 — percentage payout from loan_amount
  // =====================================================================
  const cPct = await track('adv-pct', 'p1');
  ok('F13/F14 percent 10% of 1000 → 100', (await postback('adv-pct', `click_id=${cPct}&event=sale&loan_amount=1000`)).json.payout === 100);
  const cPct0 = await track('adv-pct', 'p1');
  const rPct0 = await postback('adv-pct', `click_id=${cPct0}&event=sale`);
  ok('F14 percent w/o loan_amount → 0 + note', rPct0.json.payout === 0 && rPct0.json.note === 'missing_loan_amount');

  // =====================================================================
  // F16 — revenue captured + margin in admin dashboard
  // =====================================================================
  const cRev = await track('adv-basic', 'p1');
  await postback('adv-basic', `click_id=${cRev}&event=sale&revenue=7`);
  ok('F16 revenue stored on conversion', db.prepare('SELECT revenue FROM conversions WHERE click_id=?').get(cRev).revenue === 7);
  const dash = await text(await admin.req('GET', '/admin'));
  ok('F16 dashboard has Revenue + Margin columns', dash.includes('<th>Revenue</th>') && dash.includes('<th>Margin</th>'));

  // =====================================================================
  // F7 / F8 / F10 — sub params, enhanced tracking, AppsFlyer mapping + S2S macros
  // =====================================================================
  const cSub = await track('adv-basic', 'p1',
    '&sub1=campA&sub2=b7&sub5=s5&subpub=aff9&gclid=GCL1&fbclid=FB1&af_siteid=site42&af_campaign=AFc&af_adset=AFa&af_ad=AFcr',
    { Referer: 'https://ref.example.com/x' });
  const clickRow = db.prepare('SELECT * FROM clicks WHERE click_id=?').get(cSub);
  ok('F7 sub params stored', clickRow.sub1 === 'campA' && clickRow.subpub === 'aff9');
  ok('F8 gclid/fbclid/referrer stored', clickRow.gclid === 'GCL1' && clickRow.fbclid === 'FB1' && clickRow.referrer === 'https://ref.example.com/x');
  ok('F10 AppsFlyer mapped (campaign/network)', clickRow.campaign === 'AFc' && clickRow.network === 'site42' && clickRow.creative === 'AFcr');
  await postback('adv-basic', `click_id=${cSub}&event=sale`);
  await sleep(500); // S2S is fire-and-forget
  const macroHit = s2s.find(u => u.includes(`cid=${cSub}`));
  ok('F7/F10 S2S macros substituted', !!macroHit && macroHit.includes('s1=campA') && macroHit.includes('sp=aff9') && macroHit.includes('camp=AFc') && macroHit.includes('net=site42'));

  // Adjust fallback mapping
  const cAdj = await track('adv-basic', 'p1', '&adjust_campaign=ADJc&adjust_network=ADJn');
  const adjRow = db.prepare('SELECT campaign, network FROM clicks WHERE click_id=?').get(cAdj);
  ok('F10 Adjust fallback mapping', adjRow.campaign === 'ADJc' && adjRow.network === 'ADJn');

  // =====================================================================
  // F9 — transaction_id stored, in CSV, reconcile-by-txn
  // =====================================================================
  const cTxn = await track('adv-basic', 'p1');
  await postback('adv-basic', `click_id=${cTxn}&event=sale&transaction_id=TXN-1`);
  ok('F9 transaction_id stored', db.prepare('SELECT transaction_id FROM conversions WHERE click_id=?').get(cTxn).transaction_id === 'TXN-1');
  const csv = await text(await admin.req('GET', '/admin/export.csv?advertiser=adv-basic'));
  ok('F9 CSV export has transaction_id column', csv.split('\n')[0].includes('transaction_id') && csv.includes('TXN-1'));
  // reconcile by transaction_id only (no click_id)
  {
    const _csrf = await csrf(admin, '/admin/advertisers/adv-basic/reconcile');
    const fd = new FormData();
    fd.append('_csrf', _csrf);
    fd.append('csv_file', new Blob(['click_id,transaction_id,status,reason,payout\n,TXN-1,approved,verified,18.50\n'], { type: 'text/csv' }), 'r.csv');
    await fetch(`${BASE}/admin/advertisers/adv-basic/reconcile`, { method: 'POST', headers: { Cookie: admin.cookie }, body: fd, redirect: 'manual' });
    const c = db.prepare("SELECT status, payout FROM conversions WHERE transaction_id='TXN-1'").get();
    ok('F9 reconcile by transaction_id → approved + payout 18.5', c.status === 'approved' && c.payout === 18.5);
  }

  // =====================================================================
  // F11 — click expiry (per-advertiser lookback)
  // =====================================================================
  const cExp = await track('adv-basic', 'p1');
  db.prepare("UPDATE clicks SET created_at = datetime('now','-31 days') WHERE click_id=?").run(cExp);
  ok('F11 click older than 30d → 410', (await postback('adv-basic', `click_id=${cExp}&event=sale`)).status === 410);
  db.prepare("UPDATE clicks SET created_at = datetime('now','-10 days') WHERE click_id=?").run(cExp);
  ok('F11 click within window → 200', (await postback('adv-basic', `click_id=${cExp}&event=sale`)).status === 200);

  // =====================================================================
  // F15 — duplicate user detection
  // =====================================================================
  const cU1 = await track('adv-basic', 'p1');
  const rU1 = await postback('adv-basic', `click_id=${cU1}&event=sale&user_id=USER-X`);
  ok('F15 first user_id → ok + payout', rU1.json.status === 'ok' && rU1.json.payout === 10);
  const cU2 = await track('adv-basic', 'p1');
  const rU2 = await postback('adv-basic', `click_id=${cU2}&event=purchase&user_id=USER-X`);
  ok('F15 repeat user_id → duplicate + payout 0 + 200', rU2.status === 200 && rU2.json.status === 'duplicate' && rU2.json.payout === 0);
  const cU3 = await track('adv-basic', 'p1');
  ok('F15 different user_id → ok', (await postback('adv-basic', `click_id=${cU3}&event=sale&user_id=USER-Y`)).json.status === 'ok');
  // admin override duplicate → approved
  {
    const dupId = db.prepare("SELECT id FROM conversions WHERE status='duplicate' LIMIT 1").get().id;
    await adminPost(admin, `/admin/conversions/${dupId}/status`, { status: 'approved' }, '/admin');
    ok('F15 admin override duplicate → approved', db.prepare('SELECT status FROM conversions WHERE id=?').get(dupId).status === 'approved');
  }

  // =====================================================================
  // F12 — advertiser cap (approved-only) → 429 + auto-pause; then reset
  // =====================================================================
  // create 2 conversions on adv-cap and approve them (via reconcile), reaching cap=2
  const capClicks = [];
  for (let i = 0; i < 2; i++) { const c = await track('adv-cap', 'p1'); await postback('adv-cap', `click_id=${c}&event=sale`); capClicks.push(c); }
  {
    const _csrf = await csrf(admin, '/admin/advertisers/adv-cap/reconcile');
    const fd = new FormData();
    fd.append('_csrf', _csrf);
    fd.append('csv_file', new Blob([`click_id,status\n${capClicks[0]},approved\n${capClicks[1]},approved\n`], { type: 'text/csv' }), 'c.csv');
    await fetch(`${BASE}/admin/advertisers/adv-cap/reconcile`, { method: 'POST', headers: { Cookie: admin.cookie }, body: fd, redirect: 'manual' });
  }
  ok('F12 setup: 2 approved on adv-cap', db.prepare("SELECT COUNT(*) n FROM conversions WHERE advertiser_slug='adv-cap' AND status='approved'").get().n === 2);
  const cCap = await track('adv-cap', 'p1');
  const rCap = await postback('adv-cap', `click_id=${cCap}&event=sale`);
  ok('F12 at cap → 429', rCap.status === 429);
  ok('F12 advertiser auto-paused', db.prepare("SELECT status FROM advertisers WHERE slug='adv-cap'").get().status === 'paused');
  ok('F12 cap_alerted_100 flag set', db.prepare("SELECT cap_alerted_100 FROM advertisers WHERE slug='adv-cap'").get().cap_alerted_100 === 1);
  // reset via edit form (current month)
  const month = new Date().toISOString().slice(0, 7);
  await adminPost(admin, '/admin/advertisers/adv-cap/update',
    { name: 'Cap', offer_url: 'https://adv-cap.test/o', payout_amount: 5, payout_type: 'fixed', click_lookback_window: 30, monthly_conversion_cap: 2, cap_reset_month: month, status: 'paused' },
    '/admin/advertisers/adv-cap/edit');
  const capAfter = db.prepare("SELECT status, cap_reset_at FROM advertisers WHERE slug='adv-cap'").get();
  ok('F12 reset re-activates advertiser + stamps floor', capAfter.status === 'active' && !!capAfter.cap_reset_at);
  await sleep(1100);
  const cCap2 = await track('adv-cap', 'p1');
  ok('F12 postback accepted after reset', (await postback('adv-cap', `click_id=${cCap2}&event=sale`)).status === 200);

  // =====================================================================
  // F5 — smart links
  // =====================================================================
  // rules for p1: adv-basic on country XX (localhost) any device pri 10; adv-pct on any country mobile pri 5
  await adminPost(admin, `/admin/publishers/${p1}/smart-links`, { advertiser_id: advs.basic.id, country: 'XX', device_type: '*', priority: 10 }, `/admin/publishers/${p1}/smart-links`);
  await adminPost(admin, `/admin/publishers/${p1}/smart-links`, { advertiser_id: advs.pct.id, country: '*', device_type: 'mobile', priority: 5 }, `/admin/publishers/${p1}/smart-links`);
  const goMobile = await fetch(`${BASE}/go/p1`, { redirect: 'manual', headers: { 'User-Agent': 'iPhone Mobile' } });
  ok('F5 mobile → priority 5 rule (adv-pct)', (goMobile.headers.get('location') || '').includes('adv-pct.test'));
  const goDesktop = await fetch(`${BASE}/go/p1`, { redirect: 'manual', headers: { 'User-Agent': 'Macintosh Chrome' } });
  ok('F5 desktop → adv-basic rule', (goDesktop.headers.get('location') || '').includes('adv-basic.test'));
  const go404 = await fetch(`${BASE}/go/p2`, { redirect: 'manual' }); // p2 assigned to nothing, no rules
  ok('F5 no rules + no assignment → 404', go404.status === 404);

  // =====================================================================
  // F6 — marketplace
  // =====================================================================
  // make adv-pct public
  await adminPost(admin, '/admin/advertisers/adv-pct/update',
    { name: 'Pct', offer_url: 'https://adv-pct.test/o', payout_amount: 10, payout_type: 'percent', click_lookback_window: 30,
      monthly_conversion_cap: '', is_public: '1', category: 'Loans', description: 'desc', countries_allowed: 'VN, TH', status: 'active' },
    '/admin/advertisers/adv-pct/edit');
  const mp = await text(await fetch(`${BASE}/marketplace`).then(r => r));
  ok('F6 public listing shows campaign + category', mp.includes('Loans') && mp.includes('VN, TH'));
  const applyOut = await fetch(`${BASE}/marketplace/apply`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: `advertiser_id=${advs.pct.id}`, redirect: 'manual' });
  ok('F6 logged-out apply → login?next', (applyOut.headers.get('location') || '').includes('/publisher/login?next='));
  // p2 logs in and applies (p2 not assigned to adv-pct)
  const p2jar = makeJar();
  await p2jar.req('POST', '/publisher/login', { form: { username: 'p2', password: 'p2password' } });
  await p2jar.req('POST', '/marketplace/apply', { form: { advertiser_id: advs.pct.id, _csrf: await csrf(p2jar, '/marketplace') } });
  ok('F6 apply creates pending application', db.prepare("SELECT COUNT(*) n FROM marketplace_applications WHERE publisher_id=? AND status='pending'").get(p2).n === 1);
  const mpPending = await text(await p2jar.req('GET', '/marketplace'));
  ok('F6 shows Application pending', mpPending.includes('Application pending'));
  // admin approves
  const appId = db.prepare("SELECT id FROM marketplace_applications WHERE publisher_id=? AND status='pending'").get(p2).id;
  await adminPost(admin, `/admin/marketplace/${appId}/approve`, {}, '/admin/marketplace');
  ok('F6 approve → assignment + status approved',
    !!db.prepare('SELECT 1 FROM publisher_advertisers WHERE publisher_id=? AND advertiser_id=?').get(p2, advs.pct.id) &&
    db.prepare('SELECT status FROM marketplace_applications WHERE id=?').get(appId).status === 'approved');

  // =====================================================================
  // F1 — change password
  // =====================================================================
  const p1jar = makeJar();
  await p1jar.req('POST', '/publisher/login', { form: { username: 'p1', password: 'p1password' } });
  const prof = await text(await p1jar.req('GET', '/publisher/profile'));
  ok('F1 profile page has change-password form + csrf', prof.includes('Change Password') && /name="_csrf"/.test(prof));
  const pTok = (prof.match(/name="_csrf" value="([a-f0-9]+)"/) || [])[1];
  const badCur = await text(await p1jar.req('POST', '/publisher/change-password', { form: { current_password: 'WRONG', new_password: 'newp1password', confirm_password: 'newp1password', _csrf: pTok } }));
  ok('F1 wrong current password rejected', badCur.includes('Current password is incorrect'));
  const goodChg = await text(await p1jar.req('POST', '/publisher/change-password', { form: { current_password: 'p1password', new_password: 'newp1password', confirm_password: 'newp1password', _csrf: pTok } }));
  ok('F1 correct change → success', goodChg.includes('updated successfully'));
  const relog = makeJar();
  await relog.req('POST', '/publisher/login', { form: { username: 'p1', password: 'newp1password' } });
  const dashAfter = await relog.req('GET', '/publisher/dashboard');
  ok('F1 re-login with new password works', dashAfter.status === 200);
  const noCsrf = await fetch(`${BASE}/publisher/change-password`, { method: 'POST', headers: { Cookie: p1jar.cookie, 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'current_password=newp1password&new_password=zzzzzzzz9&confirm_password=zzzzzzzz9', redirect: 'manual' });
  ok('F1 change-password without CSRF → 403', noCsrf.status === 403);

  // =====================================================================
  // F2 — forgot / reset password
  // =====================================================================
  db.prepare("UPDATE publishers SET email='p1@example.com' WHERE id=?").run(p1);
  const fp = await text(await (await fetch(`${BASE}/publisher/forgot-password`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'email=p1@example.com', redirect: 'manual' })));
  ok('F2 forgot-password generic response', fp.includes('a password reset link has been sent'));
  const tokRow = db.prepare("SELECT token FROM password_resets WHERE publisher_id=? AND used_at IS NULL ORDER BY created_at DESC LIMIT 1").get(p1);
  ok('F2 reset token created', !!tokRow);
  const adminEdit = await text(await admin.req('GET', `/admin/publishers/${p1}/edit`));
  ok('F2 admin edit surfaces reset link', adminEdit.includes('Active reset link'));
  const resetForm = await text(await fetch(`${BASE}/publisher/reset-password?token=${tokRow.token}`).then(r => r));
  ok('F2 valid token shows reset form', resetForm.includes('Choose a new password'));
  const badTok = await text(await fetch(`${BASE}/publisher/reset-password?token=BOGUS`).then(r => r));
  ok('F2 invalid token → expired page', badTok.includes('Link expired'));
  await fetch(`${BASE}/publisher/reset-password`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: `token=${tokRow.token}&new_password=resetp1password&confirm_password=resetp1password`, redirect: 'manual' });
  const reset2 = makeJar();
  await reset2.req('POST', '/publisher/login', { form: { username: 'p1', password: 'resetp1password' } });
  ok('F2 reset password → login works', (await reset2.req('GET', '/publisher/dashboard')).status === 200);
  const reuse = await text(await fetch(`${BASE}/publisher/reset-password?token=${tokRow.token}`).then(r => r));
  ok('F2 reset token is single-use', reuse.includes('Link expired'));

  // =====================================================================
  // F17 — publisher experience
  // =====================================================================
  // p1 has a percentage conversion on adv-pct (cPct, payout 100 from loan 1000). Set adv-pct payout to 2.75 for the exact string? Use existing conv.
  const dashP1 = await text(await reset2.req('GET', '/publisher/dashboard'));
  ok('F17 dashboard "Updated" caption under cards', (dashP1.match(/Updated /g) || []).length >= 6);
  const convP1 = await text(await reset2.req('GET', '/publisher/conversions'));
  ok('F17 conversions page shows Loan Amount + Revenue columns', convP1.includes('<th>Loan Amount</th>') && convP1.includes('<th>Revenue</th>'));
  ok('F17 percentage breakdown rendered', /[\d,]+ VND × [\d.]+% = [\d,]+ VND/.test(dashP1));
  const payP1 = await text(await reset2.req('GET', '/publisher/payments'));
  const nextMonth = new Date(Date.UTC(new Date().getUTCFullYear(), new Date().getUTCMonth() + 1, 1)).toLocaleDateString('en-GB', { day: '2-digit', month: 'long', year: 'numeric', timeZone: 'UTC' });
  ok('F17 payments next-payment banner', payP1.includes('Expected next payment') && payP1.includes(nextMonth));
  ok('F17 profile shows registered email', (await text(await reset2.req('GET', '/publisher/profile'))).includes('p1@example.com'));
  ok('F17 login has forgot-password link', (await text(await fetch(`${BASE}/publisher/login`).then(r => r))).includes('/publisher/forgot-password'));
  ok('F17 responsive table CSS present', dashP1.includes('.pub-content table'));
  ok('F17 sidebar Browse Offers + Profile', dashP1.includes('/marketplace') && dashP1.includes('/publisher/profile'));

  // ---- done ----
  recv.close();
  console.log(`\nPASSED: ${pass}`);
  if (failures.length) {
    console.log(`FAILED: ${failures.length}`);
    failures.forEach(f => console.log('  ✗ ' + f));
    process.exit(1);
  } else {
    console.log('ALL GREEN ✓');
    process.exit(0);
  }
})().catch(e => { console.error('HARNESS ERROR:', e); process.exit(2); });
