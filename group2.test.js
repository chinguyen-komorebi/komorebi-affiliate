'use strict';
// Backlog Group 2 (Important, items 5–12) — drives the running server over HTTP.
// Boot server like the other suites (PORT=3999, ADMIN_PASS=testpass123) then:
//   node group2.test.js
// Items: #5 partner-link template, #6 AppsFlyer onboarding docs, #7 event mapping,
// #8 postback test tool, #9 cohort report, #10 pivot export, #11 advertiser portal,
// #12 custom domain per publisher.

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
async function post(jar, p, form, csrfPage) { return jar.req('POST', p, { form: { ...form, _csrf: await csrf(jar, csrfPage) } }); }
async function track(slug, pub) {
  const res = await fetch(`${BASE}/track/${slug}?pub=${pub}`, { redirect: 'manual' });
  return ((res.headers.get('location') || '').match(/click_id=([a-f0-9-]+)/) || [])[1] || null;
}
async function postback(slug, qs) { return fetch(`${BASE}/postback/${slug}?${qs}`, { redirect: 'manual' }); }

(async () => {
  const admin = makeJar();
  await admin.req('POST', '/admin/login', { form: { username: 'admin', password: 'testpass123' } });

  // seed advertiser + publisher + assignment
  await post(admin, '/admin/advertisers',
    { name: 'G2 Adv', slug: 'g2adv', offer_url: 'https://g2.test/o', payout_amount: 10, payout_type: 'fixed',
      click_lookback_window: 90, timezone: 'Asia/Bangkok', currency: 'USD', status: 'active' }, '/admin/advertisers/new');
  await post(admin, '/admin/publishers', { username: 'g2pub', password: 'g2pubpass1', status: 'active' }, '/admin/publishers/new');
  const advId = db.prepare("SELECT id FROM advertisers WHERE slug='g2adv'").get().id;
  const pubId = db.prepare("SELECT id FROM publishers WHERE username='g2pub'").get().id;
  await post(admin, `/admin/publishers/${pubId}/assign`, { advertiser_id: advId }, `/admin/publishers/${pubId}/edit`);

  // ===== #5 partner-link template =====
  const tpl = 'https://t.example/track/g2adv?pub={publisher}&customer_user_id={click_id}&af_siteid={af_siteid}';
  await post(admin, '/admin/advertisers/g2adv/partner-link', { partner_link_template: tpl }, '/admin/advertisers/g2adv/edit');
  ok('#5 partner-link template stored', db.prepare("SELECT partner_link_template FROM advertisers WHERE slug='g2adv'").get().partner_link_template === tpl);
  const editHtml = await txt(await admin.req('GET', '/admin/advertisers/g2adv/edit'));
  ok('#5 edit page shows copy-paste AppsFlyer setup block', editHtml.includes('Copy-paste AppsFlyer setup block') && editHtml.includes('customer_user_id'));

  // ===== #7 event name mapping (affects goal resolution) =====
  await post(admin, '/admin/advertisers/g2adv/goals', { name: 'Bonus', event_token: 'bonus', payout: 40, payout_type: 'fixed', description: '' }, '/admin/advertisers/g2adv/edit');
  await post(admin, '/admin/advertisers/g2adv/event-mappings', { source_event: 'af_bonus', mapped_event: 'bonus' }, '/admin/advertisers/g2adv/edit');
  ok('#7 mapping stored', !!db.prepare("SELECT 1 FROM event_mappings WHERE advertiser_id=? AND source_event='af_bonus'").get(advId));
  const cMap = await track('g2adv', 'g2pub');
  const rMap = await postback('g2adv', `click_id=${cMap}&event=af_bonus`);
  const mapJson = await rMap.json();
  ok('#7 mapped event resolves to Komorebi goal payout (af_bonus→bonus→40)', mapJson.payout === 40, JSON.stringify(mapJson));
  ok('#7 conversion stored with mapped event', db.prepare('SELECT event FROM conversions WHERE click_id=?').get(cMap).event === 'bonus');
  const delId = db.prepare("SELECT id FROM event_mappings WHERE advertiser_id=? AND source_event='af_bonus'").get(advId).id;
  await post(admin, `/admin/advertisers/g2adv/event-mappings/${delId}/delete`, {}, '/admin/advertisers/g2adv/edit');
  ok('#7 mapping deletable', !db.prepare('SELECT 1 FROM event_mappings WHERE id=?').get(delId));

  // ===== #8 postback test tool =====
  const tForm = await txt(await admin.req('GET', '/admin/advertisers/g2adv/postback-test'));
  ok('#8 postback test form renders', tForm.includes('Postback Test Tool') && tForm.includes('Send Test Postback'));
  const cTest = await track('g2adv', 'g2pub');
  const tRes = await txt(await post(admin, '/admin/advertisers/g2adv/postback-test', { click_id: cTest, event: 'sale' }, '/admin/advertisers/g2adv/postback-test'));
  ok('#8 test tool reports HTTP 200 result', tRes.includes('Test Result — HTTP 200'));
  ok('#8 test tool actually created the conversion', !!db.prepare('SELECT 1 FROM conversions WHERE click_id=?').get(cTest));

  // ===== #6 AppsFlyer onboarding docs =====
  const docs = await txt(await admin.req('GET', '/docs'));
  ok('#6 docs has AppsFlyer onboarding walkthrough', docs.includes('AppsFlyer Onboarding Walkthrough'));
  ok('#6 docs has Agency partner + grant event postbacks steps', docs.includes('Agency partner') && docs.includes('Grant event postbacks'));
  ok('#6 docs has HMAC signing section', docs.includes('id="hmac"') && docs.includes('HMAC Postback Signing'));

  // ===== #9 cohort report =====
  const cohort = await fetch(`${BASE}/admin/reports/cohort`, { headers: { Cookie: admin.cookie }, redirect: 'manual' });
  ok('#9 cohort report returns 200', cohort.status === 200);
  const cohortHtml = await txt(cohort);
  ok('#9 cohort report renders + has D0-D28+ buckets + media source row', cohortHtml.includes('Cohort / Retention Report') && cohortHtml.includes('D28+') && cohortHtml.includes('g2pub'));
  const cohortCsv = await fetch(`${BASE}/admin/reports/cohort?format=csv`, { headers: { Cookie: admin.cookie }, redirect: 'manual' });
  ok('#9 cohort CSV export is text/csv', (cohortCsv.headers.get('content-type') || '').includes('text/csv') && (await txt(cohortCsv)).startsWith('media_source,'));

  // ===== #10 pivot report =====
  const pivot = await fetch(`${BASE}/admin/reports/pivot?dim1=publisher&dim2=advertiser`, { headers: { Cookie: admin.cookie }, redirect: 'manual' });
  ok('#10 pivot returns 200', pivot.status === 200);
  const pivotHtml = await txt(pivot);
  ok('#10 pivot renders with two dimensions', pivotHtml.includes('Pivot / Grouped Report') && pivotHtml.includes('g2pub'));
  const pivotCsv = await txt(await fetch(`${BASE}/admin/reports/pivot?dim1=country&format=csv`, { headers: { Cookie: admin.cookie }, redirect: 'manual' }));
  ok('#10 pivot CSV export has header row', pivotCsv.split('\n')[0].includes('Geo') && pivotCsv.includes('conversions'));

  // ===== #11 advertiser portal =====
  await post(admin, '/admin/advertisers/g2adv/portal-password', { portal_password: 'advportal123' }, '/admin/advertisers/g2adv/edit');
  ok('#11 portal password hash stored', !!db.prepare("SELECT portal_password_hash FROM advertisers WHERE slug='g2adv'").get().portal_password_hash);
  const advJar = makeJar();
  const badLogin = await txt(await advJar.req('POST', '/advertiser/login', { form: { username: 'g2adv', password: 'WRONG' } }));
  ok('#11 wrong portal password rejected', badLogin.includes('Invalid advertiser slug or password'));
  const goodLogin = await advJar.req('POST', '/advertiser/login', { form: { username: 'g2adv', password: 'advportal123' } });
  ok('#11 correct portal login → redirect to dashboard', (goodLogin.headers.get('location') || '').includes('/advertiser/dashboard'));
  const advDash = await txt(await advJar.req('GET', '/advertiser/dashboard'));
  ok('#11 advertiser dashboard shows advertiser name + scoped cards', advDash.includes('G2 Adv') && advDash.includes('Conversions'));
  ok('#11 advertiser conversions page loads', (await advJar.req('GET', '/advertiser/conversions')).status === 200);
  ok('#11 advertiser analytics page loads', (await advJar.req('GET', '/advertiser/analytics')).status === 200);
  const advLinks = await txt(await advJar.req('GET', '/advertiser/tracking-links'));
  ok('#11 advertiser tracking-links shows the assigned publisher link', advLinks.includes('/track/g2adv?pub=g2pub'));
  // advertiser cannot reach admin
  const advToAdmin = await advJar.req('GET', '/admin');
  ok('#11 advertiser has NO admin access', (advToAdmin.headers.get('location') || '').includes('/admin/login') || advToAdmin.status === 302);
  // advertiser reconcile upload approves a conversion
  const cRec = await track('g2adv', 'g2pub');
  await postback('g2adv', `click_id=${cRec}&event=sale`);
  {
    const _csrf = await csrf(advJar, '/advertiser/reconcile');
    const fd = new FormData();
    fd.append('_csrf', _csrf);
    fd.append('csv_file', new Blob([`click_id,status\n${cRec},approved\n`], { type: 'text/csv' }), 'r.csv');
    await fetch(`${BASE}/advertiser/reconcile`, { method: 'POST', headers: { Cookie: advJar.cookie }, body: fd, redirect: 'manual' });
  }
  ok('#11 advertiser CSV reconcile approved its conversion', db.prepare('SELECT status FROM conversions WHERE click_id=?').get(cRec).status === 'approved');

  // ===== #12 custom domain per publisher =====
  await post(admin, `/admin/publishers/${pubId}/update`, { status: 'active', minimum_payout: 50, postback_url: '', custom_domain: 'https://go.partner.com/x' }, `/admin/publishers/${pubId}/edit`);
  ok('#12 custom domain normalized to bare host', db.prepare('SELECT custom_domain FROM publishers WHERE id=?').get(pubId).custom_domain === 'go.partner.com');
  const advLinks2 = await txt(await advJar.req('GET', '/advertiser/tracking-links'));
  ok('#12 tracking links use the custom domain', advLinks2.includes('https://go.partner.com/track/g2adv?pub=g2pub'));
  // invalid domain → null
  await post(admin, `/admin/publishers/${pubId}/update`, { status: 'active', minimum_payout: 50, postback_url: '', custom_domain: 'not a domain' }, `/admin/publishers/${pubId}/edit`);
  ok('#12 invalid custom domain stored as null', db.prepare('SELECT custom_domain FROM publishers WHERE id=?').get(pubId).custom_domain === null);

  console.log(`\nPASSED: ${pass}`);
  if (failures.length) { console.log(`FAILED: ${failures.length}`); failures.forEach(f => console.log('  ✗ ' + f)); process.exit(1); }
  console.log('ALL GREEN ✓'); process.exit(0);
})().catch(e => { console.error('HARNESS ERROR:', e); process.exit(2); });
