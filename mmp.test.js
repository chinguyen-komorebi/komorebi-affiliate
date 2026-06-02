'use strict';
// F20 — MMP (AppsFlyer) integration tests. Runs a mock AppsFlyer Reports API.
// Boot server with: MMP_ENCRYPTION_KEY=<64hex> MMP_APPSFLYER_BASE=http://localhost:4600
//   RATE_LIMIT_MAX=100000 POSTBACK_WHITELIST_ENABLED=false SESSION_SECRET=x ADMIN_USER=admin ADMIN_PASS=testpass123 PORT=3999

const http = require('node:http');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const BASE = process.env.E2E_BASE || 'http://localhost:3999';
const db = new DatabaseSync(path.join(__dirname, 'affiliate.db'));
db.exec('PRAGMA busy_timeout = 5000');

let pass = 0; const failures = [];
const ok = (n, c, x = '') => { c ? pass++ : failures.push(n + (x ? ` — ${x}` : '')); };

// ---- mock AppsFlyer server (mutable state) ----
const mock = { validToken: 'VALID-TOKEN', csv: 'click_id,status\n' };
const afServer = http.createServer((req, res) => {
  const auth = req.headers.authorization || '';
  if (auth !== `Bearer ${mock.validToken}`) { res.statusCode = 401; return res.end('unauthorized'); }
  res.setHeader('Content-Type', 'text/csv');
  res.end(mock.csv);
});

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

(async () => {
  await new Promise(r => afServer.listen(4600, r));
  const admin = makeJar();
  await admin.req('POST', '/admin/login', { form: { username: 'admin', password: 'testpass123' } });

  // create advertiser with AppsFlyer creds + publisher + assignment
  await adminPost(admin, '/admin/advertisers',
    { name: 'MMPAdv', slug: 'mmpadv', offer_url: 'https://mmp.test/o', payout_amount: 5, payout_type: 'fixed',
      click_lookback_window: 30, mmp_type: 'appsflyer', mmp_app_id: 'app1', mmp_api_token: 'VALID-TOKEN',
      mmp_partner_name: 'Komorebi', status: 'active' },
    '/admin/advertisers/new');
  await adminPost(admin, '/admin/publishers', { username: 'mmppub', password: 'mmppubpass1', status: 'active' }, '/admin/publishers/new');
  const advId = db.prepare("SELECT id FROM advertisers WHERE slug='mmpadv'").get().id;
  const pubId = db.prepare("SELECT id FROM publishers WHERE username='mmppub'").get().id;
  await adminPost(admin, `/admin/publishers/${pubId}/assign`, { advertiser_id: advId }, `/admin/publishers/${pubId}/edit`);

  // ---- encryption at rest ----
  const stored = db.prepare("SELECT mmp_api_token FROM advertisers WHERE slug='mmpadv'").get().mmp_api_token;
  ok('encrypted token at rest (enc:v1 prefix, not plaintext)', stored.startsWith('enc:v1:') && !stored.includes('VALID-TOKEN'), stored.slice(0, 16));
  // H2: edit page must NOT contain the decrypted token; field is empty with a "(saved)" placeholder.
  const editHtml = await txt(await admin.req('GET', '/admin/advertisers/mmpadv/edit'));
  ok('H2 edit page does not leak token (empty field + (saved) placeholder)',
    !editHtml.includes('VALID-TOKEN') && /id="mmptoken" name="mmp_api_token" value=""/.test(editHtml) && editHtml.includes('(saved) — leave blank to keep'));

  // ---- test connection ----
  const testRes = await adminPost(admin, '/admin/advertisers/mmpadv/mmp-test', {}, '/admin/advertisers/mmpadv/edit');
  ok('mmp-test valid creds → ok=1', (testRes.headers.get('location') || '').includes('ok=1'));
  // invalid token → 401 from mock
  await adminPost(admin, '/admin/advertisers/mmpadv/update',
    { name: 'MMPAdv', offer_url: 'https://mmp.test/o', payout_amount: 5, payout_type: 'fixed', click_lookback_window: 30,
      mmp_type: 'appsflyer', mmp_app_id: 'app1', mmp_api_token: 'BAD-TOKEN', mmp_partner_name: 'Komorebi', status: 'active' },
    '/admin/advertisers/mmpadv/edit');
  const testBad = await adminPost(admin, '/admin/advertisers/mmpadv/mmp-test', {}, '/admin/advertisers/mmpadv/edit');
  ok('mmp-test invalid creds → ok=0', (testBad.headers.get('location') || '').includes('ok=0'));
  // restore valid token
  await adminPost(admin, '/admin/advertisers/mmpadv/update',
    { name: 'MMPAdv', offer_url: 'https://mmp.test/o', payout_amount: 5, payout_type: 'fixed', click_lookback_window: 30,
      mmp_type: 'appsflyer', mmp_app_id: 'app1', mmp_api_token: 'VALID-TOKEN', mmp_partner_name: 'Komorebi', status: 'active' },
    '/admin/advertisers/mmpadv/edit');
  // partner/agency name round-trips through the form and persists in the DB
  ok('mmp_partner_name saved + persists across updates',
    db.prepare("SELECT mmp_partner_name FROM advertisers WHERE slug='mmpadv'").get().mmp_partner_name === 'Komorebi');
  const editHtml2 = await txt(await admin.req('GET', '/admin/advertisers/mmpadv/edit'));
  ok('edit page renders saved Partner / Agency Name', /name="mmp_partner_name" value="Komorebi"/.test(editHtml2));

  // ---- create pending conversions, then sync ----
  const cA = await track('mmpadv', 'mmppub'); await fetch(`${BASE}/postback/mmpadv?click_id=${cA}&event=sale`, { redirect: 'manual' });
  const cB = await track('mmpadv', 'mmppub'); await fetch(`${BASE}/postback/mmpadv?click_id=${cB}&event=sale`, { redirect: 'manual' });
  const cC = await track('mmpadv', 'mmppub'); await fetch(`${BASE}/postback/mmpadv?click_id=${cC}&event=sale`, { redirect: 'manual' });
  ok('3 pending conversions created',
    db.prepare("SELECT COUNT(*) n FROM conversions WHERE advertiser_slug='mmpadv' AND status='pending'").get().n === 3);

  mock.csv = `click_id,status\n${cA},attributed\n${cB},organic\n${cC},fraud\nno-match-xyz,attributed\n`;
  const runRes = await adminPost(admin, '/admin/advertisers/mmpadv/mmp-sync/run', {}, '/admin/advertisers/mmpadv/mmp-sync');
  ok('mmp-sync/run → ok=1 redirect', (runRes.headers.get('location') || '').includes('ok=1'));

  const stA = db.prepare('SELECT status, reason FROM conversions WHERE click_id=?').get(cA);
  const stB = db.prepare('SELECT status, reason FROM conversions WHERE click_id=?').get(cB);
  const stC = db.prepare('SELECT status, reason FROM conversions WHERE click_id=?').get(cC);
  ok('sync auto-approve attributed', stA.status === 'approved' && stA.reason === 'mmp_attributed');
  ok('sync auto-reject organic', stB.status === 'rejected' && stB.reason === 'mmp_rejected');
  ok('sync auto-reject fraud', stC.status === 'rejected' && stC.reason === 'mmp_rejected');

  const log = db.prepare("SELECT * FROM mmp_sync_log WHERE advertiser_slug='mmpadv' ORDER BY id DESC LIMIT 1").get();
  ok('sync log: pulled=4 matched=3 approved=1 rejected=2 success',
    log.events_pulled === 4 && log.matched === 3 && log.auto_approved === 1 && log.auto_rejected === 2 && log.status === 'success',
    JSON.stringify({ p: log.events_pulled, m: log.matched, a: log.auto_approved, r: log.auto_rejected, s: log.status }));
  ok('sync log records unmatched event in errors', !!log.errors && log.errors.includes('no-match-xyz'));

  // re-sync should not re-decide already-decided conversions (idempotent on status)
  const runRes2 = await adminPost(admin, '/admin/advertisers/mmpadv/mmp-sync/run', {}, '/admin/advertisers/mmpadv/mmp-sync');
  const log2 = db.prepare("SELECT * FROM mmp_sync_log WHERE advertiser_slug='mmpadv' ORDER BY id DESC LIMIT 1").get();
  ok('re-sync matches but approves/rejects 0 (already decided)', log2.matched === 3 && log2.auto_approved === 0 && log2.auto_rejected === 0);

  // ---- QA1: REAL AppsFlyer raw export columns (customer_user_id + media_source + partner) ----
  // Non-organic only auto-approves when the Partner column == the advertiser's
  // mmp_partner_name ('Komorebi'); a different/blank partner is flagged 'mmp_not_komorebi'.
  const cR1 = await track('mmpadv', 'mmppub'); await fetch(`${BASE}/postback/mmpadv?click_id=${cR1}&event=sale`, { redirect: 'manual' });
  const cR2 = await track('mmpadv', 'mmppub'); await fetch(`${BASE}/postback/mmpadv?click_id=${cR2}&event=sale`, { redirect: 'manual' });
  const cR3 = await track('mmpadv', 'mmppub'); await fetch(`${BASE}/postback/mmpadv?click_id=${cR3}&event=sale`, { redirect: 'manual' });
  mock.csv = `appsflyer_id,customer_user_id,event_name,event_time,media_source,campaign,partner\n`
    + `af-aaa,${cR1},af_purchase,2026-06-01 10:00:00,facebook,camp_x,Komorebi\n`
    + `af-bbb,${cR2},af_purchase,2026-06-01 11:00:00,organic,,\n`
    + `af-ccc,${cR3},af_purchase,2026-06-01 12:00:00,facebook,camp_z,Facebook\n`;
  await adminPost(admin, '/admin/advertisers/mmpadv/mmp-sync/run', {}, '/admin/advertisers/mmpadv/mmp-sync');
  const qR1 = db.prepare('SELECT status,reason FROM conversions WHERE click_id=?').get(cR1);
  const qR2 = db.prepare('SELECT status,reason FROM conversions WHERE click_id=?').get(cR2);
  const qR3 = db.prepare('SELECT status,reason FROM conversions WHERE click_id=?').get(cR3);
  ok('QA1 non-organic + partner matches Komorebi → approved', qR1.status === 'approved' && qR1.reason === 'mmp_attributed', JSON.stringify(qR1));
  ok('QA1 organic → rejected', qR2.status === 'rejected' && qR2.reason === 'mmp_rejected', JSON.stringify(qR2));
  ok('QA1 non-organic + partner is NOT Komorebi → flagged mmp_not_komorebi', qR3.status === 'pending' && qR3.reason === 'mmp_not_komorebi', JSON.stringify(qR3));
  const rlog = db.prepare("SELECT * FROM mmp_sync_log WHERE advertiser_slug='mmpadv' ORDER BY id DESC LIMIT 1").get();
  ok('QA1 sync log: pulled=3 matched=3 approved=1 rejected=1 flagged=1', rlog.events_pulled === 3 && rlog.matched === 3 && rlog.auto_approved === 1 && rlog.auto_rejected === 1 && rlog.flagged === 1,
    JSON.stringify({ p: rlog.events_pulled, m: rlog.matched, a: rlog.auto_approved, r: rlog.auto_rejected, f: rlog.flagged }));

  // ---- QA2: ACTUAL AppsFlyer export header casing — Title Case with spaces, incl. "Partner" ----
  // The real export ships "Customer User ID","Media Source","Partner",… (not snake_case).
  // parseCSV normalizes headers, so the same attribution must hold. Covers all four
  // outcomes: approved (partner match), rejected (organic), and the two flag reasons
  // (restricted, and non-organic with no/other partner → mmp_not_komorebi).
  const cT1 = await track('mmpadv', 'mmppub'); await fetch(`${BASE}/postback/mmpadv?click_id=${cT1}&event=sale`, { redirect: 'manual' });
  const cT2 = await track('mmpadv', 'mmppub'); await fetch(`${BASE}/postback/mmpadv?click_id=${cT2}&event=sale`, { redirect: 'manual' });
  const cT3 = await track('mmpadv', 'mmppub'); await fetch(`${BASE}/postback/mmpadv?click_id=${cT3}&event=sale`, { redirect: 'manual' });
  const cT4 = await track('mmpadv', 'mmppub'); await fetch(`${BASE}/postback/mmpadv?click_id=${cT4}&event=sale`, { redirect: 'manual' });
  mock.csv = `AppsFlyer ID,Customer User ID,Event Name,Event Time,Media Source,Campaign,Adset,Ad,Site ID,Partner\n`
    + `af-t1,${cT1},af_purchase,2026-06-01 10:00:00,facebook,camp_x,set_a,ad_1,site_9,Komorebi\n`
    + `af-t2,${cT2},af_purchase,2026-06-01 11:00:00,organic,,,,,\n`
    + `af-t3,${cT3},af_purchase,2026-06-01 12:00:00,restricted,,,,,\n`
    + `af-t4,${cT4},af_purchase,2026-06-01 13:00:00,googleads,,,,,\n`;
  await adminPost(admin, '/admin/advertisers/mmpadv/mmp-sync/run', {}, '/admin/advertisers/mmpadv/mmp-sync');
  const tA = db.prepare('SELECT status,reason FROM conversions WHERE click_id=?').get(cT1);
  const tO = db.prepare('SELECT status,reason FROM conversions WHERE click_id=?').get(cT2);
  const tR = db.prepare('SELECT status,reason FROM conversions WHERE click_id=?').get(cT3);
  const tN = db.prepare('SELECT status,reason FROM conversions WHERE click_id=?').get(cT4);
  ok('QA2 Title Case + partner match → approved', tA.status === 'approved' && tA.reason === 'mmp_attributed', JSON.stringify(tA));
  ok('QA2 Title Case organic → rejected', tO.status === 'rejected' && tO.reason === 'mmp_rejected', JSON.stringify(tO));
  ok('QA2 restricted Media Source → flagged mmp_restricted', tR.status === 'pending' && tR.reason === 'mmp_restricted', JSON.stringify(tR));
  ok('QA2 non-organic + no/other partner → flagged mmp_not_komorebi', tN.status === 'pending' && tN.reason === 'mmp_not_komorebi', JSON.stringify(tN));
  const tlog = db.prepare("SELECT * FROM mmp_sync_log WHERE advertiser_slug='mmpadv' ORDER BY id DESC LIMIT 1").get();
  ok('QA2 sync log: pulled=4 matched=4 approved=1 rejected=1 flagged=2',
    tlog.events_pulled === 4 && tlog.matched === 4 && tlog.auto_approved === 1 && tlog.auto_rejected === 1 && tlog.flagged === 2,
    JSON.stringify({ p: tlog.events_pulled, m: tlog.matched, a: tlog.auto_approved, r: tlog.auto_rejected, f: tlog.flagged }));

  // ---- CSV upload: reconcile an uploaded AppsFlyer export (multipart, source='csv_upload') ----
  // Mirrors a real downloaded export filename; no API token is used for this path. The
  // partner gate (PR #2) applies here too — non-organic only approves when the Partner
  // column matches the advertiser's mmp_partner_name ('Komorebi'); otherwise mmp_not_komorebi.
  const cU1 = await track('mmpadv', 'mmppub'); await fetch(`${BASE}/postback/mmpadv?click_id=${cU1}&event=sale`, { redirect: 'manual' });
  const cU2 = await track('mmpadv', 'mmppub'); await fetch(`${BASE}/postback/mmpadv?click_id=${cU2}&event=sale`, { redirect: 'manual' });
  const cU3 = await track('mmpadv', 'mmppub'); await fetch(`${BASE}/postback/mmpadv?click_id=${cU3}&event=sale`, { redirect: 'manual' });
  const cU4 = await track('mmpadv', 'mmppub'); await fetch(`${BASE}/postback/mmpadv?click_id=${cU4}&event=sale`, { redirect: 'manual' });
  const uploadCsv = `AppsFlyer ID,Customer User ID,Event Name,Event Time,Media Source,Campaign,Partner\n`
    + `af-u1,${cU1},af_purchase,2025-09-12 10:00:00,facebook,camp,Komorebi\n`
    + `af-u2,${cU2},af_purchase,2025-09-12 11:00:00,organic,,\n`
    + `af-u3,${cU3},af_purchase,2025-09-12 12:00:00,restricted,,\n`
    + `af-u4,${cU4},af_purchase,2025-09-12 13:00:00,bytedance_int,camp,SomeOtherAgency\n`;
  const upTok = await csrf(admin, '/admin/advertisers/mmpadv/mmp-sync');
  const fd = new FormData();
  fd.append('_csrf', upTok);
  fd.append('csv_file', new Blob([uploadCsv], { type: 'text/csv' }), 'id1633169952_in_app_events_postbacks_2025_09_12_2025_09_19_Asia.csv');
  const upRes = await fetch(`${BASE}/admin/advertisers/mmpadv/mmp-sync/upload-csv`, { method: 'POST', headers: { Cookie: admin.cookie }, body: fd, redirect: 'manual' });
  ok('CSV upload → redirect ok=1', (upRes.headers.get('location') || '').includes('ok=1'), String(upRes.status));
  const uU1 = db.prepare('SELECT status,reason FROM conversions WHERE click_id=?').get(cU1);
  const uU2 = db.prepare('SELECT status,reason FROM conversions WHERE click_id=?').get(cU2);
  const uU3 = db.prepare('SELECT status,reason FROM conversions WHERE click_id=?').get(cU3);
  const uU4 = db.prepare('SELECT status,reason FROM conversions WHERE click_id=?').get(cU4);
  ok('CSV upload: non-organic + partner matches → approved', uU1.status === 'approved' && uU1.reason === 'mmp_attributed', JSON.stringify(uU1));
  ok('CSV upload: organic → rejected', uU2.status === 'rejected' && uU2.reason === 'mmp_rejected', JSON.stringify(uU2));
  ok('CSV upload: restricted → flagged pending', uU3.status === 'pending' && uU3.reason === 'mmp_restricted', JSON.stringify(uU3));
  ok('CSV upload: non-organic + partner != mmp_partner_name → pending mmp_not_komorebi', uU4.status === 'pending' && uU4.reason === 'mmp_not_komorebi', JSON.stringify(uU4));
  const ulog = db.prepare("SELECT * FROM mmp_sync_log WHERE advertiser_slug='mmpadv' ORDER BY id DESC LIMIT 1").get();
  ok('CSV upload logged with source=csv_upload + counts',
    ulog.source === 'csv_upload' && ulog.events_pulled === 4 && ulog.matched === 4 && ulog.auto_approved === 1 && ulog.auto_rejected === 1 && ulog.flagged === 2,
    JSON.stringify({ src: ulog.source, p: ulog.events_pulled, m: ulog.matched, a: ulog.auto_approved, r: ulog.auto_rejected, f: ulog.flagged }));
  const fdNoCsrf = new FormData();
  fdNoCsrf.append('csv_file', new Blob([uploadCsv], { type: 'text/csv' }), 'x.csv');
  const upNoCsrf = await fetch(`${BASE}/admin/advertisers/mmpadv/mmp-sync/upload-csv`, { method: 'POST', headers: { Cookie: admin.cookie }, body: fdNoCsrf, redirect: 'manual' });
  ok('CSV upload without CSRF → 403', upNoCsrf.status === 403);

  // ---- sync failure path (bad token → mock 401) ----
  await adminPost(admin, '/admin/advertisers/mmpadv/update',
    { name: 'MMPAdv', offer_url: 'https://mmp.test/o', payout_amount: 5, payout_type: 'fixed', click_lookback_window: 30,
      mmp_type: 'appsflyer', mmp_app_id: 'app1', mmp_api_token: 'BAD-TOKEN', mmp_partner_name: 'Komorebi', status: 'active' },
    '/admin/advertisers/mmpadv/edit');
  await adminPost(admin, '/admin/advertisers/mmpadv/mmp-sync/run', {}, '/admin/advertisers/mmpadv/mmp-sync');
  const failLog = db.prepare("SELECT * FROM mmp_sync_log WHERE advertiser_slug='mmpadv' ORDER BY id DESC LIMIT 1").get();
  ok('sync failure logged as failed with error', failLog.status === 'failed' && !!failLog.errors);

  // ---- dashboard renders log entries ----
  const dash = await txt(await admin.req('GET', '/admin/advertisers/mmpadv/mmp-sync'));
  ok('sync dashboard renders runs + Run Sync button', dash.includes('MMP Sync') && dash.includes('Run Sync Now'));

  afServer.close();
  console.log(`\nPASSED: ${pass}`);
  if (failures.length) { console.log(`FAILED: ${failures.length}`); failures.forEach(f => console.log('  ✗ ' + f)); process.exit(1); }
  console.log('ALL GREEN ✓'); process.exit(0);
})().catch(e => { console.error('HARNESS ERROR:', e); process.exit(2); });
