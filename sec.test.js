'use strict';
// F18/F19 security-hardening end-to-end tests (A–G).
// Boot the server with: ADMIN_IDLE_SECONDS=2 RATE_LIMIT_MAX=100000 POSTBACK_WHITELIST_ENABLED=false
//   SESSION_SECRET=testsecret ADMIN_USER=admin ADMIN_PASS=testpass123 PORT=3999
// then: node sec.test.js

const crypto = require('node:crypto');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const BASE = process.env.E2E_BASE || 'http://localhost:3999';
const db = new DatabaseSync(path.join(__dirname, 'affiliate.db'));
db.exec('PRAGMA busy_timeout = 5000');

let pass = 0; const failures = [];
const ok = (n, c, x = '') => { c ? pass++ : failures.push(n + (x ? ` — ${x}` : '')); };
const sleep = ms => new Promise(r => setTimeout(r, ms));

function makeJar() {
  let cookie = '', lastSetCookie = [];
  return {
    get cookie() { return cookie; }, get lastSetCookie() { return lastSetCookie; },
    async req(method, p, { form, headers = {} } = {}) {
      const h = { ...headers }; if (cookie) h.Cookie = cookie;
      let body; if (form) { body = new URLSearchParams(form).toString(); h['Content-Type'] = 'application/x-www-form-urlencoded'; }
      const res = await fetch(BASE + p, { method, headers: h, body, redirect: 'manual' });
      lastSetCookie = res.headers.getSetCookie?.() || [];
      for (const c of lastSetCookie) {
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
  const admin = makeJar();
  const loginRes = await admin.req('POST', '/admin/login', { form: { username: 'admin', password: 'testpass123' } });

  // ---- A1: SameSite=Strict on the session cookie ----
  const sidCookie = (loginRes.headers.getSetCookie?.() || []).find(c => c.startsWith('connect.sid=')) || '';
  ok('A1 session cookie SameSite=Strict', /SameSite=Strict/i.test(sidCookie), sidCookie);

  // ---- A2: admin idle timeout (server booted with ADMIN_IDLE_SECONDS=2) ----
  ok('A2 admin authed before idle', (await admin.req('GET', '/admin')).status === 200);
  await sleep(2300);
  const afterIdle = await admin.req('GET', '/admin');
  ok('A2 admin auto-logout after idle → redirect to login',
    afterIdle.status === 302 && (afterIdle.headers.get('location') || '').startsWith('/admin/login'));
  // re-login for the rest of the suite
  await admin.req('POST', '/admin/login', { form: { username: 'admin', password: 'testpass123' } });

  // ---- seed: publisher + advertiser with HMAC secret ----
  await adminPost(admin, '/admin/publishers', { username: 'secpub', password: 'secpubpass1', status: 'active' }, '/admin/publishers/new');
  const SECRET = 'topsecret-key';
  await adminPost(admin, '/admin/advertisers',
    { name: 'SecAdv', slug: 'secadv', offer_url: 'https://secadv.test/o', payout_amount: 5, payout_type: 'fixed',
      click_lookback_window: 30, postback_secret: SECRET, status: 'active' }, '/admin/advertisers/new');
  await adminPost(admin, '/admin/advertisers',
    { name: 'PlainAdv', slug: 'plainadv', offer_url: 'https://plainadv.test/o', payout_amount: 5, payout_type: 'fixed',
      click_lookback_window: 30, status: 'active' }, '/admin/advertisers/new');
  const pubId = db.prepare("SELECT id FROM publishers WHERE username='secpub'").get().id;
  const secId = db.prepare("SELECT id FROM advertisers WHERE slug='secadv'").get().id;
  const plainId = db.prepare("SELECT id FROM advertisers WHERE slug='plainadv'").get().id;
  await adminPost(admin, `/admin/publishers/${pubId}/assign`, { advertiser_id: secId }, `/admin/publishers/${pubId}/edit`);
  await adminPost(admin, `/admin/publishers/${pubId}/assign`, { advertiser_id: plainId }, `/admin/publishers/${pubId}/edit`);
  ok('B setup: secret persisted on advertiser', db.prepare("SELECT postback_secret FROM advertisers WHERE slug='secadv'").get().postback_secret === SECRET);

  // ---- B: HMAC postback signature ----
  const cB = await track('secadv', 'secpub');
  const noSig = await fetch(`${BASE}/postback/secadv?click_id=${cB}&event=sale&payout=5`, { redirect: 'manual' });
  ok('B postback without sig → 403', noSig.status === 403);
  const badSig = await fetch(`${BASE}/postback/secadv?click_id=${cB}&event=sale&payout=5&sig=deadbeef`, { redirect: 'manual' });
  ok('B postback with bad sig → 403', badSig.status === 403);
  const goodSig = crypto.createHmac('sha256', SECRET).update(`${cB}:sale:5`).digest('hex');
  const okRes = await fetch(`${BASE}/postback/secadv?click_id=${cB}&event=sale&payout=5&sig=${goodSig}`, { redirect: 'manual' });
  ok('B postback with valid sig → 200', okRes.status === 200);
  // backward compatible: no secret → unsigned accepted
  const cP = await track('plainadv', 'secpub');
  const plainRes = await fetch(`${BASE}/postback/plainadv?click_id=${cP}&event=sale`, { redirect: 'manual' });
  ok('B no-secret advertiser accepts unsigned postback → 200', plainRes.status === 200);

  // ---- C: PII masking in audit log ----
  // advertiser.created logs detail.name → put phone + api key + email in the name
  const pii = '0967123857 kom_live_abcdef123456 john.doe@komorebimedia.com';
  await adminPost(admin, '/admin/advertisers',
    { name: pii, slug: 'piiadv', offer_url: 'https://pii.test/o', payout_amount: 1, payout_type: 'fixed', click_lookback_window: 30, status: 'active' },
    '/admin/advertisers/new');
  const auditRow = db.prepare("SELECT detail FROM audit_log WHERE action='advertiser.created' AND entity_id='piiadv' ORDER BY id DESC LIMIT 1").get();
  const detail = auditRow ? auditRow.detail : '';
  ok('C phone masked (0967***857)', detail.includes('0967***857') && !detail.includes('0967123857'));
  ok('C api key masked (kom_live_***)', detail.includes('kom_live_***') && !detail.includes('kom_live_abcdef123456'));
  ok('C email masked (j***@komorebimedia.com)', detail.includes('j***@komorebimedia.com') && !detail.includes('john.doe@komorebimedia.com'));

  // ---- D: secrets health check ----
  const health = await (await fetch(`${BASE}/health`)).json();
  ok('D health.secrets booleans', health.secrets && health.secrets.SESSION_SECRET === true && health.secrets.ADMIN_PASS === true && health.secrets.GMAIL_USER === false && health.secrets.TELEGRAM_BOT_TOKEN === false);
  ok('D health.secrets has no values (booleans only)', Object.values(health.secrets).every(v => typeof v === 'boolean'));

  // ---- G: security headers ----
  const hres = await fetch(`${BASE}/health`);
  ok('G Permissions-Policy header', hres.headers.get('permissions-policy') === 'interest-cohort=()');
  ok('G HSTS header present', !!hres.headers.get('strict-transport-security'));
  ok('G CSP header present', !!hres.headers.get('content-security-policy'));
  ok('G X-Content-Type-Options nosniff', hres.headers.get('x-content-type-options') === 'nosniff');
  ok('G /health reports active headers', health.security_headers && health.security_headers.permissions_policy === 'interest-cohort=()' && health.security_headers.content_security_policy === true && health.security_headers.strict_transport_security === true);

  // ---- F: input hardening ----
  // oversized field → 400 (use admin login POST; rejected before auth logic)
  const big = 'x'.repeat(2001);
  const oversize = await fetch(`${BASE}/admin/login`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'username=' + big + '&password=y', redirect: 'manual' });
  ok('F field > 2000 chars → 400', oversize.status === 400);
  // null-byte stripped: create advertiser with NUL in name → stored without NUL
  await adminPost(admin, '/admin/advertisers',
    { name: 'Ab cd', slug: 'nulladv', offer_url: 'https://n.test/o', payout_amount: 1, payout_type: 'fixed', click_lookback_window: 30, status: 'active' },
    '/admin/advertisers/new');
  const nm = db.prepare("SELECT name FROM advertisers WHERE slug='nulladv'").get();
  ok('F null byte stripped from POST field', nm && nm.name === 'Abcd' && !nm.name.includes(' '));

  // ---- A (publisher): idle timeout (ADMIN_IDLE_SECONDS=2 applies to publishers too) ----
  {
    const pj = makeJar();
    await pj.req('POST', '/publisher/login', { form: { username: 'secpub', password: 'secpubpass1' } });
    ok('A publisher authed before idle', (await pj.req('GET', '/publisher/dashboard')).status === 200);
    await sleep(2300);
    const after = await pj.req('GET', '/publisher/dashboard');
    ok('A publisher auto-logout after idle → /publisher/login',
      after.status === 302 && (after.headers.get('location') || '').startsWith('/publisher/login'));
  }

  // ---- E: rate limits (run last — they exhaust per-IP counters) ----
  // marketplace/apply: 10/min. Log in as publisher, fire 11.
  const pub = makeJar();
  await pub.req('POST', '/publisher/login', { form: { username: 'secpub', password: 'secpubpass1' } });
  let applyStatuses = [];
  for (let i = 0; i < 11; i++) {
    const r = await pub.req('POST', '/marketplace/apply', { form: { advertiser_id: secId } });
    applyStatuses.push(r.status);
  }
  ok('E /marketplace/apply 10/min → 11th is 429', applyStatuses[10] === 429 && applyStatuses.slice(0, 10).every(s => s !== 429), JSON.stringify(applyStatuses));

  // postback limiter: 300/min, independent of global. Fire 302 to an (invalid) postback; expect a 429 past 300.
  let pbStatuses = [];
  for (let i = 0; i < 302; i++) {
    const r = await fetch(`${BASE}/postback/secadv?click_id=none&event=sale`, { redirect: 'manual' });
    pbStatuses.push(r.status);
  }
  // A handful of /postback requests earlier in this suite already consumed budget,
  // so the first 429 lands at ~300 total (loop index ≈ 300 − prior). Confirm the
  // limit is ~300 (well above the global 100) and that early requests passed.
  const first429 = pbStatuses.indexOf(429);
  ok('E /postback ~300/min limit enforced (independent of global 100)',
    pbStatuses[0] !== 429 && first429 >= 290 && first429 <= 300 && pbStatuses.slice(0, first429).every(s => s !== 429),
    `first429@${first429}`);

  console.log(`\nPASSED: ${pass}`);
  if (failures.length) { console.log(`FAILED: ${failures.length}`); failures.forEach(f => console.log('  ✗ ' + f)); process.exit(1); }
  console.log('ALL GREEN ✓'); process.exit(0);
})().catch(e => { console.error('HARNESS ERROR:', e); process.exit(2); });
