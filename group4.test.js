'use strict';
// Group 4 — Smart Links + Marketplace. Drives the running server over HTTP.
// Boot like the other suites (PORT=3999, ADMIN_PASS=testpass123) then: node group4.test.js
// Covers: (1) smart link routes by GEO, (2) no matching rule -> 404, (3) click recorded
// with smart_link_slug, (4) admin listing visible to publisher, (5) publisher apply seen
// by admin, (6) admin approve -> publisher gets advertiser access.

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
    async req(m, p, { form, headers = {} } = {}) {
      const h = { ...headers }; if (cookie) h.Cookie = cookie;
      let body; if (form) { body = new URLSearchParams(form).toString(); h['Content-Type'] = 'application/x-www-form-urlencoded'; }
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

(async () => {
  const admin = makeJar();
  await admin.req('POST', '/admin/login', { form: { username: 'admin', password: 'testpass123' } });
  // advertisers + publisher
  for (const [slug, name] of [['g4a', 'G4 Adv A'], ['g4b', 'G4 Adv B']]) {
    await post(admin, '/admin/advertisers',
      { name, slug, offer_url: `https://${slug}.test/o`, payout_amount: 10, payout_type: 'fixed', click_lookback_window: 90, status: 'active' },
      '/admin/advertisers/new');
  }
  await post(admin, '/admin/publishers', { username: 'g4p', password: 'g4ppass12', status: 'active' }, '/admin/publishers/new');
  const advAId = db.prepare("SELECT id FROM advertisers WHERE slug='g4a'").get().id;
  const pubId  = db.prepare("SELECT id FROM publishers WHERE username='g4p'").get().id;

  // ===== Smart Links =====
  // link with a GEO rule that matches localhost (country 'XX'), routing to g4a; plus a
  // catch-all fallback to g4b at lower priority.
  await post(admin, '/admin/smart-links', { name: 'G4 SL', slug: 'g4sl' }, '/admin/smart-links/new');
  const slId = db.prepare("SELECT id FROM smart_links WHERE slug='g4sl'").get().id;
  await post(admin, `/admin/smart-links/${slId}/rules`, { geo: 'VN', advertiser_slug: 'g4a', priority: 0 }, `/admin/smart-links/${slId}`); // won't match localhost
  await post(admin, `/admin/smart-links/${slId}/rules`, { geo: 'XX', advertiser_slug: 'g4b', priority: 1 }, `/admin/smart-links/${slId}`); // matches localhost (XX)
  const r1 = await fetch(`${BASE}/smart/g4sl?pub=g4p`, { redirect: 'manual' });
  const loc = r1.headers.get('location') || '';
  ok('(1) smart link routes by GEO (VN skipped, XX → g4b)', r1.status === 302 && loc.startsWith('https://g4b.test/o') && /click_id=/.test(loc), `${r1.status} ${loc}`);
  const clickId = (loc.match(/click_id=([a-f0-9-]+)/) || [])[1];

  // (3) click recorded with smart_link_slug
  const clickRow = db.prepare('SELECT advertiser_slug, publisher, smart_link_slug FROM clicks WHERE click_id=?').get(clickId);
  ok('(3) click recorded with smart_link_slug + chosen advertiser/publisher',
    !!clickRow && clickRow.smart_link_slug === 'g4sl' && clickRow.advertiser_slug === 'g4b' && clickRow.publisher === 'g4p', JSON.stringify(clickRow));

  // (2) no matching rule → 404
  await post(admin, '/admin/smart-links', { name: 'G4 None', slug: 'g4none' }, '/admin/smart-links/new');
  const noneId = db.prepare("SELECT id FROM smart_links WHERE slug='g4none'").get().id;
  await post(admin, `/admin/smart-links/${noneId}/rules`, { geo: 'VN', advertiser_slug: 'g4a' }, `/admin/smart-links/${noneId}`); // VN never matches localhost
  const r404 = await fetch(`${BASE}/smart/g4none?pub=g4p`, { redirect: 'manual' });
  ok('(2) no matching rule → 404', r404.status === 404, `status=${r404.status}`);
  ok('(2b) unknown smart link → 404', (await fetch(`${BASE}/smart/does-not-exist?pub=g4p`, { redirect: 'manual' })).status === 404);

  // ===== Marketplace =====
  // (4) admin creates listing → publisher sees it
  await post(admin, '/admin/marketplace-listings',
    { title: 'G4 Offer', advertiser_slug: 'g4a', payout_display: '3.5% CPS', category: 'fintech', geo: 'VN', status: 'active' },
    '/admin/marketplace-listings');
  const listingId = db.prepare("SELECT id FROM marketplace_listings WHERE title='G4 Offer'").get().id;

  const pubJar = makeJar();
  await pubJar.req('POST', '/publisher/login', { form: { username: 'g4p', password: 'g4ppass12' } });
  const mp = await txt(await pubJar.req('GET', '/publisher/marketplace'));
  ok('(4) publisher sees the new listing (no access yet)', mp.includes('G4 Offer') && mp.includes('3.5% CPS'));

  // (5) publisher applies → admin sees application
  await post(pubJar, `/publisher/marketplace/${listingId}/apply`, {}, '/publisher/marketplace');
  const appRow = db.prepare("SELECT * FROM marketplace_apps WHERE listing_id=? AND publisher='g4p'").get(listingId);
  ok('(5) application created (pending)', !!appRow && appRow.status === 'pending', JSON.stringify(appRow));
  const adminApps = await txt(await admin.req('GET', `/admin/marketplace-listings/${listingId}/applications`));
  ok('(5b) admin sees the application', adminApps.includes('g4p') && adminApps.includes('Approve'));
  // publisher my-applications shows it pending
  const myApps = await txt(await pubJar.req('GET', '/publisher/marketplace/my-applications'));
  ok('(5c) publisher my-applications shows pending', myApps.includes('G4 Offer') && /pending/.test(myApps));

  // (6) admin approves → publisher gets advertiser access (publisher_advertisers)
  const hadAccessBefore = !!db.prepare('SELECT 1 FROM publisher_advertisers WHERE publisher_id=? AND advertiser_id=?').get(pubId, advAId);
  await post(admin, `/admin/marketplace-listings/${listingId}/applications/${appRow.id}/approve`, {}, `/admin/marketplace-listings/${listingId}/applications`);
  const appAfter = db.prepare('SELECT status FROM marketplace_apps WHERE id=?').get(appRow.id);
  const hasAccess = !!db.prepare('SELECT 1 FROM publisher_advertisers WHERE publisher_id=? AND advertiser_id=?').get(pubId, advAId);
  ok('(6) approve sets status approved + grants access', appAfter.status === 'approved' && !hadAccessBefore && hasAccess, JSON.stringify({ appAfter, hasAccess }));
  // listing no longer shown to the publisher (they now have access)
  const mp2 = await txt(await pubJar.req('GET', '/publisher/marketplace'));
  ok('(6b) approved listing drops out of publisher browse', !mp2.includes('G4 Offer'));

  console.log(`\nPASSED: ${pass}`);
  if (failures.length) { console.log(`FAILED: ${failures.length}`); failures.forEach(f => console.log('  ✗ ' + f)); process.exit(1); }
  console.log('ALL GREEN ✓'); process.exit(0);
})().catch(e => { console.error('HARNESS ERROR:', e); process.exit(2); });
