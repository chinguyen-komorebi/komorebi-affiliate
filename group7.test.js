'use strict';
// Group 7 — commission tiers, publisher notifications, advertiser self-onboarding,
// scheduled weekly reports, sidebar fix, mobile scroll affordance.
// HTTP harness (same style as the other suites). Boot the server first; pass
// E2E_BASE to point at it (defaults to :4007).
//   1 sidebar labels  2 tiers CRUD  3 tier payout in postback  4 advertiser apply
//   5 admin approve/reject application (+ auto-create advertiser)
//   6 publisher email on approve (conversion + marketplace) + toggle gating
//   7 settings toggles  8 weekly report runs

const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const BASE = process.env.E2E_BASE || 'http://localhost:4007';
const db = new DatabaseSync(path.join(__dirname, 'affiliate.db'));
db.exec('PRAGMA busy_timeout = 5000');

let pass = 0; const failures = [];
const ok = (n, c, x = '') => { c ? pass++ : failures.push(n + (x ? ` — ${x}` : '')); };

function makeJar() {
  let cookie = '';
  return { get cookie() { return cookie; },
    async req(m, p, { form, headers = {} } = {}) {
      const h = { ...headers }; if (cookie) h.Cookie = cookie;
      let body;
      if (form) { body = new URLSearchParams(form).toString(); h['Content-Type'] = 'application/x-www-form-urlencoded'; }
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
const track = async (qs) => ((((await fetch(`${BASE}/track/${qs}`, { redirect: 'manual' })).headers.get('location')) || '').match(/click_id=([a-f0-9-]+)/) || [])[1] || null;
const postback = (slug, qs) => fetch(`${BASE}/postback/${slug}?${qs}`, { redirect: 'manual' });
const convByClick = c => db.prepare('SELECT * FROM conversions WHERE click_id = ?').get(c);
const notifCount = (pub, type) => db.prepare('SELECT COUNT(*) n FROM publisher_notifications WHERE publisher=? AND type=?').get(pub, type).n;

(async () => {
  const admin = makeJar();
  await admin.req('POST', '/admin/login', { form: { username: 'admin', password: 'testpass123' } });

  // advertiser g7adv (default payout 5) + publisher g7pub (with email), assigned.
  await post(admin, '/admin/advertisers',
    { name: 'G7 Adv', slug: 'g7adv', offer_url: 'https://g7adv.test/o', payout_amount: 5, payout_type: 'fixed', click_lookback_window: 90, currency: 'USD', status: 'active' },
    '/admin/advertisers/new');
  await post(admin, '/admin/publishers', { username: 'g7pub', password: 'g7pubpass1', status: 'active' }, '/admin/publishers/new');
  db.prepare("UPDATE publishers SET email='g7pub@test.com' WHERE username='g7pub'").run();
  const pubId = db.prepare("SELECT id FROM publishers WHERE username='g7pub'").get().id;
  const advId = db.prepare("SELECT id FROM advertisers WHERE slug='g7adv'").get().id;
  await post(admin, `/admin/publishers/${pubId}/assign`, { advertiser_id: advId }, `/admin/publishers/${pubId}/edit`);

  // ===== (1) sidebar labels =====
  const dash = await txt(await admin.req('GET', '/admin'));
  ok('(1) sidebar has "Marketplace Listings"', dash.includes('Marketplace Listings'));
  ok('(1) sidebar has "Marketplace Apps"', dash.includes('Marketplace Apps'));

  // ===== (2) tiers CRUD (on a dedicated advertiser to avoid payout interference) =====
  await post(admin, '/admin/advertisers',
    { name: 'G7 Tier Adv', slug: 'g7tieradv', offer_url: 'https://g7t.test/o', payout_amount: 4, payout_type: 'fixed', click_lookback_window: 90, currency: 'USD', status: 'active' },
    '/admin/advertisers/new');
  await post(admin, '/admin/advertisers/g7tieradv/tiers', { min_conversions: 5, payout_rate: 12.5, currency: 'USD' }, '/admin/advertisers/g7tieradv/tiers');
  const tier = db.prepare("SELECT * FROM commission_tiers WHERE advertiser_slug='g7tieradv'").get();
  ok('(2) tier created via route', tier && tier.min_conversions === 5 && tier.payout_rate === 12.5, JSON.stringify(tier));
  const tiersPage = await txt(await admin.req('GET', '/admin/advertisers/g7tieradv/tiers'));
  ok('(2) tiers page lists the tier', tiersPage.includes('12.5') || tiersPage.includes('12.50'));
  await post(admin, `/admin/advertisers/g7tieradv/tiers/${tier.id}/delete`, {}, '/admin/advertisers/g7tieradv/tiers');
  ok('(2) tier deleted', !db.prepare('SELECT 1 FROM commission_tiers WHERE id=?').get(tier.id));

  // ===== (3) tier payout logic in postback =====
  // tier(min=0,rate=7) applies immediately; tier(min=2,rate=9) once 2 approved.
  await post(admin, '/admin/advertisers/g7adv/tiers', { min_conversions: 0, payout_rate: 7, currency: 'USD' }, '/admin/advertisers/g7adv/tiers');
  const c1 = await track('g7adv?pub=g7pub');
  await postback('g7adv', `click_id=${c1}&event=sale`);
  ok('(3) tier(min0) overrides advertiser default (7 not 5)', convByClick(c1).payout === 7, JSON.stringify(convByClick(c1)));
  const c2 = await track('g7adv?pub=g7pub');
  await postback('g7adv', `click_id=${c2}&event=sale`);
  await post(admin, '/admin/advertisers/g7adv/tiers', { min_conversions: 2, payout_rate: 9, currency: 'USD' }, '/admin/advertisers/g7adv/tiers');
  // approve the first two so approvedCount reaches 2
  db.prepare("UPDATE conversions SET status='approved' WHERE click_id IN (?, ?)").run(c1, c2);
  const c3 = await track('g7adv?pub=g7pub');
  await postback('g7adv', `click_id=${c3}&event=sale`);
  ok('(3) highest reached tier(min2) applies (9)', convByClick(c3).payout === 9, JSON.stringify(convByClick(c3)));

  // ===== (4) advertiser self-onboarding form =====
  const applyPage = await txt(await fetch(`${BASE}/advertiser/apply`, { redirect: 'manual' }));
  ok('(4) apply page renders form fields', applyPage.includes('name="name"') && applyPage.includes('name="email"') && applyPage.includes('name="website"') && applyPage.includes('name="notes"'));
  const applyRes = await fetch(`${BASE}/advertiser/apply`, {
    method: 'POST', redirect: 'manual',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ name: 'Acme Onboard Co', email: 'biz@acme.test', website: 'https://acme.test', notes: 'VN fintech CPS' }).toString(),
  });
  ok('(4) apply POST redirects to submitted', (applyRes.headers.get('location') || '').includes('submitted=1'), String(applyRes.status));
  const appRow = db.prepare("SELECT * FROM advertiser_applications WHERE email='biz@acme.test'").get();
  ok('(4) application stored pending', appRow && appRow.status === 'pending', JSON.stringify(appRow));

  // ===== (5) admin approve/reject + auto-create advertiser =====
  const appsPage = await txt(await admin.req('GET', '/admin/advertiser-applications'));
  ok('(5) admin applications list shows the application', appsPage.includes('Acme Onboard Co'));
  await post(admin, `/admin/advertiser-applications/${appRow.id}/approve`, {}, '/admin/advertiser-applications');
  ok('(5) application marked approved', db.prepare('SELECT status FROM advertiser_applications WHERE id=?').get(appRow.id).status === 'approved');
  const newAdv = db.prepare("SELECT * FROM advertisers WHERE slug='acme-onboard-co'").get();
  ok('(5) advertiser auto-created with slug from name', !!newAdv && newAdv.status === 'active', JSON.stringify(newAdv));
  ok('(5) advertiser description holds the application email', newAdv && newAdv.description === 'biz@acme.test');
  // reject another
  await fetch(`${BASE}/advertiser/apply`, { method: 'POST', redirect: 'manual', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ name: 'Reject Me Ltd', email: 'no@reject.test' }).toString() });
  const rj = db.prepare("SELECT id FROM advertiser_applications WHERE email='no@reject.test'").get();
  await post(admin, `/admin/advertiser-applications/${rj.id}/reject`, {}, '/admin/advertiser-applications');
  ok('(5) application rejected', db.prepare('SELECT status FROM advertiser_applications WHERE id=?').get(rj.id).status === 'rejected');

  // ===== (6) publisher email on approve (+ toggle gating) =====
  // conversion approved → notification
  const cn = await track('g7adv?pub=g7pub');
  await postback('g7adv', `click_id=${cn}&event=sale`);
  const cnId = convByClick(cn).id;
  const before = notifCount('g7pub', 'conversion_approved');
  await post(admin, `/admin/conversions/${cnId}/status`, { status: 'approved' }, '/admin');
  ok('(6) conversion approval emails the publisher', notifCount('g7pub', 'conversion_approved') === before + 1);

  // toggle OFF gates the notification
  db.prepare("UPDATE settings SET value='false' WHERE key='notify_conversion_approved'").run();
  const cn2 = await track('g7adv?pub=g7pub');
  await postback('g7adv', `click_id=${cn2}&event=sale`);
  const cn2Id = convByClick(cn2).id;
  const before2 = notifCount('g7pub', 'conversion_approved');
  await post(admin, `/admin/conversions/${cn2Id}/status`, { status: 'approved' }, '/admin');
  ok('(6) toggle OFF suppresses the notification', notifCount('g7pub', 'conversion_approved') === before2);
  db.prepare("UPDATE settings SET value='true' WHERE key='notify_conversion_approved'").run();

  // marketplace application approved → notification
  db.prepare("INSERT INTO marketplace_listings (advertiser_slug, title, status) VALUES ('g7adv','G7 Offer','active')").run();
  const lid = db.prepare("SELECT id FROM marketplace_listings WHERE title='G7 Offer'").get().id;
  db.prepare("INSERT INTO marketplace_apps (listing_id, publisher, status) VALUES (?, 'g7pub', 'pending')").run(lid);
  const aid = db.prepare('SELECT id FROM marketplace_apps WHERE listing_id=? AND publisher=?').get(lid, 'g7pub').id;
  const mbefore = notifCount('g7pub', 'marketplace_approved');
  await post(admin, `/admin/marketplace-listings/${lid}/applications/${aid}/approve`, {}, `/admin/marketplace-listings/${lid}/applications`);
  ok('(6) marketplace approval emails the publisher', notifCount('g7pub', 'marketplace_approved') === mbefore + 1);

  // ===== (7) settings toggles present + persist =====
  const settingsPage = await txt(await admin.req('GET', '/admin/settings'));
  ok('(7) settings page exposes the 4 G7 toggles',
    settingsPage.includes('name="notify_conversion_approved"') &&
    settingsPage.includes('name="notify_marketplace_approved"') &&
    settingsPage.includes('name="notify_invoice_ready"') &&
    settingsPage.includes('name="weekly_report"'));
  // toggle weekly_report off via the settings form (omit the field) — keep others on
  await post(admin, '/admin/settings',
    { email_notifications: 'on', daily_summary: 'on', webhook_notifications: 'on', webhook_daily_summary: 'on',
      notify_conversion_approved: 'on', notify_marketplace_approved: 'on', notify_invoice_ready: 'on' },
    '/admin/settings');
  ok('(7) weekly_report persisted off when omitted', db.prepare("SELECT value FROM settings WHERE key='weekly_report'").get().value === 'false');
  await post(admin, '/admin/settings',
    { email_notifications: 'on', daily_summary: 'on', webhook_notifications: 'on', webhook_daily_summary: 'on',
      notify_conversion_approved: 'on', notify_marketplace_approved: 'on', notify_invoice_ready: 'on', weekly_report: 'on' },
    '/admin/settings');
  ok('(7) weekly_report persisted on', db.prepare("SELECT value FROM settings WHERE key='weekly_report'").get().value === 'true');

  // ===== (8) weekly report runs (g7pub has activity this week) =====
  const wbefore = notifCount('g7pub', 'weekly_report');
  const wr = await admin.req('POST', '/admin/reports/weekly/run', { form: { _csrf: await csrf(admin, '/admin/settings') } });
  ok('(8) weekly report trigger returns 302', wr.status === 302, String(wr.status));
  // give the async run a moment to write the outbox rows
  await new Promise(r => setTimeout(r, 400));
  ok('(8) weekly report emails active publisher with activity', notifCount('g7pub', 'weekly_report') >= wbefore + 1);

  console.log(`\nPASSED: ${pass}`);
  if (failures.length) { console.log(`FAILED: ${failures.length}`); failures.forEach(f => console.log('  ✗ ' + f)); process.exit(1); }
  console.log('ALL GREEN ✓'); process.exit(0);
})().catch(e => { console.error('HARNESS ERROR:', e); process.exit(2); });
