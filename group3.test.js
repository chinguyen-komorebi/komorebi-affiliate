'use strict';
// Backlog Group 3 (Nice-to-Have, items 13–17).
// SELF-HOSTED: spawns its own server instance with the IP whitelist ENABLED (so the
// Protect360 403 path is real) and its own throwaway database, then tears it down.
// Run: node group3.test.js   (no external server needed)
//
// Covers: #13 Protect360 (update existing / insert unknown / 403 non-whitelisted),
//         #14 duplicate click_id flag, #15 CTIT fast/normal/slow flags,
//         #16 quality score (50% rejection → 80 / grade B), #17 af_sub1/af_sub2.

const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const ROOT = __dirname;                       // has server.js, db.js, node_modules
const DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'g3-'));
fs.symlinkSync(path.join(ROOT, 'node_modules'), path.join(DIR, 'node_modules'));
fs.copyFileSync(path.join(ROOT, 'server.js'), path.join(DIR, 'server.js'));
fs.copyFileSync(path.join(ROOT, 'db.js'), path.join(DIR, 'db.js'));

const PORT = 3997;
const BASE = `http://localhost:${PORT}`;
const srv = spawn('node', ['server.js'], {
  cwd: DIR,
  env: { ...process.env,
    PORT: String(PORT),
    POSTBACK_WHITELIST_ENABLED: 'true',        // whitelist ON — localhost still allowed, foreign IPs 403
    SESSION_SECRET: 'g3secret', ADMIN_USER: 'admin', ADMIN_PASS: 'testpass123',
    RATE_LIMIT_MAX: '100000', POSTBACK_RATE_LIMIT_MAX: '100000',
    MMP_ENCRYPTION_KEY: crypto.randomBytes(32).toString('hex'), NODE_NO_WARNINGS: '1' },
  stdio: 'ignore',
});

let pass = 0; const failures = [];
const ok = (n, c, x = '') => { c ? pass++ : failures.push(n + (x ? ` — ${x}` : '')); };
const sleep = ms => new Promise(r => setTimeout(r, ms));
function cleanup() { try { srv.kill(); } catch {} try { fs.rmSync(DIR, { recursive: true, force: true }); } catch {} }

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
const track = async (qs) => ((((await fetch(`${BASE}/track/${qs}`, { redirect: 'manual' })).headers.get('location')) || '').match(/click_id=([a-f0-9-]+)/) || [])[1] || null;
const postback = (slug, qs) => fetch(`${BASE}/postback/${slug}?${qs}`, { redirect: 'manual' });

(async () => {
  // wait for boot
  let up = false;
  for (let i = 0; i < 60; i++) { try { if ((await fetch(`${BASE}/health`)).ok) { up = true; break; } } catch {} await sleep(250); }
  if (!up) throw new Error('server did not start');
  const db = new DatabaseSync(path.join(DIR, 'affiliate.db'));
  db.exec('PRAGMA busy_timeout = 5000');

  const admin = makeJar();
  await admin.req('POST', '/admin/login', { form: { username: 'admin', password: 'testpass123' } });
  await post(admin, '/admin/advertisers',
    { name: 'G3 Adv', slug: 'g3a', offer_url: 'https://g3.test/o', payout_amount: 10, payout_type: 'fixed', click_lookback_window: 90, status: 'active' },
    '/admin/advertisers/new');
  await post(admin, '/admin/publishers', { username: 'g3p', password: 'g3ppass12', status: 'active' }, '/admin/publishers/new');
  await post(admin, '/admin/publishers', { username: 'g3q', password: 'g3qpass12', status: 'active' }, '/admin/publishers/new');
  const advId = db.prepare("SELECT id FROM advertisers WHERE slug='g3a'").get().id;
  const pId = db.prepare("SELECT id FROM publishers WHERE username='g3p'").get().id;
  const qId = db.prepare("SELECT id FROM publishers WHERE username='g3q'").get().id;
  await post(admin, `/admin/publishers/${pId}/assign`, { advertiser_id: advId }, `/admin/publishers/${pId}/edit`);
  await post(admin, `/admin/publishers/${qId}/assign`, { advertiser_id: advId }, `/admin/publishers/${qId}/edit`);

  // ===== #13 Protect360 =====
  const cP = await track('g3a?pub=g3p');
  db.prepare("UPDATE clicks SET created_at = datetime('now','-1 hour') WHERE click_id=?").run(cP);
  await postback('g3a', `click_id=${cP}&event=sale`);
  ok('#13 setup: conversion exists + not yet rejected', db.prepare("SELECT status FROM conversions WHERE click_id=?").get(cP).status === 'pending');
  await fetch(`${BASE}/postback/g3a/protect360?click_id=${cP}&reason=bot_traffic`, { redirect: 'manual' });
  const flagged = db.prepare('SELECT status, reason, payout, fraud_source FROM conversions WHERE click_id=?').get(cP);
  ok('#13 valid hit overturns existing conversion', flagged.status === 'rejected' && flagged.reason === 'protect360:bot_traffic' && flagged.payout === 0 && flagged.fraud_source === 'protect360', JSON.stringify(flagged));
  // unknown click_id → inserts a rejected protect360 row
  await fetch(`${BASE}/postback/g3a/protect360?click_id=unknown-xyz&reason=fraud_ring`, { redirect: 'manual' });
  const inserted = db.prepare("SELECT status, reason, payout, fraud_source FROM conversions WHERE click_id='unknown-xyz' AND advertiser_slug='g3a'").get();
  ok('#13 unknown click_id inserts rejected protect360 row', !!inserted && inserted.status === 'rejected' && inserted.fraud_source === 'protect360' && inserted.payout === 0, JSON.stringify(inserted));
  // non-whitelisted IP → 403 (foreign IP via X-Forwarded-For; trust proxy is on)
  const r403 = await fetch(`${BASE}/postback/g3a/protect360?click_id=${cP}&reason=x`, { headers: { 'X-Forwarded-For': '203.0.113.99' }, redirect: 'manual' });
  ok('#13 non-whitelisted IP → 403', r403.status === 403, `status=${r403.status}`);

  // ===== #14 duplicate click_id (normal CTIT so flag is exactly 'duplicate_click_id') =====
  const cD = await track('g3a?pub=g3p');
  db.prepare("UPDATE clicks SET created_at = datetime('now','-1 hour') WHERE click_id=?").run(cD);
  await postback('g3a', `click_id=${cD}&event=sale`);
  await postback('g3a', `click_id=${cD}&event=purchase`);
  const dupRows = db.prepare('SELECT fraud_flag FROM conversions WHERE click_id=? ORDER BY event').all(cD);
  ok('#14 both rows flagged duplicate_click_id', dupRows.length === 2 && dupRows.every(r => r.fraud_flag === 'duplicate_click_id'), JSON.stringify(dupRows));

  // ===== #15 CTIT fast / normal / slow =====
  const cFast = await track('g3a?pub=g3p'); await postback('g3a', `click_id=${cFast}&event=sale`); // immediate ~0s
  ok('#15 CTIT < 10s → ctit_too_fast', db.prepare('SELECT fraud_flag FROM conversions WHERE click_id=?').get(cFast).fraud_flag === 'ctit_too_fast');
  const cNorm = await track('g3a?pub=g3p');
  db.prepare("UPDATE clicks SET created_at = datetime('now','-1 hour') WHERE click_id=?").run(cNorm);
  await postback('g3a', `click_id=${cNorm}&event=sale`);
  ok('#15 CTIT normal (1h) → no flag', db.prepare('SELECT fraud_flag FROM conversions WHERE click_id=?').get(cNorm).fraud_flag === null);
  const cSlow = await track('g3a?pub=g3p');
  db.prepare("UPDATE clicks SET created_at = datetime('now','-31 days') WHERE click_id=?").run(cSlow);
  await postback('g3a', `click_id=${cSlow}&event=sale`);
  ok('#15 CTIT > 30d → ctit_too_slow', db.prepare('SELECT fraud_flag FROM conversions WHERE click_id=?').get(cSlow).fraud_flag === 'ctit_too_slow');

  // ===== #16 quality score: g3q with 50% rejection, no fraud → 80 / B =====
  for (let i = 0; i < 4; i++) {
    const c = await track('g3a?pub=g3q');
    db.prepare("UPDATE clicks SET created_at = datetime('now','-1 hour') WHERE click_id=?").run(c); // normal CTIT, no flag
    await postback('g3a', `click_id=${c}&event=sale`);
  }
  // reject 2 of g3q's 4 conversions
  const qConv = db.prepare("SELECT id FROM conversions WHERE publisher='g3q' ORDER BY id LIMIT 2").all();
  for (const r of qConv) db.prepare("UPDATE conversions SET status='rejected' WHERE id=?").run(r.id);
  const qStats = db.prepare("SELECT COUNT(*) t, SUM(CASE WHEN status='rejected' THEN 1 ELSE 0 END) r, SUM(CASE WHEN fraud_flag IS NOT NULL THEN 1 ELSE 0 END) f FROM conversions WHERE publisher='g3q'").get();
  ok('#16 setup: g3q has 4 conv, 2 rejected, 0 fraud', qStats.t === 4 && qStats.r === 2 && qStats.f === 0, JSON.stringify(qStats));
  const qHtml = await txt(await admin.req('GET', '/admin/publisher-quality'));
  ok('#16 quality page shows g3q score=80 grade=B', /data-pub="g3q"[^>]*data-score="80"[^>]*data-grade="B"/.test(qHtml), (qHtml.match(/data-pub="g3q"[^>]*>/) || [''])[0]);

  // ===== #17 af_sub1 / af_sub2 =====
  const cS = await track('g3a?pub=g3p&af_sub1=AGENCY1&af_sub2=SUB9');
  const clickRow = db.prepare('SELECT af_sub1, af_sub2 FROM clicks WHERE click_id=?').get(cS);
  ok('#17 af_sub1/af_sub2 stored on click', clickRow.af_sub1 === 'AGENCY1' && clickRow.af_sub2 === 'SUB9', JSON.stringify(clickRow));
  await postback('g3a', `click_id=${cS}&event=sale`);
  const convRow = db.prepare('SELECT af_sub1, af_sub2 FROM conversions WHERE click_id=?').get(cS);
  ok('#17 af_sub1/af_sub2 propagated to conversion', convRow.af_sub1 === 'AGENCY1' && convRow.af_sub2 === 'SUB9', JSON.stringify(convRow));
  const csv = await txt(await admin.req('GET', '/admin/export.csv?advertiser=g3a'));
  ok('#17 CSV export has af_sub1/af_sub2 columns + value', csv.split('\n')[0].includes('af_sub1,af_sub2') && csv.includes('AGENCY1'));

  db.close?.();
  console.log(`\nPASSED: ${pass}`);
  if (failures.length) { console.log(`FAILED: ${failures.length}`); failures.forEach(f => console.log('  ✗ ' + f)); cleanup(); process.exit(1); }
  console.log('ALL GREEN ✓'); cleanup(); process.exit(0);
})().catch(e => { console.error('HARNESS ERROR:', e); cleanup(); process.exit(2); });
