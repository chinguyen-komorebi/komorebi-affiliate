'use strict';
// Smoke test — feat/backlog-5d (Cohort/retention + Pivot reports, items 9 & 10).
const BASE = process.env.E2E_BASE || 'http://localhost:3999';
let pass = 0; const fail = [];
const ok = (n, c, x = '') => { c ? pass++ : fail.push(n + (x ? ` — ${x}` : '')); };
function jar() { let ck = ''; return { get cookie() { return ck; }, async req(m, p, o = {}) { const h = { ...(o.headers || {}) }; if (ck) h.Cookie = ck; let b; if (o.form) { b = new URLSearchParams(o.form).toString(); h['Content-Type'] = 'application/x-www-form-urlencoded'; } const r = await fetch(BASE + p, { method: m, headers: h, body: b, redirect: 'manual' }); for (const c of (r.headers.getSetCookie?.() || [])) { const kv = c.split(';')[0], nm = kv.split('=')[0]; const ps = (ck ? ck.split('; ') : []).filter(x => x.split('=')[0] !== nm); ps.push(kv); ck = ps.join('; '); } return r; } }; }
const txt = r => r.text();

(async () => {
  const a = jar();
  await a.req('POST', '/admin/login', { form: { username: 'admin', password: 'testpass123' } });
  const cohort = await a.req('GET', '/admin/reports/cohort');
  ok('#9 cohort report returns 200', cohort.status === 200);
  ok('#9 cohort report renders D0-D28+ buckets', (await txt(cohort)).includes('Cohort / Retention Report') && (await txt(await a.req('GET', '/admin/reports/cohort'))).includes('D28+'));
  const cCsv = await a.req('GET', '/admin/reports/cohort?format=csv');
  ok('#9 cohort CSV export is text/csv', (cCsv.headers.get('content-type') || '').includes('text/csv') && (await txt(cCsv)).startsWith('media_source,'));
  const pivot = await a.req('GET', '/admin/reports/pivot?dim1=publisher&dim2=country');
  ok('#10 pivot returns 200', pivot.status === 200);
  ok('#10 pivot renders', (await txt(pivot)).includes('Pivot / Grouped Report'));
  const pCsv = await txt(await a.req('GET', '/admin/reports/pivot?dim1=country&format=csv'));
  ok('#10 pivot CSV header', pCsv.split('\n')[0].includes('Geo') && pCsv.includes('conversions'));
  console.log(`\nPASSED: ${pass}`);
  if (fail.length) { console.log(`FAILED: ${fail.length}`); fail.forEach(f => console.log('  ✗ ' + f)); process.exit(1); }
  console.log('ALL GREEN ✓'); process.exit(0);
})().catch(e => { console.error('HARNESS ERROR:', e); process.exit(2); });
