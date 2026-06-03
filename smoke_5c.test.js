'use strict';
// Smoke test — feat/backlog-5c (AppsFlyer onboarding walkthrough in /docs, item 6).
const BASE = process.env.E2E_BASE || 'http://localhost:3999';
let pass = 0; const fail = [];
const ok = (n, c) => { c ? pass++ : fail.push(n); };
(async () => {
  const docs = await (await fetch(`${BASE}/docs`)).text();
  ok('#6 onboarding walkthrough section present', docs.includes('id="appsflyer-onboarding"') && docs.includes('AppsFlyer Onboarding Walkthrough'));
  ok('#6 covers Agency partner step', docs.includes('Agency partner'));
  ok('#6 covers granting event postbacks', docs.includes('Grant event postbacks'));
  ok('#6 covers configuring the postback URL', /Configure the postback URL/i.test(docs));
  console.log(`\nPASSED: ${pass}`);
  if (fail.length) { console.log(`FAILED: ${fail.length}`); fail.forEach(f => console.log('  ✗ ' + f)); process.exit(1); }
  console.log('ALL GREEN ✓'); process.exit(0);
})().catch(e => { console.error('HARNESS ERROR:', e); process.exit(2); });
