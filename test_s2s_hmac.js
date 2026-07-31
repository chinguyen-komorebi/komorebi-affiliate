// Test HMAC outbound signing (spec §11)
const assert = require('node:assert');
const crypto = require('node:crypto');

function signOutboundUrl(url, secret){
  if(!secret) return url;
  const ts=Math.floor(Date.now()/1000);
  const withTs=url+(url.includes('?')?'&':'?')+'ts='+ts;
  const sig=crypto.createHmac('sha256',secret).update(withTs).digest('hex');
  return withTs+'&sig='+sig;
}

let pass=0,fail=0;
const t=(n,fn)=>{try{fn();console.log('  ✓',n);pass++;}catch(e){console.log('  ✗',n,'\n     ',e.message);fail++;}};

console.log('No secret → unsigned:');
t('no secret returns url unchanged', ()=>assert.strictEqual(signOutboundUrl('https://y.com/pb?c=1',null),'https://y.com/pb?c=1'));
t('empty secret returns url unchanged', ()=>assert.strictEqual(signOutboundUrl('https://y.com/pb',''),'https://y.com/pb'));

console.log('With secret → signed with ts + sig:');
const signed=signOutboundUrl('https://y.com/pb?c=1','s3cr3t');
t('has ts param', ()=>assert.ok(/[?&]ts=\d+/.test(signed)));
t('has sig param', ()=>assert.ok(/[?&]sig=[a-f0-9]{64}/.test(signed)));
t('appends with & when url has query', ()=>assert.ok(signed.startsWith('https://y.com/pb?c=1&ts=')));

console.log('Publisher can verify signature (round-trip):');
const secret='yana-secret-key';
const signed2=signOutboundUrl('https://yana.com/postback?click_id=abc&payout=11','yana-secret-key');
// publisher extracts sig, recomputes over the rest
const m=signed2.match(/^(.*)&sig=([a-f0-9]{64})$/);
t('signature format parseable', ()=>assert.ok(m));
const base=m[1], sentSig=m[2];
const recomputed=crypto.createHmac('sha256',secret).update(base).digest('hex');
t('publisher recomputes same signature → verified', ()=>assert.strictEqual(recomputed,sentSig));
t('wrong secret → verification fails', ()=>{const bad=crypto.createHmac('sha256','wrong').update(base).digest('hex');assert.notStrictEqual(bad,sentSig);});

console.log('Timestamp freshness (anti-replay):');
t('ts is a recent unix timestamp', ()=>{const ts=parseInt(signed2.match(/[?&]ts=(\d+)/)[1],10);const now=Math.floor(Date.now()/1000);assert.ok(Math.abs(now-ts)<5);});

console.log('URL without query → uses ? for ts:');
const signed3=signOutboundUrl('https://y.com/pb','k');
t('no-query url gets ?ts=', ()=>assert.ok(signed3.startsWith('https://y.com/pb?ts=')));

console.log('Tamper detection:');
t('modified payout breaks signature', ()=>{
  const orig=signOutboundUrl('https://y.com/pb?payout=11','k');
  const mm=orig.match(/^(.*)&sig=([a-f0-9]{64})$/);
  const tampered=mm[1].replace('payout=11','payout=9999');
  const recomputed=crypto.createHmac('sha256','k').update(tampered).digest('hex');
  assert.notStrictEqual(recomputed,mm[2]);
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail?1:0);
