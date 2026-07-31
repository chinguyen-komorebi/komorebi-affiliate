// Test #1 — IP allowlist (new CIDRs) + HMAC bypass authorization
// Standalone: re-implements the pure logic exactly as in server.js and asserts.
const crypto = require('node:crypto');
const assert = require('node:assert');

// ---- mirror of server.js logic (fix #1) ----
const APPSFLYER_CIDRS = ['45.92.116.0/22', '194.28.46.0/23'];
const ADJUST_IPS   = ['52.28.45.153','52.29.210.126','52.57.50.121','52.58.201.201','52.212.58.78','54.220.181.220','34.253.115.83','52.209.165.161'];
const ADJUST_CIDRS = ['185.151.204.0/24'];
const EXTRA_IPS = [], EXTRA_CIDRS = [];
const WHITELIST_ON = true;
const ALL_TRUSTED_CIDRS = [...APPSFLYER_CIDRS, ...ADJUST_CIDRS, ...EXTRA_CIDRS];
const ipToInt = ip => ip.split('.').reduce((n,o)=>(n<<8)|parseInt(o,10),0)>>>0;
function inCidr(ip,cidr){const[r,b]=cidr.split('/');const m=b==='32'?0xffffffff:(~((1<<(32-+b))-1))>>>0;return(ipToInt(ip)&m)===(ipToInt(r)&m);}
function isWhitelisted(ip){
  if(!WHITELIST_ON)return true;
  const addr=ip.replace(/^::ffff:/,'');
  if(addr==='127.0.0.1'||addr==='::1')return true;
  if(EXTRA_IPS.includes(addr))return true;
  if(!/^\d+\.\d+\.\d+\.\d+$/.test(addr))return false;
  return ALL_TRUSTED_CIDRS.some(c=>inCidr(addr,c))||ADJUST_IPS.includes(addr);
}
function hasValidPostbackSignature(query, adv){
  if(!adv||!adv.postback_secret)return false;
  const sig=String(query.sig||'').toLowerCase();
  if(!sig)return false;
  const base=[String(query.click_id||''),String(query.event||'sale'),query.payout!=null?String(query.payout):''].join(':');
  const expected=crypto.createHmac('sha256',adv.postback_secret).update(base).digest('hex');
  if(sig.length!==expected.length)return false;
  try{return crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(expected));}catch{return false;}
}
function sign(secret,q){return crypto.createHmac('sha256',secret).update([q.click_id,q.event||'sale',q.payout!=null?String(q.payout):''].join(':')).digest('hex');}

let pass=0,fail=0;
const t=(name,fn)=>{try{fn();console.log('  ✓',name);pass++;}catch(e){console.log('  ✗',name,'\n     ',e.message);fail++;}};

console.log('IP allowlist (new AppsFlyer CIDRs):');
// AppsFlyer 45.92.116.0/22 covers 45.92.116.0 – 45.92.119.255
t('AppsFlyer IP in 45.92.116.0/22 → allowed', ()=>assert(isWhitelisted('45.92.117.10')));
t('AppsFlyer IP in 194.28.46.0/23 → allowed', ()=>assert(isWhitelisted('194.28.47.5')));
t('AppsFlyer edge 45.92.119.255 → allowed', ()=>assert(isWhitelisted('45.92.119.255')));
t('AppsFlyer just-outside 45.92.120.0 → rejected', ()=>assert(!isWhitelisted('45.92.120.0')));
t('LEGACY AppsFlyer IP 52.6.61.4 → now REJECTED (deprecated)', ()=>assert(!isWhitelisted('52.6.61.4')));
t('Adjust IP 52.28.45.153 → allowed', ()=>assert(isWhitelisted('52.28.45.153')));
t('Adjust CIDR 185.151.204.7 → allowed', ()=>assert(isWhitelisted('185.151.204.7')));
t('loopback 127.0.0.1 → allowed (test tool)', ()=>assert(isWhitelisted('127.0.0.1')));
t('random public IP 8.8.8.8 → rejected', ()=>assert(!isWhitelisted('8.8.8.8')));
t('IPv6 (non-loopback) → rejected', ()=>assert(!isWhitelisted('2001:4860:4860::8888')));
t('::ffff: mapped AppsFlyer IP → allowed', ()=>assert(isWhitelisted('::ffff:45.92.117.10')));

console.log('HMAC signature bypass:');
const adv={postback_secret:'s3cr3t'};
const q={click_id:'abc123',event:'sale',payout:'11'};
const good=sign('s3cr3t',q);
t('valid signature → authorized', ()=>assert(hasValidPostbackSignature({...q,sig:good},adv)));
t('valid signature UPPERCASE → authorized (lowercased)', ()=>assert(hasValidPostbackSignature({...q,sig:good.toUpperCase()},adv)));
t('wrong signature → rejected', ()=>assert(!hasValidPostbackSignature({...q,sig:'deadbeef'.repeat(8)},adv)));
t('no signature → rejected', ()=>assert(!hasValidPostbackSignature(q,adv)));
t('advertiser without secret → no bypass', ()=>assert(!hasValidPostbackSignature({...q,sig:good},{postback_secret:null})));
t('tampered payout invalidates signature', ()=>{const s=sign('s3cr3t',q);assert(!hasValidPostbackSignature({...q,payout:'9999',sig:s},adv));});

console.log('Combined authorization (IP OR HMAC):');
const authorize=(ip,query,adv)=>isWhitelisted(ip)||hasValidPostbackSignature(query,adv);
t('bad IP + valid sig → authorized (the key network case)', ()=>assert(authorize('8.8.8.8',{...q,sig:good},adv)));
t('good IP + no sig + no secret → authorized', ()=>assert(authorize('45.92.117.10',q,{postback_secret:null})));
t('bad IP + no sig → rejected', ()=>assert(!authorize('8.8.8.8',q,{postback_secret:null})));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail?1:0);
