// Test #5: per-source cap (spec §8, BA điểm 3) — cap at af_sub1 level, isolates sources
const assert = require('node:assert');
const { DatabaseSync } = require('node:sqlite');
const db = new DatabaseSync(':memory:');
db.exec(`
  CREATE TABLE publishers (id INTEGER PRIMARY KEY, username TEXT);
  CREATE TABLE advertisers (id INTEGER PRIMARY KEY, slug TEXT);
  CREATE TABLE conversions (id INTEGER PRIMARY KEY AUTOINCREMENT, publisher TEXT, advertiser_slug TEXT, af_sub1 TEXT, status TEXT, received_at TEXT DEFAULT (datetime('now')));
  CREATE TABLE source_caps (id INTEGER PRIMARY KEY AUTOINCREMENT, publisher_id INTEGER, advertiser_id INTEGER, sub_id TEXT,
    daily_click_cap INTEGER, daily_conversion_cap INTEGER, monthly_conversion_cap INTEGER, fallback_url TEXT, UNIQUE(publisher_id,advertiser_id,sub_id));
`);
db.prepare("INSERT INTO publishers VALUES (1,'moonrover')").run();
db.prepare("INSERT INTO advertisers VALUES (10,'tambadana')").run();

function checkSourceCap(pubRow, advRow, subId){
  if(!subId) return null;
  const cap=db.prepare('SELECT * FROM source_caps WHERE publisher_id=? AND advertiser_id=? AND sub_id=?').get(pubRow.id,advRow.id,subId);
  if(!cap) return null;
  const pubName=pubRow.username||db.prepare('SELECT username FROM publishers WHERE id=?').get(pubRow.id)?.username;
  if(cap.daily_conversion_cap!=null){
    const n=db.prepare(`SELECT COUNT(*) n FROM conversions WHERE publisher=? AND advertiser_slug=? AND af_sub1=? AND status='approved' AND date(received_at)=date('now')`).get(pubName,advRow.slug,subId).n;
    if(n>=cap.daily_conversion_cap) return {reason:'cap_reached',scope:'daily_conversion',fallback_url:cap.fallback_url||null};
  }
  if(cap.monthly_conversion_cap!=null){
    const n=db.prepare(`SELECT COUNT(*) n FROM conversions WHERE publisher=? AND advertiser_slug=? AND af_sub1=? AND status='approved' AND strftime('%Y-%m',received_at)=strftime('%Y-%m','now')`).get(pubName,advRow.slug,subId).n;
    if(n>=cap.monthly_conversion_cap) return {reason:'cap_reached',scope:'monthly_conversion',fallback_url:cap.fallback_url||null};
  }
  return null;
}
const pub={id:1,username:'moonrover'}, adv={id:10,slug:'tambadana'};
const addConv=(sub,status='approved')=>db.prepare("INSERT INTO conversions (publisher,advertiser_slug,af_sub1,status) VALUES ('moonrover','tambadana',?,?)").run(sub,status);

let pass=0,fail=0;
const t=(n,fn)=>{try{fn();console.log('  ✓',n);pass++;}catch(e){console.log('  ✗',n,'\n     ',e.message);fail++;}};

console.log('No cap configured → unlimited:');
t('no sub_id → exempt', ()=>assert.strictEqual(checkSourceCap(pub,adv,null),null));
t('sub without cap row → allowed', ()=>assert.strictEqual(checkSourceCap(pub,adv,'src_free'),null));

console.log('Daily conversion cap:');
db.prepare("INSERT INTO source_caps (publisher_id,advertiser_id,sub_id,daily_conversion_cap) VALUES (1,10,'src_a',2)").run();
t('under cap (0/2) → allowed', ()=>assert.strictEqual(checkSourceCap(pub,adv,'src_a'),null));
addConv('src_a'); 
t('under cap (1/2) → allowed', ()=>assert.strictEqual(checkSourceCap(pub,adv,'src_a'),null));
addConv('src_a');
t('at cap (2/2) → cap_reached', ()=>{const r=checkSourceCap(pub,adv,'src_a');assert.strictEqual(r.reason,'cap_reached');assert.strictEqual(r.scope,'daily_conversion');});

console.log('Source isolation (BA điểm 3 — chỉ ảnh hưởng source đó):');
t('src_b (different source, no cap) still allowed while src_a capped', ()=>assert.strictEqual(checkSourceCap(pub,adv,'src_b'),null));
db.prepare("INSERT INTO source_caps (publisher_id,advertiser_id,sub_id,daily_conversion_cap) VALUES (1,10,'src_b',5)").run();
t('src_b own cap (0/5) → allowed even though src_a is capped', ()=>assert.strictEqual(checkSourceCap(pub,adv,'src_b'),null));

console.log('Pending conversions do NOT count toward cap:');
db.prepare("INSERT INTO source_caps (publisher_id,advertiser_id,sub_id,daily_conversion_cap) VALUES (1,10,'src_c',1)").run();
addConv('src_c','pending'); addConv('src_c','rejected');
t('pending/rejected not counted → still allowed', ()=>assert.strictEqual(checkSourceCap(pub,adv,'src_c'),null));
addConv('src_c','approved');
t('one approved → now at cap', ()=>assert.strictEqual(checkSourceCap(pub,adv,'src_c').reason,'cap_reached'));

console.log('Fallback URL surfaced:');
db.prepare("INSERT INTO source_caps (publisher_id,advertiser_id,sub_id,daily_conversion_cap,fallback_url) VALUES (1,10,'src_d',1,'https://fallback.com')").run();
addConv('src_d','approved');
t('cap with fallback → returns fallback_url', ()=>{const r=checkSourceCap(pub,adv,'src_d');assert.strictEqual(r.fallback_url,'https://fallback.com');});

console.log('Publisher isolation:');
db.prepare("INSERT INTO publishers VALUES (2,'other')").run();
t('other publisher same sub_id name → own cap scope (no row → allowed)', ()=>assert.strictEqual(checkSourceCap({id:2,username:'other'},adv,'src_a'),null));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail?1:0);
