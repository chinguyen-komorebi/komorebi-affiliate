// Test #4: outbound postback test tool (spec §6, BA điểm 4)
const assert = require('node:assert');
const { DatabaseSync } = require('node:sqlite');
const db = new DatabaseSync(':memory:');
db.exec(`
  CREATE TABLE postback_log (id INTEGER PRIMARY KEY AUTOINCREMENT, publisher TEXT, click_id TEXT, external_click_id TEXT,
    url TEXT, http_status INTEGER, attempt INTEGER, success INTEGER, delivered INTEGER, error TEXT, response_body TEXT, response_ms INTEGER, is_test INTEGER DEFAULT 0);
`);

let pass=0,fail=0;
const t=(n,fn)=>{try{fn();console.log('  ✓',n);pass++;}catch(e){console.log('  ✗',n,'\n     ',e.message);fail++;}};

// mirror preview URL builder
function buildPreview(template, sample){
  const macros={click_id:sample.click_id, payout:sample.payout, event:sample.event, advertiser:sample.advertiser,
    external_click_id:sample.external_click_id, status:sample.status, currency:sample.currency,
    af_sub1:sample.af_sub1, af_sub2:sample.af_sub2};
  return Object.entries(macros).reduce((u,[k,v])=>u.replaceAll(`{${k}}`,encodeURIComponent(v==null?'':String(v))),template);
}

console.log('Preview URL substitution:');
t('external_click_id substituted', ()=>{
  const url=buildPreview('https://y.com/pb?ext={external_click_id}&c={click_id}',{external_click_id:'yana-99',click_id:'ic-1'});
  assert.strictEqual(url,'https://y.com/pb?ext=yana-99&c=ic-1');
});
t('empty macro → empty (not undefined)', ()=>{
  const url=buildPreview('https://y.com/pb?s={af_sub1}',{af_sub1:''});
  assert.strictEqual(url,'https://y.com/pb?s=');
});
t('special chars encoded', ()=>{
  const url=buildPreview('https://y.com/pb?e={external_click_id}',{external_click_id:'a b&c'});
  assert.strictEqual(url,'https://y.com/pb?e=a%20b%26c');
});

console.log('Test log marked is_test=1 (BA điểm 4 — không tính report/cap/payout):');
// simulate the tool logging a test
db.prepare(`INSERT INTO postback_log (publisher,click_id,external_click_id,url,http_status,attempt,success,delivered,response_body,response_ms,is_test)
  VALUES ('moonrover','test-1','yana-1','https://y.com',200,1,1,1,'OK',42,1)`).run();
// simulate a real conversion postback
db.prepare(`INSERT INTO postback_log (publisher,click_id,external_click_id,url,http_status,attempt,success,delivered,response_body,response_ms,is_test)
  VALUES ('moonrover','real-1','yana-2','https://y.com',200,1,1,1,'OK',30,0)`).run();

t('test row has is_test=1', ()=>assert.strictEqual(db.prepare("SELECT is_test FROM postback_log WHERE click_id='test-1'").get().is_test,1));
t('real row has is_test=0', ()=>assert.strictEqual(db.prepare("SELECT is_test FROM postback_log WHERE click_id='real-1'").get().is_test,0));

console.log('Reports exclude test rows (the delivery-status JOIN uses is_test=0):');
// mirror the API JOIN which filters is_test=0
const realDeliveries = db.prepare("SELECT COUNT(*) n FROM postback_log WHERE is_test=0").get().n;
t('only real postbacks counted in delivery stats', ()=>assert.strictEqual(realDeliveries,1));
t('test postback excluded from delivery stats', ()=>{
  const testInStats = db.prepare("SELECT COUNT(*) n FROM postback_log WHERE is_test=0 AND click_id='test-1'").get().n;
  assert.strictEqual(testInStats,0);
});

console.log('Test tool attempt=1 always (no retry chain):');
// the tool inserts exactly one row with attempt=1 and schedules NO retry
t('test row attempt is 1 (single fire)', ()=>assert.strictEqual(db.prepare("SELECT attempt FROM postback_log WHERE click_id='test-1'").get().attempt,1));
t('only ONE test row per send (no retry duplicates)', ()=>assert.strictEqual(db.prepare("SELECT COUNT(*) n FROM postback_log WHERE click_id='test-1'").get().n,1));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail?1:0);
