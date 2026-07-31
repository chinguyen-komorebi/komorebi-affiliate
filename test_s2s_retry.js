// Test P1 manual retry (spec §7) — guards against retrying test/delivered
const assert = require('node:assert');
const { DatabaseSync } = require('node:sqlite');
const db = new DatabaseSync(':memory:');
db.exec(`CREATE TABLE postback_log (id INTEGER PRIMARY KEY AUTOINCREMENT, publisher TEXT, click_id TEXT,
  external_click_id TEXT, url TEXT, http_status INTEGER, attempt INTEGER, success INTEGER, delivered INTEGER,
  error TEXT, response_body TEXT, response_ms INTEGER, is_test INTEGER DEFAULT 0);`);

let pass=0,fail=0;
const t=(n,fn)=>{try{fn();console.log('  ✓',n);pass++;}catch(e){console.log('  ✗',n,'\n     ',e.message);fail++;}};

// mirror the retry guard logic
function canRetry(row){
  if(!row) return {ok:false,reason:'not_found'};
  if(row.is_test) return {ok:false,reason:'test'};
  if(row.success||row.delivered) return {ok:false,reason:'already_delivered'};
  const already=db.prepare("SELECT 1 FROM postback_log WHERE publisher=? AND click_id=? AND is_test=0 AND (success=1 OR delivered=1) LIMIT 1").get(row.publisher,row.click_id);
  if(already) return {ok:false,reason:'delivered_elsewhere'};
  return {ok:true};
}
const add=(o)=>db.prepare(`INSERT INTO postback_log (publisher,click_id,url,attempt,success,delivered,is_test) VALUES (?,?,?,?,?,?,?)`)
  .run(o.publisher,o.click_id,o.url||'https://y.com',o.attempt||1,o.success||0,o.delivered||0,o.is_test||0).lastInsertRowid;
const get=(id)=>db.prepare('SELECT * FROM postback_log WHERE id=?').get(id);

console.log('Retry eligibility:');
const failedId=add({publisher:'moonrover',click_id:'c1',success:0});
t('failed non-test row → can retry', ()=>assert.strictEqual(canRetry(get(failedId)).ok,true));

const testId=add({publisher:'moonrover',click_id:'c2',success:0,is_test:1});
t('test row → CANNOT retry', ()=>{const r=canRetry(get(testId));assert.strictEqual(r.ok,false);assert.strictEqual(r.reason,'test');});

const deliveredId=add({publisher:'moonrover',click_id:'c3',success:1,delivered:1});
t('delivered row → CANNOT retry', ()=>{const r=canRetry(get(deliveredId));assert.strictEqual(r.ok,false);assert.strictEqual(r.reason,'already_delivered');});

console.log('Dedup — no retry if another attempt already delivered (spec §7):');
add({publisher:'moonrover',click_id:'c4',success:1,delivered:1,attempt:1}); // delivered attempt
const failedButDeliveredElsewhere=add({publisher:'moonrover',click_id:'c4',success:0,attempt:2}); // failed attempt same click
t('failed attempt but click already delivered → blocked', ()=>{const r=canRetry(get(failedButDeliveredElsewhere));assert.strictEqual(r.ok,false);assert.strictEqual(r.reason,'delivered_elsewhere');});

console.log('Attempt numbering continues:');
add({publisher:'p2',click_id:'c5',success:0,attempt:1});
add({publisher:'p2',click_id:'c5',success:0,attempt:2});
const maxA=db.prepare("SELECT MAX(attempt) m FROM postback_log WHERE publisher='p2' AND click_id='c5' AND is_test=0").get().m;
t('next manual attempt = max+1', ()=>assert.strictEqual(maxA+1,3));

console.log('Not found:');
t('nonexistent log id → cannot retry', ()=>assert.strictEqual(canRetry(get(9999)).ok,false));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail?1:0);
