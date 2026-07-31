// Test P0 #6: conversion API exposes external_click_id + af_sub3-5 + postback delivery
// Critical: scoping must survive the postback_log JOIN.
const assert = require('node:assert');
const { DatabaseSync } = require('node:sqlite');
const db = new DatabaseSync(':memory:');
db.exec(`
  CREATE TABLE conversions (id INTEGER PRIMARY KEY AUTOINCREMENT, click_id TEXT, advertiser_slug TEXT, publisher TEXT,
    event TEXT, status TEXT, payout REAL, currency TEXT, af_sub1 TEXT, af_sub2 TEXT, af_sub3 TEXT, af_sub4 TEXT, af_sub5 TEXT,
    external_click_id TEXT, reason TEXT, received_at TEXT);
  CREATE TABLE postback_log (id INTEGER PRIMARY KEY AUTOINCREMENT, publisher TEXT, click_id TEXT, delivered INTEGER,
    attempt INTEGER, http_status INTEGER, response_body TEXT, is_test INTEGER DEFAULT 0);
`);
const ins = db.prepare(`INSERT INTO conversions (click_id,advertiser_slug,publisher,event,status,payout,currency,af_sub1,af_sub3,external_click_id,received_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`);
ins.run('ic1','tambadana','moonrover','install','approved',11,'USD','pubA','place1','yana-1','2026-07-10 10:00:00');
ins.run('ic2','tambadana','moonrover','install','approved',11,'USD','pubA','place2','yana-2','2026-07-11 10:00:00');
ins.run('ic3','tambadana','other_pub','install','approved',11,'USD','pubX',null,'other-1','2026-07-12 10:00:00');
// postback_log: ic1 delivered, ic2 failed, plus a test row for ic1 that must be ignored
db.prepare("INSERT INTO postback_log (publisher,click_id,delivered,attempt,http_status,response_body,is_test) VALUES ('moonrover','ic1',1,1,200,'OK',0)").run();
db.prepare("INSERT INTO postback_log (publisher,click_id,delivered,attempt,http_status,response_body,is_test) VALUES ('moonrover','ic2',0,3,500,'err',0)").run();
db.prepare("INSERT INTO postback_log (publisher,click_id,delivered,attempt,http_status,response_body,is_test) VALUES ('moonrover','ic1',1,1,200,'TEST',1)").run();

function queryApi(pubUsername, q={}){
  const where=['cv.publisher = ?']; const params=[pubUsername];
  if(q.external_click_id){where.push('cv.external_click_id = ?');params.push(q.external_click_id);}
  if(q.sub_id){where.push('cv.af_sub1 = ?');params.push(q.sub_id);}
  const w=where.join(' AND ');
  const total=db.prepare(`SELECT COUNT(*) n FROM conversions cv WHERE ${w}`).get(...params).n;
  const rows=db.prepare(`
    SELECT cv.click_id, cv.af_sub1, cv.af_sub3, cv.external_click_id,
           pl.delivered AS pb_delivered, pl.attempt AS pb_attempts, pl.response_body AS pb_response
    FROM conversions cv
    LEFT JOIN (SELECT p1.* FROM postback_log p1 JOIN (SELECT click_id, MAX(id) mid FROM postback_log WHERE is_test=0 GROUP BY click_id) p2 ON p1.id=p2.mid) pl
      ON pl.click_id = cv.click_id
    WHERE ${w} ORDER BY cv.received_at DESC`).all(...params);
  return {total, rows:rows.map(r=>({
    click_id:r.click_id, external_click_id:r.external_click_id||null, af_sub3:r.af_sub3||null,
    postback_delivery_status: r.pb_delivered==null?null:(r.pb_delivered?'delivered':'failed'),
    postback_attempts: r.pb_attempts!=null?r.pb_attempts:null,
    last_postback_response: r.pb_response||null,
  }))};
}

let pass=0,fail=0;
const t=(n,fn)=>{try{fn();console.log('  ✓',n);pass++;}catch(e){console.log('  ✗',n,'\n     ',e.message);fail++;}};

console.log('Scoping survives JOIN (critical):');
t('moonrover sees only its 2 conversions', ()=>assert.strictEqual(queryApi('moonrover').total,2));
t('moonrover NEVER sees other_pub ic3', ()=>{const r=queryApi('moonrover');assert(!r.rows.find(x=>x.click_id==='ic3'));});
t('JOIN does not duplicate rows', ()=>assert.strictEqual(queryApi('moonrover').rows.length,2));

console.log('external_click_id exposed + filterable:');
t('external_click_id in response', ()=>{const r=queryApi('moonrover');assert.strictEqual(r.rows.find(x=>x.click_id==='ic1').external_click_id,'yana-1');});
t('filter by external_click_id', ()=>{const r=queryApi('moonrover',{external_click_id:'yana-2'});assert.strictEqual(r.total,1);assert.strictEqual(r.rows[0].click_id,'ic2');});
t('af_sub3 exposed', ()=>{const r=queryApi('moonrover');assert.strictEqual(r.rows.find(x=>x.click_id==='ic1').af_sub3,'place1');});

console.log('Postback delivery status:');
t('ic1 → delivered', ()=>{const r=queryApi('moonrover');assert.strictEqual(r.rows.find(x=>x.click_id==='ic1').postback_delivery_status,'delivered');});
t('ic2 → failed, attempts 3', ()=>{const r=queryApi('moonrover');const c=r.rows.find(x=>x.click_id==='ic2');assert.strictEqual(c.postback_delivery_status,'failed');assert.strictEqual(c.postback_attempts,3);});
t('test postback row IGNORED (is_test=1)', ()=>{const r=queryApi('moonrover');const c=r.rows.find(x=>x.click_id==='ic1');assert.strictEqual(c.last_postback_response,'OK');/* not TEST */});

console.log('No postback → null (not delivered/failed):');
db.prepare("INSERT INTO conversions (click_id,advertiser_slug,publisher,event,status,payout,currency,received_at) VALUES ('ic4','tambadana','moonrover','install','approved',11,'USD','2026-07-13 10:00:00')").run();
t('ic4 (no outbound) → delivery status null', ()=>{const r=queryApi('moonrover');assert.strictEqual(r.rows.find(x=>x.click_id==='ic4').postback_delivery_status,null);});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail?1:0);
