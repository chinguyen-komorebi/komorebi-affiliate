// Test P0 #1-#2: external_click_id capture at /track + restore into conversion
const assert = require('node:assert');
const { DatabaseSync } = require('node:sqlite');
const db = new DatabaseSync(':memory:');
// minimal schema mirroring the new columns
db.exec(`
  CREATE TABLE clicks (click_id TEXT UNIQUE, advertiser_slug TEXT, publisher TEXT,
    af_sub1 TEXT, af_sub2 TEXT, af_sub3 TEXT, af_sub4 TEXT, af_sub5 TEXT, external_click_id TEXT, campaign_id INTEGER);
  CREATE TABLE conversions (id INTEGER PRIMARY KEY AUTOINCREMENT, click_id TEXT, publisher TEXT, event TEXT,
    af_sub1 TEXT, af_sub2 TEXT, af_sub3 TEXT, af_sub4 TEXT, af_sub5 TEXT, external_click_id TEXT);
`);

let pass=0,fail=0;
const t=(n,fn)=>{try{fn();console.log('  ✓',n);pass++;}catch(e){console.log('  ✗',n,'\n     ',e.message);fail++;}};

// simulate /track capturing a click from Yana (with external_click_id + af_subs)
function recordClick(clickId, q){
  db.prepare(`INSERT INTO clicks (click_id, advertiser_slug, publisher, af_sub1, af_sub2, af_sub3, af_sub4, af_sub5, external_click_id)
    VALUES (?,?,?,?,?,?,?,?,?)`).run(clickId, 'tambadana', 'moonrover',
    q.af_sub1||null, q.af_sub2||null, q.af_sub3||null, q.af_sub4||null, q.af_sub5||null, q.external_click_id||null);
}
// simulate postback → conversion restoring identifiers from the click
function recordConversion(clickId, event){
  const click = db.prepare('SELECT * FROM clicks WHERE click_id = ?').get(clickId);
  db.prepare(`INSERT INTO conversions (click_id, publisher, event, af_sub1, af_sub2, af_sub3, af_sub4, af_sub5, external_click_id)
    VALUES (?,?,?,?,?,?,?,?,?)`).run(clickId, click.publisher, event,
    click.af_sub1, click.af_sub2, click.af_sub3, click.af_sub4, click.af_sub5, click.external_click_id);
}

console.log('P0 #1 — /track captures external_click_id + af_sub3/4/5:');
recordClick('int-click-1', {external_click_id:'yana-xc-123', af_sub1:'pub_A', af_sub2:'src_9', af_sub3:'place_x'});
const c1 = db.prepare("SELECT * FROM clicks WHERE click_id='int-click-1'").get();
t('external_click_id stored', ()=>assert.strictEqual(c1.external_click_id,'yana-xc-123'));
t('internal click_id unchanged (separate)', ()=>assert.strictEqual(c1.click_id,'int-click-1'));
t('af_sub1 (Yana publisher id) stored', ()=>assert.strictEqual(c1.af_sub1,'pub_A'));
t('af_sub3 stored', ()=>assert.strictEqual(c1.af_sub3,'place_x'));

console.log('P0 #2 — conversion restores external_click_id from click (inbound):');
recordConversion('int-click-1','install');
const cv1 = db.prepare("SELECT * FROM conversions WHERE click_id='int-click-1'").get();
t('conversion.external_click_id restored from click', ()=>assert.strictEqual(cv1.external_click_id,'yana-xc-123'));
t('conversion keyed by internal click_id (attribution key)', ()=>assert.strictEqual(cv1.click_id,'int-click-1'));
t('af_sub1 carried to conversion', ()=>assert.strictEqual(cv1.af_sub1,'pub_A'));
t('af_sub3 carried to conversion', ()=>assert.strictEqual(cv1.af_sub3,'place_x'));

console.log('Backward compat — click WITHOUT external_click_id:');
recordClick('int-click-2', {af_sub1:'pub_B'});
recordConversion('int-click-2','install');
const cv2 = db.prepare("SELECT * FROM conversions WHERE click_id='int-click-2'").get();
t('external_click_id null when not provided (no error)', ()=>assert.strictEqual(cv2.external_click_id,null));
t('standard flow still records conversion', ()=>assert.strictEqual(cv2.click_id,'int-click-2'));

console.log('Identity separation (BA điểm 2):');
t('external_click_id (Yana) ≠ internal click_id (Komorebi)', ()=>assert.notStrictEqual(cv1.external_click_id, cv1.click_id));
t('Yana publisher id lives in af_sub1, not as PID', ()=>assert.strictEqual(cv1.af_sub1,'pub_A'));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail?1:0);
