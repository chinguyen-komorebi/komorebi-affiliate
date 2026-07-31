// Test P0 #3: Integration Mode gate + backward-compat (spec §5, §16, BA điểm rủi ro)
const assert = require('node:assert');
const { DatabaseSync } = require('node:sqlite');
const db = new DatabaseSync(':memory:');
db.exec(`
  CREATE TABLE publishers (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, postback_url TEXT,
    integration_mode TEXT NOT NULL DEFAULT 'standard', s2s_postback_active INTEGER NOT NULL DEFAULT 0);
  CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT);
`);

// mirror of the gate decision in fireS2SPostback
function s2sEnabled(pub){
  if(!pub?.postback_url) return false;
  return (pub.integration_mode==='s2s_network' || pub.integration_mode==='portal_s2s') && pub.s2s_postback_active===1;
}
// mirror of the backward-compat backfill migration
function runBackfill(){
  const done = db.prepare("SELECT value FROM settings WHERE key='s2s_postback_backfill'").get()?.value;
  if(done!=='done'){
    db.exec(`UPDATE publishers SET integration_mode=CASE WHEN integration_mode='standard' THEN 'portal_s2s' ELSE integration_mode END, s2s_postback_active=1 WHERE postback_url IS NOT NULL AND TRIM(postback_url)<>''`);
    db.prepare("INSERT OR REPLACE INTO settings (key,value) VALUES ('s2s_postback_backfill','done')").run();
  }
}
const get = u => db.prepare('SELECT * FROM publishers WHERE username=?').get(u);

let pass=0,fail=0;
const t=(n,fn)=>{try{fn();console.log('  ✓',n);pass++;}catch(e){console.log('  ✗',n,'\n     ',e.message);fail++;}};

console.log('Seed (pre-feature state):');
// existing publisher already receiving postbacks (had URL before feature)
db.prepare("INSERT INTO publishers (username,postback_url,integration_mode,s2s_postback_active) VALUES ('legacy_pub','https://legacy.com/pb',(?),0)").run('standard');
// standard publisher, no URL
db.prepare("INSERT INTO publishers (username,integration_mode) VALUES ('portal_only','standard')").run();

console.log('BEFORE backfill — legacy_pub would break (standard + inactive):');
t('legacy_pub NOT enabled before backfill (the risk)', ()=>assert.strictEqual(s2sEnabled(get('legacy_pub')),false));

console.log('Backward-compat backfill (BA điểm rủi ro):');
runBackfill();
t('legacy_pub → portal_s2s after backfill', ()=>assert.strictEqual(get('legacy_pub').integration_mode,'portal_s2s'));
t('legacy_pub → active after backfill', ()=>assert.strictEqual(get('legacy_pub').s2s_postback_active,1));
t('legacy_pub NOW enabled (keeps receiving — no silent break)', ()=>assert.strictEqual(s2sEnabled(get('legacy_pub')),true));
t('portal_only (no URL) stays disabled', ()=>assert.strictEqual(s2sEnabled(get('portal_only')),false));

console.log('Backfill idempotent:');
runBackfill(); runBackfill();
t('legacy_pub still portal_s2s+active (no double apply issue)', ()=>{const p=get('legacy_pub');assert.strictEqual(p.integration_mode,'portal_s2s');assert.strictEqual(p.s2s_postback_active,1);});

console.log('New publishers (post-feature):');
db.prepare("INSERT INTO publishers (username,integration_mode,s2s_postback_active) VALUES ('new_standard','standard',0)").run();
db.prepare("INSERT INTO publishers (username,postback_url,integration_mode,s2s_postback_active) VALUES ('new_s2s','https://yana.com/pb','s2s_network',1)").run();
db.prepare("INSERT INTO publishers (username,postback_url,integration_mode,s2s_postback_active) VALUES ('new_s2s_inactive','https://yana.com/pb','s2s_network',0)").run();
t('new standard publisher → NO outbound (spec §5)', ()=>assert.strictEqual(s2sEnabled(get('new_standard')),false));
t('new s2s_network + active + URL → outbound', ()=>assert.strictEqual(s2sEnabled(get('new_s2s')),true));
t('new s2s_network but INACTIVE → NO outbound', ()=>assert.strictEqual(s2sEnabled(get('new_s2s_inactive')),false));
t('s2s mode but no URL → NO outbound', ()=>{db.prepare("INSERT INTO publishers (username,integration_mode,s2s_postback_active) VALUES ('s2s_nourl','s2s_network',1)").run();assert.strictEqual(s2sEnabled(get('s2s_nourl')),false);});

console.log('Macro empty handling (spec §5 — no "undefined"/"null"):');
function applyMacros(url, macros){return Object.entries(macros).reduce((u,[k,v])=>u.replaceAll(`{${k}}`,encodeURIComponent(v==null?'':String(v))),url);}
t('missing external_click_id → empty, not "undefined"', ()=>{const r=applyMacros('x?e={external_click_id}',{external_click_id:undefined});assert.strictEqual(r,'x?e=');});
t('missing af_sub3 → empty, not "null"', ()=>{const r=applyMacros('x?s={af_sub3}',{af_sub3:null});assert.strictEqual(r,'x?s=');});
t('present external_click_id → encoded', ()=>{const r=applyMacros('x?e={external_click_id}',{external_click_id:'yana 123'});assert.strictEqual(r,'x?e=yana%20123');});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail?1:0);
