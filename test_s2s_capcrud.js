// Test source_caps CRUD (spec §8)
const assert = require('node:assert');
const { DatabaseSync } = require('node:sqlite');
const db = new DatabaseSync(':memory:');
db.exec(`CREATE TABLE source_caps (id INTEGER PRIMARY KEY AUTOINCREMENT, publisher_id INTEGER, advertiser_id INTEGER, sub_id TEXT,
  daily_click_cap INTEGER, daily_conversion_cap INTEGER, monthly_conversion_cap INTEGER, fallback_url TEXT,
  UNIQUE(publisher_id, advertiser_id, sub_id));`);

let pass=0,fail=0;
const t=(n,fn)=>{try{fn();console.log('  ✓',n);pass++;}catch(e){console.log('  ✗',n,'\n     ',e.message);fail++;}};

const intOrNull = v => { const n=parseInt(v,10); return Number.isInteger(n)&&n>=0?n:null; };
function upsert(pid,aid,sub,dc,dv,mv,fb){
  db.prepare(`INSERT INTO source_caps (publisher_id,advertiser_id,sub_id,daily_click_cap,daily_conversion_cap,monthly_conversion_cap,fallback_url)
    VALUES (?,?,?,?,?,?,?) ON CONFLICT(publisher_id,advertiser_id,sub_id) DO UPDATE SET
    daily_click_cap=excluded.daily_click_cap, daily_conversion_cap=excluded.daily_conversion_cap,
    monthly_conversion_cap=excluded.monthly_conversion_cap, fallback_url=excluded.fallback_url`)
    .run(pid,aid,sub,intOrNull(dc),intOrNull(dv),intOrNull(mv),fb||null);
}
const get=(pid,aid,sub)=>db.prepare('SELECT * FROM source_caps WHERE publisher_id=? AND advertiser_id=? AND sub_id=?').get(pid,aid,sub);

console.log('Empty → NULL (unlimited):');
upsert(1,10,'src_a','','', '', '');
t('empty daily_click → null', ()=>assert.strictEqual(get(1,10,'src_a').daily_click_cap,null));
t('empty monthly → null', ()=>assert.strictEqual(get(1,10,'src_a').monthly_conversion_cap,null));

console.log('Values stored:');
upsert(1,10,'src_b','100','20','300','https://fb.com');
t('daily_click=100', ()=>assert.strictEqual(get(1,10,'src_b').daily_click_cap,100));
t('monthly=300', ()=>assert.strictEqual(get(1,10,'src_b').monthly_conversion_cap,300));
t('fallback stored', ()=>assert.strictEqual(get(1,10,'src_b').fallback_url,'https://fb.com'));

console.log('Upsert (update existing, no duplicate row):');
upsert(1,10,'src_b','50','10','150','');
t('updated daily_click 100→50', ()=>assert.strictEqual(get(1,10,'src_b').daily_click_cap,50));
t('no duplicate rows for same key', ()=>assert.strictEqual(db.prepare("SELECT COUNT(*) n FROM source_caps WHERE publisher_id=1 AND advertiser_id=10 AND sub_id='src_b'").get().n,1));

console.log('Invalid values → null (not error):');
upsert(2,10,'src_c','abc','-5','','');
t('non-numeric → null', ()=>assert.strictEqual(get(2,10,'src_c').daily_click_cap,null));
t('negative → null', ()=>assert.strictEqual(get(2,10,'src_c').daily_conversion_cap,null));

console.log('Delete:');
const id=get(1,10,'src_a').id;
db.prepare('DELETE FROM source_caps WHERE id=?').run(id);
t('deleted row gone', ()=>assert.strictEqual(get(1,10,'src_a'),undefined));
t('other rows unaffected', ()=>assert.ok(get(1,10,'src_b')));

console.log('Isolation — same sub_id, different publisher = separate cap:');
upsert(1,10,'shared','10','','','');
upsert(2,10,'shared','99','','','');
t('publisher 1 shared cap = 10', ()=>assert.strictEqual(get(1,10,'shared').daily_click_cap,10));
t('publisher 2 shared cap = 99 (independent)', ()=>assert.strictEqual(get(2,10,'shared').daily_click_cap,99));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail?1:0);
