// Test #3 — conversion-level API: scoping, masking, pagination, filters
const assert = require('node:assert');
const { DatabaseSync } = require('node:sqlite');
const db = new DatabaseSync(':memory:');
db.exec(`CREATE TABLE conversions (id INTEGER PRIMARY KEY AUTOINCREMENT, click_id TEXT, advertiser_slug TEXT,
  publisher TEXT, event TEXT, status TEXT, payout REAL, currency TEXT, af_sub1 TEXT, af_sub2 TEXT, reason TEXT, received_at TEXT);`);

const PUB_SAFE_REASONS = new Set(['below_min_value','duplicate','duplicate_user','duplicate_click_id','not_activated','no_event']);
const pubSafeReason = r => !r ? '' : (PUB_SAFE_REASONS.has(r) ? r : 'Attribution adjustment');

// seed: publisher A (moonrover) + publisher B (other) — to test scoping
const ins = db.prepare(`INSERT INTO conversions (click_id,advertiser_slug,publisher,event,status,payout,currency,af_sub1,af_sub2,reason,received_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`);
ins.run('c1','tambadana','moonrover','install','approved',11,'USD','subA',null,null,'2026-07-01 10:00:00');
ins.run('c2','tambadana','moonrover','install','rejected',0,'USD','subA',null,'telesale_wins','2026-07-02 10:00:00'); // internal reason → must mask
ins.run('c3','tambadana','moonrover','install','rejected',0,'USD','subB',null,'duplicate','2026-07-03 10:00:00');     // safe reason → keep
ins.run('c4','keebu','moonrover','install','pending',11,'USD','subA',null,null,'2026-07-04 10:00:00');
ins.run('c5','tambadana','other_pub','install','approved',11,'USD','subX',null,null,'2026-07-05 10:00:00');          // different publisher

// mirror of endpoint query logic
function queryConversions(pubUsername, q={}){
  const where=['publisher = ?']; const params=[pubUsername];
  if(q.advertiser){where.push('advertiser_slug = ?');params.push(q.advertiser);}
  if(q.sub_id){where.push('af_sub1 = ?');params.push(q.sub_id);}
  if(q.status){where.push('status = ?');params.push(q.status);}
  if(/^\d{4}-\d{2}-\d{2}$/.test(q.from||'')){where.push("date(received_at) >= date(?)");params.push(q.from);}
  if(/^\d{4}-\d{2}-\d{2}$/.test(q.to||'')){where.push("date(received_at) <= date(?)");params.push(q.to);}
  const w=where.join(' AND ');
  const limit=Math.min(q.limit||100,500); const page=q.page||1; const offset=(page-1)*limit;
  const total=db.prepare(`SELECT COUNT(*) n FROM conversions WHERE ${w}`).get(...params).n;
  const rows=db.prepare(`SELECT click_id,advertiser_slug,event,status,payout,currency,af_sub1,af_sub2,reason,received_at FROM conversions WHERE ${w} ORDER BY received_at DESC, id DESC LIMIT ? OFFSET ?`).all(...params,limit,offset);
  return {total,page,limit,rows:rows.map(r=>({click_id:r.click_id,status:r.status,sub_id:r.af_sub1||null,rejection_reason:r.status==='rejected'?(pubSafeReason(r.reason)||null):null,payout:+(Number(r.payout)||0).toFixed(2)}))};
}

let pass=0,fail=0;
const t=(name,fn)=>{try{fn();console.log('  ✓',name);pass++;}catch(e){console.log('  ✗',name,'\n     ',e.message);fail++;}};

console.log('Scoping (critical security):');
t('moonrover sees only its own 4 conversions', ()=>assert.strictEqual(queryConversions('moonrover').total,4));
t('moonrover NEVER sees other_pub row c5', ()=>{const r=queryConversions('moonrover');assert(!r.rows.find(x=>x.click_id==='c5'));});
t('other_pub sees only its own 1', ()=>assert.strictEqual(queryConversions('other_pub').total,1));

console.log('Reason masking (publisher-safe):');
t('internal reason telesale_wins → masked to Attribution adjustment', ()=>{const r=queryConversions('moonrover',{status:'rejected'});const c2=r.rows.find(x=>x.click_id==='c2');assert.strictEqual(c2.rejection_reason,'Attribution adjustment');});
t('safe reason duplicate → kept as-is', ()=>{const r=queryConversions('moonrover',{status:'rejected'});const c3=r.rows.find(x=>x.click_id==='c3');assert.strictEqual(c3.rejection_reason,'duplicate');});
t('approved row → rejection_reason null', ()=>{const r=queryConversions('moonrover',{status:'approved'});assert.strictEqual(r.rows[0].rejection_reason,null);});
t('raw internal reason never leaks in any row', ()=>{const r=queryConversions('moonrover');assert(!JSON.stringify(r.rows).includes('telesale_wins'));});

console.log('Filters:');
t('filter by advertiser=keebu → 1 row', ()=>assert.strictEqual(queryConversions('moonrover',{advertiser:'keebu'}).total,1));
t('filter by sub_id=subA → 3 rows', ()=>assert.strictEqual(queryConversions('moonrover',{sub_id:'subA'}).total,3));
t('filter by status=rejected → 2 rows', ()=>assert.strictEqual(queryConversions('moonrover',{status:'rejected'}).total,2));
t('filter by date from 2026-07-03 → 2 rows (c3,c4)', ()=>assert.strictEqual(queryConversions('moonrover',{from:'2026-07-03'}).total,2));
t('filter by date range 07-02..07-03 → 2 rows', ()=>assert.strictEqual(queryConversions('moonrover',{from:'2026-07-02',to:'2026-07-03'}).total,2));

console.log('Pagination:');
t('limit=2 page=1 → 2 rows, total still 4', ()=>{const r=queryConversions('moonrover',{limit:2,page:1});assert.strictEqual(r.rows.length,2);assert.strictEqual(r.total,4);});
t('limit=2 page=2 → 2 rows', ()=>assert.strictEqual(queryConversions('moonrover',{limit:2,page:2}).rows.length,2));
t('limit=2 page=3 → 0 rows', ()=>assert.strictEqual(queryConversions('moonrover',{limit:2,page:3}).rows.length,0));
t('ordering is newest-first (c4 before c1)', ()=>{const r=queryConversions('moonrover');const i4=r.rows.findIndex(x=>x.click_id==='c4');const i1=r.rows.findIndex(x=>x.click_id==='c1');assert(i4<i1);});
t('limit capped at 500', ()=>assert.strictEqual(queryConversions('moonrover',{limit:9999}).limit,500));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail?1:0);
