// Test #2 — API key state consistency (write + read + repair migration)
// Uses in-memory sqlite mirroring the real publishers key columns.
const crypto = require('node:crypto');
const assert = require('node:assert');
const { DatabaseSync } = require('node:sqlite');

const db = new DatabaseSync(':memory:');
db.exec(`CREATE TABLE publishers (id INTEGER PRIMARY KEY, username TEXT, status TEXT DEFAULT 'active',
  api_key TEXT, api_key_hash TEXT, api_key_suffix TEXT);`);

const genKey = () => 'kom_live_' + crypto.randomBytes(16).toString('hex');
const hashKey = k => crypto.createHash('sha256').update(k).digest('hex');

// mirrors of server.js helpers
function setPublisherKey(pubId){const key=genKey();db.prepare('UPDATE publishers SET api_key=NULL, api_key_hash=?, api_key_suffix=? WHERE id=?').run(hashKey(key),key.slice(-8),pubId);return key;}
function revokePublisherKey(pubId){db.prepare('UPDATE publishers SET api_key=NULL, api_key_hash=NULL, api_key_suffix=NULL WHERE id=?').run(pubId);}
function keyStatus(pub){return pub&&pub.api_key_hash?'active':'revoked';}
function keySuffixOf(pub){return (pub&&(pub.api_key_suffix||(pub.api_key?pub.api_key.slice(-8):null)))||null;}
const get = id => db.prepare('SELECT * FROM publishers WHERE id=?').get(id);

let pass=0,fail=0;
const t=(name,fn)=>{try{fn();console.log('  ✓',name);pass++;}catch(e){console.log('  ✗',name,'\n     ',e.message);fail++;}};

console.log('Key write consistency (the invariant):');
db.prepare("INSERT INTO publishers (id,username) VALUES (1,'p1')").run();
const k1 = setPublisherKey(1);
t('after setPublisherKey: api_key is NULL', ()=>assert.strictEqual(get(1).api_key,null));
t('after setPublisherKey: hash is set', ()=>assert.ok(get(1).api_key_hash));
t('after setPublisherKey: suffix is set (last 8)', ()=>assert.strictEqual(get(1).api_key_suffix,k1.slice(-8)));
t('status reads active', ()=>assert.strictEqual(keyStatus(get(1)),'active'));
t('suffix helper returns the suffix', ()=>assert.strictEqual(keySuffixOf(get(1)),k1.slice(-8)));
t('returned plaintext hashes to stored hash', ()=>assert.strictEqual(hashKey(k1),get(1).api_key_hash));

console.log('Approve path (was the bug) now consistent:');
db.prepare("INSERT INTO publishers (id,username,status) VALUES (2,'p2','pending')").run();
// simulate fixed approve route: set status then setPublisherKey
db.prepare("UPDATE publishers SET status='active' WHERE id=?").run(2);
const k2 = setPublisherKey(2);
t('approved row: active + hash + suffix all consistent', ()=>{const p=get(2);assert.strictEqual(keyStatus(p),'active');assert.ok(p.api_key_hash);assert.strictEqual(p.api_key_suffix,k2.slice(-8));assert.strictEqual(p.api_key,null);});
t('edit-save (no key columns touched) keeps key intact', ()=>{db.prepare("UPDATE publishers SET status='paused' WHERE id=?").run(2);const p=get(2);assert.strictEqual(keyStatus(p),'active');/* key survives */assert.strictEqual(p.api_key_suffix,k2.slice(-8));});

console.log('Revoke:');
revokePublisherKey(1);
t('revoked: all three columns NULL', ()=>{const p=get(1);assert.strictEqual(p.api_key,null);assert.strictEqual(p.api_key_hash,null);assert.strictEqual(p.api_key_suffix,null);});
t('revoked reads revoked', ()=>assert.strictEqual(keyStatus(get(1)),'revoked'));
t('regenerate after revoke restores active', ()=>{const nk=setPublisherKey(1);assert.strictEqual(keyStatus(get(1)),'active');assert.strictEqual(get(1).api_key_suffix,nk.slice(-8));});

console.log('Repair migration (broken rows: hash set, suffix NULL):');
// inject a broken row exactly like the old bug produced
db.prepare("INSERT INTO publishers (id,username,api_key,api_key_hash,api_key_suffix) VALUES (3,'p3',NULL,?,NULL)").run(hashKey('kom_live_orphanhash'));
t('broken row initially reads active but has NO suffix', ()=>{const p=get(3);assert.strictEqual(keyStatus(p),'active');assert.strictEqual(keySuffixOf(p),null);});
// run repair migration
const broken = db.prepare('SELECT id FROM publishers WHERE api_key_hash IS NOT NULL AND (api_key_suffix IS NULL OR api_key_suffix = ?)').all('');
for(const p of broken){const k=genKey();db.prepare('UPDATE publishers SET api_key_hash=?, api_key_suffix=? WHERE id=?').run(hashKey(k),k.slice(-8),p.id);}
t('after repair: broken row now has a suffix', ()=>assert.ok(keySuffixOf(get(3))));
t('after repair: still active', ()=>assert.strictEqual(keyStatus(get(3)),'active'));
t('repair is idempotent (2nd run touches nothing)', ()=>{const before=get(3).api_key_hash;const again=db.prepare('SELECT id FROM publishers WHERE api_key_hash IS NOT NULL AND (api_key_suffix IS NULL OR api_key_suffix = ?)').all('');assert.strictEqual(again.length,0);assert.strictEqual(get(3).api_key_hash,before);});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail?1:0);
