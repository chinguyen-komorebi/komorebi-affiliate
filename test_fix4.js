// Test #4 — per-PID gating: approval mode + per-PID run state (two independent controls)
const assert = require('node:assert');
const { DatabaseSync } = require('node:sqlite');
const db = new DatabaseSync(':memory:');
db.exec(`
  CREATE TABLE publishers (id INTEGER PRIMARY KEY);
  CREATE TABLE advertisers (id INTEGER PRIMARY KEY, pid_approval_required INTEGER NOT NULL DEFAULT 0);
  CREATE TABLE publisher_pids (id INTEGER PRIMARY KEY AUTOINCREMENT, publisher_id INTEGER, advertiser_id INTEGER,
    sub_id TEXT NOT NULL, approval_state TEXT NOT NULL DEFAULT 'approved', run_state TEXT NOT NULL DEFAULT 'running',
    note TEXT, created_at TEXT, decided_at TEXT, UNIQUE(publisher_id,advertiser_id,sub_id));
`);
db.prepare("INSERT INTO publishers (id) VALUES (1)").run();
db.prepare("INSERT INTO advertisers (id,pid_approval_required) VALUES (10,0)").run(); // auto mode
db.prepare("INSERT INTO advertisers (id,pid_approval_required) VALUES (20,1)").run(); // approve-first mode

// mirror of checkPidAllowed
function checkPidAllowed(pubRow, advRow, subId){
  if(!subId) return null;
  const approvalMode = advRow.pid_approval_required ? 1 : 0;
  let pid = db.prepare('SELECT * FROM publisher_pids WHERE publisher_id=? AND advertiser_id=? AND sub_id=?').get(pubRow.id,advRow.id,subId);
  if(!pid){
    const approvalState = approvalMode ? 'pending' : 'approved';
    const decidedAt = approvalMode ? null : '2026-07-29 10:00:00';
    db.prepare(`INSERT INTO publisher_pids (publisher_id,advertiser_id,sub_id,approval_state,run_state,decided_at) VALUES (?,?,?,?,'running',?)`).run(pubRow.id,advRow.id,subId,approvalState,decidedAt);
    if(approvalMode) return {reason:'pid_pending_approval'};
    return null;
  }
  if(pid.run_state==='paused') return {reason:'pid_paused'};
  if(pid.approval_state==='rejected') return {reason:'pid_rejected'};
  if(pid.approval_state==='pending') return {reason:'pid_pending_approval'};
  return null;
}
const adv=(id)=>db.prepare('SELECT * FROM advertisers WHERE id=?').get(id);
const getPid=(sub,advId)=>db.prepare('SELECT * FROM publisher_pids WHERE sub_id=? AND advertiser_id=?').get(sub,advId);

let pass=0,fail=0;
const t=(name,fn)=>{try{fn();console.log('  ✓',name);pass++;}catch(e){console.log('  ✗',name,'\n     ',e.message);fail++;}};

console.log('No sub_id → exempt:');
t('null sub_id always allowed', ()=>assert.strictEqual(checkPidAllowed({id:1},adv(10),null),null));

console.log('Auto mode (pid_approval_required=0) — network-friendly:');
t('unknown PID auto-approved → allowed immediately', ()=>assert.strictEqual(checkPidAllowed({id:1},adv(10),'subNEW'),null));
t('auto-created PID is approved+running', ()=>{const p=getPid('subNEW',10);assert.strictEqual(p.approval_state,'approved');assert.strictEqual(p.run_state,'running');});
t('same PID second hit still allowed', ()=>assert.strictEqual(checkPidAllowed({id:1},adv(10),'subNEW'),null));

console.log('Per-PID pause works EVEN IN AUTO MODE (the key ask):');
db.prepare("UPDATE publisher_pids SET run_state='paused' WHERE sub_id='subNEW' AND advertiser_id=10").run();
t('paused PID blocked though advertiser is auto-mode', ()=>assert.strictEqual(checkPidAllowed({id:1},adv(10),'subNEW').reason,'pid_paused'));
db.prepare("UPDATE publisher_pids SET run_state='running' WHERE sub_id='subNEW' AND advertiser_id=10").run();
t('un-paused PID allowed again', ()=>assert.strictEqual(checkPidAllowed({id:1},adv(10),'subNEW'),null));
t('pausing one PID does not affect another', ()=>{
  checkPidAllowed({id:1},adv(10),'subOTHER'); // create it
  db.prepare("UPDATE publisher_pids SET run_state='paused' WHERE sub_id='subNEW' AND advertiser_id=10").run();
  assert.strictEqual(checkPidAllowed({id:1},adv(10),'subOTHER'),null); // other still runs
  assert.strictEqual(checkPidAllowed({id:1},adv(10),'subNEW').reason,'pid_paused');
  db.prepare("UPDATE publisher_pids SET run_state='running' WHERE sub_id='subNEW' AND advertiser_id=10").run();
});

console.log('Approve-first mode (pid_approval_required=1):');
t('unknown PID → pending, blocked', ()=>assert.strictEqual(checkPidAllowed({id:1},adv(20),'subA').reason,'pid_pending_approval'));
t('created as pending', ()=>assert.strictEqual(getPid('subA',20).approval_state,'pending'));
t('still blocked while pending', ()=>assert.strictEqual(checkPidAllowed({id:1},adv(20),'subA').reason,'pid_pending_approval'));
db.prepare("UPDATE publisher_pids SET approval_state='approved', decided_at='2026-07-29 11:00:00' WHERE sub_id='subA' AND advertiser_id=20").run();
t('after admin approves → allowed', ()=>assert.strictEqual(checkPidAllowed({id:1},adv(20),'subA'),null));
db.prepare("UPDATE publisher_pids SET approval_state='rejected' WHERE sub_id='subA' AND advertiser_id=20").run();
t('rejected PID → blocked', ()=>assert.strictEqual(checkPidAllowed({id:1},adv(20),'subA').reason,'pid_rejected'));

console.log('Two controls independent — approved but paused:');
db.prepare("UPDATE publisher_pids SET approval_state='approved', run_state='paused' WHERE sub_id='subA' AND advertiser_id=20").run();
t('approved + paused → still blocked (pause wins)', ()=>assert.strictEqual(checkPidAllowed({id:1},adv(20),'subA').reason,'pid_paused'));


// ---- Publisher self-serve scoping (security-critical) ----
console.log('\nPublisher self-serve pause/run scoping:');
db.exec(`CREATE TABLE IF NOT EXISTS pub2 (x)`); // noop guard
// add a second publisher (id=2) with its own PID
db.prepare("INSERT INTO publishers (id) VALUES (2)").run();
db.prepare("INSERT INTO publisher_pids (publisher_id,advertiser_id,sub_id,approval_state,run_state) VALUES (2,10,'subZ','approved','running')").run();
const pidOfP2 = db.prepare("SELECT id FROM publisher_pids WHERE publisher_id=2 AND sub_id='subZ'").get().id;

// mirror of publisherPidAction ownership check
function publisherPidAction(pidId, publisherId, runState){
  const pid = db.prepare('SELECT * FROM publisher_pids WHERE id=? AND publisher_id=?').get(pidId, publisherId);
  if(!pid) return {ok:false, reason:'not_found_or_not_owned'};
  db.prepare('UPDATE publisher_pids SET run_state=? WHERE id=? AND publisher_id=?').run(runState, pidId, publisherId);
  return {ok:true};
}

t('publisher 1 CANNOT pause publisher 2\'s PID (ownership enforced)', ()=>{
  const r = publisherPidAction(pidOfP2, 1, 'paused'); // pub 1 tries to pause pub 2's PID
  assert.strictEqual(r.ok, false);
  // confirm P2's PID is still running (untouched)
  assert.strictEqual(db.prepare('SELECT run_state FROM publisher_pids WHERE id=?').get(pidOfP2).run_state, 'running');
});
t('publisher 2 CAN pause its own PID', ()=>{
  const r = publisherPidAction(pidOfP2, 2, 'paused');
  assert.strictEqual(r.ok, true);
  assert.strictEqual(db.prepare('SELECT run_state FROM publisher_pids WHERE id=?').get(pidOfP2).run_state, 'paused');
});
t('publisher 2 CAN run its own PID again', ()=>{
  const r = publisherPidAction(pidOfP2, 2, 'running');
  assert.strictEqual(r.ok, true);
  assert.strictEqual(db.prepare('SELECT run_state FROM publisher_pids WHERE id=?').get(pidOfP2).run_state, 'running');
});
t('nonexistent pid id → not found (no crash)', ()=>{
  assert.strictEqual(publisherPidAction(99999, 2, 'paused').ok, false);
});

console.log(`\n[publisher-scoping subtotal included above]`);

// ---- B1 (and B1-R): effective status — imports the REAL function from server.js ----
// This tests the actual pidEffectiveStatus used by both renders + mirrors
// checkPidAllowed, so UI can never drift from enforcement. Covers the mode=0 +
// pending/rejected combos that the previous (copy-paste) tests missed.
const { pidEffectiveStatus } = require('./pid-status');
console.log('\nB1/B1-R — effective status (real fn, all state combos):');
t('approved + running -> running', ()=>assert.strictEqual(pidEffectiveStatus('approved','running'),'running'));
t('pending + running -> NOT running (never green)', ()=>assert.strictEqual(pidEffectiveStatus('pending','running'),'not_running_pending'));
t('rejected + running -> NOT running (never green)', ()=>assert.strictEqual(pidEffectiveStatus('rejected','running'),'not_running_rejected'));
t('approved + paused -> paused', ()=>assert.strictEqual(pidEffectiveStatus('approved','paused'),'paused'));
t('pending + paused -> paused (pause wins over pending)', ()=>assert.strictEqual(pidEffectiveStatus('pending','paused'),'paused'));
// B1-R critical: a PID left pending/rejected while the advertiser is now Auto.
// The status does NOT depend on mode, so these are covered by the state alone —
// exactly the combo the old tests missed and that caused the false green.
t('B1-R: pending PID under (now) Auto advertiser still NOT running', ()=>assert.strictEqual(pidEffectiveStatus('pending','running'),'not_running_pending'));
t('B1-R: rejected PID under (now) Auto advertiser still NOT running', ()=>assert.strictEqual(pidEffectiveStatus('rejected','running'),'not_running_rejected'));
// Cross-check: effective status agrees with checkPidAllowed intent for every combo.
for (const asu of ['approved','pending','rejected']) for (const rs of ['running','paused']) {
  const eff = pidEffectiveStatus(asu, rs);
  const shouldConvert = (asu==='approved' && rs==='running');
  t(`consistency: (${asu},${rs}) running-badge iff convertible`, ()=>assert.strictEqual(eff==='running', shouldConvert));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail?1:0);
