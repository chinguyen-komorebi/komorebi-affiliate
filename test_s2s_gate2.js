// Test S1 fix: outboundGate shared helper (test tool must reflect enforcement)
const assert = require('node:assert');
let pass=0,fail=0;
const t=(n,fn)=>{try{fn();console.log('  ✓',n);pass++;}catch(e){console.log('  ✗',n,'\n     ',e.message);fail++;}};

const { outboundGate } = require('./outbound-gate');

console.log('S1 — test tool gate mirrors enforcement (no false positive):');
t('standard mode + URL → disabled (standard_mode)', ()=>{
  const g=outboundGate({postback_url:'https://y.com',integration_mode:'standard',s2s_postback_active:1});
  assert.strictEqual(g.enabled,false); assert.strictEqual(g.reason,'standard_mode');
});
t('s2s mode + URL + NOT active → disabled (inactive)', ()=>{
  const g=outboundGate({postback_url:'https://y.com',integration_mode:'s2s_network',s2s_postback_active:0});
  assert.strictEqual(g.enabled,false); assert.strictEqual(g.reason,'inactive');
});
t('s2s mode + active + URL → ENABLED', ()=>{
  const g=outboundGate({postback_url:'https://y.com',integration_mode:'s2s_network',s2s_postback_active:1});
  assert.strictEqual(g.enabled,true);
});
t('portal_s2s + active + URL → enabled', ()=>{
  assert.strictEqual(outboundGate({postback_url:'https://y.com',integration_mode:'portal_s2s',s2s_postback_active:1}).enabled,true);
});
t('no URL → disabled (no_url)', ()=>{
  const g=outboundGate({postback_url:'',integration_mode:'s2s_network',s2s_postback_active:1});
  assert.strictEqual(g.reason,'no_url');
});
t('empty/whitespace URL → no_url', ()=>{
  assert.strictEqual(outboundGate({postback_url:'   ',integration_mode:'s2s_network',s2s_postback_active:1}).reason,'no_url');
});

console.log('The exact false-positive scenario UI/UX flagged:');
t('publisher with URL but standard mode: test would 200 but real fires NOTHING → gate.enabled false', ()=>{
  // Admin sees URL set, hits Send Test, gets 200 — but this gate says outbound is OFF.
  const g=outboundGate({postback_url:'https://yana.com/pb',integration_mode:'standard',s2s_postback_active:0});
  assert.strictEqual(g.enabled,false);
  // banner must warn (reason drives the message)
  assert.strictEqual(g.reason,'standard_mode');
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail?1:0);
