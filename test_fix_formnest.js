// Regression test: publisher edit form must NOT contain nested <form> (breaks Save button)
const assert = require('node:assert');
const fs = require('fs');
const src = fs.readFileSync('./server.js','utf8');

let pass=0,fail=0;
const t=(n,fn)=>{try{fn();console.log('  ✓',n);pass++;}catch(e){console.log('  ✗',n,'\n     ',e.message);fail++;}};

console.log('Form-nesting hotfix — publisher edit:');
// locate the renderPubForm main edit form region
t('main edit form has id=pubEditForm', ()=>assert.ok(src.includes('id="pubEditForm"')));
t('key action buttons use form= attribute (not nested <form>)', ()=>{
  assert.ok(src.includes('form="regenKeyForm"'));
  assert.ok(src.includes('form="revokeKeyForm"'));
});
t('external key forms exist with matching ids', ()=>{
  assert.ok(src.includes('id="regenKeyForm"'));
  assert.ok(src.includes('id="revokeKeyForm"'));
});
t('data-confirm moved to external forms (submit event target)', ()=>{
  // the regenKeyForm form tag should carry data-confirm
  const m = src.match(/id="regenKeyForm"[^>]*data-confirm/);
  assert.ok(m, 'regenKeyForm should have data-confirm on the form');
});

console.log('Structural check — no <form> nested between pubEditForm open and its close:');
t('no nested form inside the main edit form body', ()=>{
  const start = src.indexOf('id="pubEditForm"');
  assert.ok(start>0);
  // find the matching close: the </form> that ends the edit form (before assignmentSection)
  const after = src.slice(start);
  const closeIdx = after.indexOf('${assignmentSection}');
  assert.ok(closeIdx>0);
  const region = after.slice(0, closeIdx);
  // Within the form body, the external key forms come AFTER </form>, so the region
  // up to the LAST </form> before assignmentSection should have no <form ... > opening
  // except the external ones which are after the main close.
  // Simpler: the main form close </form> must appear, and between open and that close,
  // there must be zero '<form' openings.
  const mainClose = region.indexOf('</form>');
  assert.ok(mainClose>0, 'main form must close');
  const body = region.slice(0, mainClose);
  const nestedOpen = body.indexOf('<form');
  assert.strictEqual(nestedOpen, -1, 'no <form> may open inside the main edit form body');
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail?1:0);
