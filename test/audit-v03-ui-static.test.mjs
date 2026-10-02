import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';

test('v0.3 independent static UI check: literal controls resolve uniquely and untrusted text has no HTML/code sink',async()=>{
 const html=await fs.readFile(new URL('../ui/index.html',import.meta.url),'utf8'),js=await fs.readFile(new URL('../ui/app.js',import.meta.url),'utf8');
 const ids=[...html.matchAll(/\bid="([^"]+)"/g)].map(match=>match[1]);
 assert.equal(new Set(ids).size,ids.length,'Duplicate HTML IDs break control ownership');
 const refs=[...js.matchAll(/\$\('([^']+)'\)/g)].map(match=>match[1]);
 assert.deepEqual([...new Set(refs.filter(id=>!ids.includes(id)))],[],'JavaScript references nonexistent controls');
 assert.doesNotMatch(js,/innerHTML|insertAdjacentHTML|\beval\s*\(|new\s+Function\s*\(|localStorage|sessionStorage/);
 assert.doesNotMatch(html,/<script\b[^>]*>(?!\s*<\/script>)[\s\S]+?<\/script>/);
 assert.match(js,/history\.replaceState\(null, '', location\.pathname\)/);
 assert.match(js,/incoming \? 'cancelTask' : 'cancel'/);
 assert.match(js,/reconcileJob/);assert.match(js,/jobCancel/);assert.match(js,/expectedEpoch/);
 // This source-level check does not claim browser rendering, clicking or history tests.
});
