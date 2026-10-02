import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { DurableStore } from '../src/durable.mjs';

test('interrupted durable staging is discarded, never promoted or allowed to grow across restarts', async()=>{
  const directory=await fs.mkdtemp(path.join(os.tmpdir(),'durable-staging-'));
  try {
    new DurableStore({directory}).open().put('peer:kept',{state:'completed',response:{value:'committed'}});
    const orphan=`.${createHash('sha256').update('peer:never-committed').digest('hex')}.json.${randomUUID()}.tmp`;
    await fs.writeFile(path.join(directory,orphan),'{partial', {mode:0o600});
    const reopened=new DurableStore({directory}).open();
    assert.equal(reopened.get('peer:kept').response.value,'committed');
    assert.equal(reopened.get('peer:never-committed'),undefined);
    await assert.rejects(fs.stat(path.join(directory,orphan)),{code:'ENOENT'});
  } finally {await fs.rm(directory,{recursive:true,force:true});}
});
