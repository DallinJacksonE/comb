import { test } from 'node:test';
import assert from 'node:assert/strict';
import { HttpAdminService } from '../src/service/HttpAdminService.ts';
test('repository HTTP methods preserve exact API bodies and encode revision/path', async () => {
  const calls: {url: string; init: RequestInit}[] = [];
  const s = new HttpAdminService(async (url, init) => { calls.push({url: String(url), init: init!}); return new Response('{}'); });
  await s.tree('a/b', 'refs/heads/feature x', 'src/a b');
  await s.blob('a/b', 'main', 'README.md');
  await s.renameCell('a/b', 'New name'); await s.deleteCell('a/b', 'New name');
  const profile = { identity: { id: 'person' } };
  await s.grantMember('a/b', profile, 'write'); await s.registerFrame('a/b', profile);
  await s.revokeMember('a/b', 'person'); await s.backup('a/b');
  assert.deepEqual(calls.map(c => c.url), ['/api/cells/a%2Fb/tree?revision=refs%2Fheads%2Ffeature+x&path=src%2Fa+b','/api/cells/a%2Fb/blob?revision=main&path=README.md','/api/cells/a%2Fb/rename','/api/cells/a%2Fb/delete','/api/cells/a%2Fb/members','/api/cells/a%2Fb/frames','/api/cells/a%2Fb/revoke','/api/cells/a%2Fb/backup']);
  assert.deepEqual(calls.slice(2,7).map(c => JSON.parse(c.init.body as string)), [{name:'New name'},{confirmation:'New name'},{profile,role:'write'},profile,{identity_id:'person'}]);
  for (const c of calls) { assert.equal(new Headers(c.init.headers).get('X-Comb-Webgui'), '1'); assert.equal(c.init.credentials, 'same-origin'); }
});
