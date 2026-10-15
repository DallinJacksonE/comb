import { test } from 'node:test';
import assert from 'node:assert/strict';
import { HttpAdminService } from '../src/service/HttpAdminService.ts';

test('service sends bearer auth and exact backend paths/payloads without leaking token in URL', async () => {
  const calls: { url: string; init: RequestInit }[] = [];
  const service = new HttpAdminService(async (url, init) => { calls.push({ url: String(url), init: init! }); return new Response('{}', { status: 200 }); });
  service.setToken('secret');
  await service.status(); await service.cells(); await service.peers();
  await service.createCell('garden'); await service.cell('a/b'); await service.issues('a/b');
  await service.createIssue('a/b', 'Title', 'Body');
  await service.createPeer({ id: 'p', url: 'http://local', public_key: 'key' });
  assert.deepEqual(calls.map(c => c.url), ['/api/status', '/api/cells', '/api/peers', '/api/cells', '/api/cells/a%2Fb', '/api/cells/a%2Fb/issues', '/api/cells/a%2Fb/issues', '/api/peers']);
  for (const call of calls) assert.equal(new Headers(call.init.headers).get('Authorization'), 'Bearer secret');
  assert.equal(calls[3].init.method, 'POST');
  assert.deepEqual(JSON.parse(calls[3].init.body as string), { name: 'garden' });
  assert.deepEqual(JSON.parse(calls[6].init.body as string), { title: 'Title', body: 'Body' });
  assert.deepEqual(JSON.parse(calls[7].init.body as string), { id: 'p', url: 'http://local', public_key: 'key' });
  service.setToken('');
  await assert.rejects(service.status(), /token/i);
});

test('HTTP failures surface status and backend error without treating HTML as JSON', async () => {
  const service = new HttpAdminService(async () => new Response(JSON.stringify({ error: 'Wrong token' }), { status: 401 }));
  service.setToken('bad');
  await assert.rejects(service.status(), /401.*Wrong token/);
});
