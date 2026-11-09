import { test } from 'node:test';
import assert from 'node:assert/strict';
import { HttpAdminService } from '../src/service/HttpAdminService.ts';

test('transport is called without the service as its receiver', async () => {
  const service = new HttpAdminService(async function (this: unknown) {
    assert.equal(this, undefined, 'native browser fetch rejects a service object receiver');
    return new Response('{}', { status: 200 });
  });
  await service.status();
});

test('service requests same-origin API routes with webgui header and no credentials', async () => {
  const calls: { url: string; init: RequestInit }[] = [];
  const service = new HttpAdminService(async (url, init) => { calls.push({ url: String(url), init: init! }); return new Response('{}', { status: 200 }); });
  await service.status(); await service.cells(); await service.peers();
  await service.createCell('garden'); await service.cell('a/b'); await service.issues('a/b');
  await service.createIssue('a/b', 'Title', 'Body');
  await service.createPeer({ id: 'p', url: 'http://local', public_key: 'key' });
  assert.deepEqual(calls.map(c => c.url), ['/api/status', '/api/cells', '/api/peers', '/api/cells', '/api/cells/a%2Fb', '/api/cells/a%2Fb/issues', '/api/cells/a%2Fb/issues', '/api/peers']);
  for (const { init } of calls) {
    const headers = new Headers(init.headers);
    assert.equal(headers.get('X-Comb-Webgui'), '1');
    assert.equal(headers.get('Authorization'), null);
    assert.equal(headers.get('Sec-Fetch-Site'), null); // Browser supplies security metadata.
    assert.equal(headers.get('Origin'), null);
    assert.equal(init.credentials, 'same-origin');
    assert.equal(init.cache, 'no-store');
    assert.equal(headers.get('Content-Type'), init.body === undefined ? null : 'application/json');
    assert.equal(init.method, init.body === undefined ? 'GET' : 'POST');
  }
  assert.deepEqual(JSON.parse(calls[3].init.body as string), { name: 'garden' });
  assert.deepEqual(JSON.parse(calls[6].init.body as string), { title: 'Title', body: 'Body' });
  assert.deepEqual(JSON.parse(calls[7].init.body as string), { id: 'p', url: 'http://local', public_key: 'key' });
  assert.equal('setToken' in service, false);
});

test('HTTP failures surface status and backend error without treating HTML as JSON', async () => {
  const service = new HttpAdminService(async () => new Response(JSON.stringify({ error: 'Browser access denied' }), { status: 403 }));
  await assert.rejects(service.status(), /403.*Browser access denied/);
  const htmlService = new HttpAdminService(async () => new Response('<html>Unavailable</html>', { status: 503, statusText: 'Service Unavailable' }));
  await assert.rejects(htmlService.status(), /503.*Service Unavailable/);
});
