import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AdminPresenter } from '../src/presenter/AdminPresenter.ts';

test('blank tokens are rejected without contacting the service; failed connection reports error', async () => {
  const { presenter: p, calls } = fixture({ status: async () => { throw new Error('Unauthorized'); } });
  assert.equal(await p.connect('  '), false);
  assert.deepEqual(calls, []);
  assert.match(p.state.error, /token/i);
  assert.equal(await p.connect('bad'), false);
  assert.match(p.state.error, /Unauthorized/);
  assert.equal(p.state.busy, false);
  assert.equal(p.state.status, null);
});

test('creating a repository validates names and returns success for form reset only after save', async () => {
  const saved: string[] = [];
  const { presenter: p } = fixture({ createCell: async (name: string) => { saved.push(name); if (name === 'fail') throw new Error('Disk unavailable'); return cell; } });
  await p.connect('token');
  assert.equal(await p.createCell('  '), false);
  assert.deepEqual(saved, []);
  assert.equal(await p.createCell(' garden '), true);
  assert.deepEqual(saved, ['garden']);
  assert.equal(p.state.cells.length, 1);
  assert.equal(p.state.status?.cells, 1);
  assert.equal(await p.createCell('fail'), false);
  assert.match(p.state.error, /Disk unavailable/);
  assert.equal(p.state.busy, false);
});

test('inline repository details load refs and issues; issue create validates and appends actual response', async () => {
  const issue = { id: 'i1', title: 'Bug', body: 'details', closed: false };
  const { presenter: p } = fixture({ cell: async () => cell, issues: async () => [], createIssue: async (id: string, title: string, body: string) => { assert.deepEqual([id, title, body], ['cell-1', 'Bug', 'details']); return issue; } });
  await p.connect('token');
  assert.equal(await p.openCell('cell-1'), true);
  assert.deepEqual(p.state.detail, cell);
  assert.equal(await p.createIssue('', 'details'), false);
  assert.equal(await p.createIssue(' Bug ', 'details'), true);
  assert.deepEqual(p.state.issues, [issue]);
  await p.openCell('cell-1');
  assert.equal(p.state.detail, null);
});

test('peer registration requires complete fields and an http URL, preserves server errors', async () => {
  const peer = { id: 'neighbor', url: 'http://127.0.0.1:7441', public_key: 'public-key' };
  const { presenter: p } = fixture({ createPeer: async () => peer });
  await p.connect('token');
  assert.equal(await p.createPeer({ ...peer, id: '' }), false);
  assert.equal(await p.createPeer({ ...peer, url: 'javascript:bad' }), false);
  assert.equal(await p.createPeer(peer), true);
  assert.deepEqual(p.state.peers, [peer]);
});

export const cell = { id: 'cell-1', name: 'garden', owner: 'local', version: '1', refs: {}, members: {} };
export const status = { identity: { id: 'local', name: 'Ada', email: 'ada@local' }, frame: { id: 'frame-1', active: true }, cells: 1, capabilities: ['git'] };
export function fixture(overrides = {}) {
  const calls: unknown[] = [];
  const service = { setToken: (token: string) => calls.push(token), status: async () => status, cells: async () => [cell], peers: async () => [], ...overrides };
  const presenter = new AdminPresenter(service as any);
  return { presenter, calls };
}

test('connecting with a local token loads real status and lists, then disconnect clears session', async () => {
  const { presenter: p, calls } = fixture();
  const loading: boolean[] = [];
  p.subscribe(() => loading.push(p.state.busy));
  assert.equal(await p.connect(' local-secret '), true);
  assert.deepEqual(calls, ['local-secret']);
  assert.equal(p.state.status?.identity.name, 'Ada');
  assert.deepEqual(p.state.cells, [cell]);
  assert.ok(loading.includes(true));
  assert.equal(p.state.busy, false);
  p.disconnect();
  assert.equal(p.state.status, null);
  assert.deepEqual(p.state.cells, []);
  assert.equal(calls.at(-1), '');
});
