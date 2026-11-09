import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AdminPresenter } from '../src/presenter/AdminPresenter.ts';

test('failed automatic connection clears stale state and retries without credentials', async () => {
  let fail = true;
  const { presenter: p } = fixture({ status: async () => { if (fail) throw new TypeError('Failed to fetch'); return status; } });
  p.state = { ...p.state, status, cells: [cell], detail: cell };
  assert.equal(await p.connect(), false);
  assert.match(p.state.error, /Failed to fetch/);
  assert.equal(p.state.busy, false);
  assert.equal(p.state.status, null);
  assert.deepEqual(p.state.cells, []);
  assert.equal(p.state.detail, null);
  fail = false;
  assert.equal(await p.connect(), true);
  assert.equal(p.state.error, '');
  assert.equal(p.state.status, status);
});

test('creating a repository validates names and returns success for form reset only after save', async () => {
  const saved: string[] = [];
  const { presenter: p } = fixture({ createCell: async (name: string) => { saved.push(name); if (name === 'fail') throw new Error('Disk unavailable'); return cell; } });
  await p.connect();
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
  await p.connect();
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
  await p.connect();
  assert.equal(await p.createPeer({ ...peer, id: '' }), false);
  assert.equal(await p.createPeer({ ...peer, url: 'javascript:bad' }), false);
  assert.equal(await p.createPeer(peer), true);
  assert.deepEqual(p.state.peers, [peer]);
});

export const cell = { id: 'cell-1', name: 'garden', slug: 'garden', owner: 'local', version: '1', refs: {}, members: {} };
export const status = { identity: { id: 'local', name: 'Ada', email: 'ada@local' }, frame: { id: 'frame-1', active: true }, cells: 1, capabilities: ['git'] };
export function fixture(overrides = {}) {
  const calls: unknown[] = [];
  const service = { status: async () => { calls.push('status'); return status; }, cells: async () => { calls.push('cells'); return [cell]; }, peers: async () => { calls.push('peers'); return []; }, ...overrides };
  const presenter = new AdminPresenter(service as any);
  return { presenter, calls };
}

test('automatic connection loads status and lists, deduplicating repeated calls while busy', async () => {
  let release!: (value: typeof status) => void;
  let requests = 0;
  const pending = new Promise<typeof status>(resolve => { release = resolve; });
  const { presenter: p, calls } = fixture({ status: () => { requests++; return pending; } });
  const first = p.connect();
  assert.equal(p.state.busy, true);
  assert.equal(await p.connect(), false);
  assert.equal(requests, 1);
  assert.deepEqual(calls, ['cells', 'peers']);
  release(status);
  assert.equal(await first, true);
  assert.equal(p.state.status?.identity.name, 'Ada');
  assert.deepEqual(p.state.cells, [cell]);
  assert.equal(p.state.busy, false);
  assert.equal(await p.connect(), true);
  assert.equal(requests, 2);
});
