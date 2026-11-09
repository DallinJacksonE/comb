import './dom.ts';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { RepositoryPresenter } from '../src/presenter/RepositoryPresenter.ts';
import { HttpAdminService } from '../src/service/HttpAdminService.ts';
import { createElement } from 'react';
import { renderToStaticMarkup as render } from 'react-dom/server';
import { MemoryRouter } from 'react-router-dom';
import { HistoryPanel } from '../src/views/HistoryPanel.tsx';
import { BranchesPanel } from '../src/views/BranchesPanel.tsx';

const cell = { id: 'c', name: 'Garden', slug: 'garden', owner: 'me', version: 'v', refs: { 'refs/heads/main': 'abc' }, members: {} };
const page = { revision: 'abc', commits: [{ id: 'abc', parents: [], author: 'Ada', authored_at: '2026-01-01T00:00:00Z', subject: 'Initial commit' }], has_more: true, next_offset: 30 };

test('history service encodes revision and offset without embedding credentials', async () => {
  let url = '';
  const service = new HttpAdminService((async (input: string) => {
    url = input;
    return { ok: true, json: async () => page };
  }) as any);
  assert.deepEqual(await service.history('c/a', 'refs/heads/feature/a', 30), page);
  assert.equal(url, '/api/cells/c%2Fa/history?revision=refs%2Fheads%2Ffeature%2Fa&offset=30');
});

test('presenter loads paginated history without fetching code or issues', async () => {
  const calls: unknown[][] = [];
  const presenter = new RepositoryPresenter({
    cell: async () => cell,
    history: async (...args: unknown[]) => { calls.push(args); return page; },
  } as any);
  await presenter.load('c', 'history', '', '', false, 30);
  assert.deepEqual(calls, [['c', 'refs/heads/main', 30]]);
  assert.deepEqual(presenter.state.history, page);
  assert.equal(presenter.state.historyOffset, 30);
  assert.equal(presenter.state.error, '');
  assert.equal(presenter.state.busy, false);
});

test('history links immutable snapshots and paginates using the resolved commit', () => {
  const presenter = new RepositoryPresenter({} as any);
  const html = render(createElement(MemoryRouter, {}, createElement(HistoryPanel, {
    cell, state: { ...presenter.state, revision: 'refs/heads/main', history: page },
  })));
  assert.match(html, /Initial commit/);
  assert.match(html, /Ada/);
  assert.match(html, /revision=abc/);
  assert.match(html, /offset=30/);
  assert.match(html, /Browse files/);
});

test('branch page excludes private refs and links each branch to code and history', () => {
  const presenter = new RepositoryPresenter({} as any);
  const html = render(createElement(MemoryRouter, {}, createElement(BranchesPanel, {
    cell: { ...cell, refs: { ...cell.refs, 'refs/heads/feature/a': 'def', 'refs/comb/private': 'secret' } },
    state: presenter.state,
  })));
  assert.match(html, /feature\/a/);
  assert.match(html, /refs%2Fheads%2Ffeature%2Fa/);
  assert.match(html, /history/);
  assert.doesNotMatch(html, /secret|private/);
});

test('late history requests cannot overwrite a new repository navigation', async () => {
  let resolve!: (value: typeof page) => void;
  const pending = new Promise<typeof page>(done => { resolve = done; });
  const presenter = new RepositoryPresenter({ cell: async (id: string) => ({ ...cell, id }), history: () => pending } as any);
  const old = presenter.load('old', 'history');
  await new Promise(done => setImmediate(done));
  await presenter.load('new', 'branches');
  resolve(page);
  await old;
  assert.equal(presenter.state.cell?.id, 'new');
  assert.equal(presenter.state.history, null);
});

test('late mutations cannot replace the newly navigated repository or clear its loading state', async () => {
  let resolve!: (value: typeof cell) => void;
  const pending = new Promise<typeof cell>(done => { resolve = done; });
  const presenter = new RepositoryPresenter({ cell: async (id: string) => ({ ...cell, id }), renameCell: () => pending } as any);
  await presenter.load('old', 'settings');
  const rename = presenter.rename('Renamed');
  await presenter.load('new', 'branches');
  resolve({ ...cell, id: 'old' });
  assert.equal(await rename, false);
  assert.equal(presenter.state.cell?.id, 'new');
  assert.equal(presenter.state.error, '');
});
