import './dom.ts';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { act, createElement } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { RepositoryRemotes } from '../src/views/RepositoryRemotes.tsx';
import { Window } from 'happy-dom';
import { AdminView } from '../src/views/AdminView.tsx';
import { AdminPresenter } from '../src/presenter/AdminPresenter.ts';
import { IssuesPanel } from '../src/views/IssuesPanel.tsx';
import { SettingsPanel } from '../src/views/SettingsPanel.tsx';
import { RepositoryView } from '../src/views/RepositoryView.tsx';
import { RepositoryPresenter } from '../src/presenter/RepositoryPresenter.ts';
import { CodePanel } from '../src/views/CodePanel.tsx';
import { readFileSync } from 'node:fs';

test('workspace theme shares button treatment with navigation actions and supports narrow layouts', () => {
  const css = readFileSync(new URL('../src/styles.css', import.meta.url), 'utf8');
  assert.match(css, /button,\s*\.button\s*\{/);
  assert.match(css, /button\.secondary,\s*\.button\.secondary\s*\{/);
  assert.match(css, /--header:\s*#292e26/);
  assert.match(css, /--link:\s*#476044/);
  assert.match(css, /--accent:\s*#e6b64d/);
  assert.match(css, /:focus-visible/);
  assert.match(css, /@media \(max-width: 600px\)/);
});

test('code browser groups branch navigation and labels the file browser with its revision', async () => {
  const state = { revision: 'refs/heads/main', path: 'src', blob: null, readme: null, tree: { revision: 'abcdef123456', entries: [{ name: 'app.ts', path: 'src/app.ts', kind: 'blob', size: 30 }] } };
  await mounted(createElement(CodePanel, { state: state as any, cell }), async container => {
    assert.ok(container.querySelector('.code-toolbar #branch'));
    assert.ok(container.querySelector('.code-toolbar nav[aria-label="Code path"]'));
    assert.ok(container.querySelector('.file-browser .file-list'));
    assert.match(container.querySelector('.file-browser')!.textContent!, /abcdef1234/);
    assert.ok(container.querySelector('a[href*="file=1"]'));
  });
});

test('repository history paging follows offset links and defaults malformed offsets safely', async () => {
  for (const [query, expected] of [['30', 30], ['-1', 0], ['10001', 0], ['1.5', 0], ['no', 0]] as const) {
    const offsets: number[] = [];
    const presenter = new RepositoryPresenter({
      cell: async () => cell,
      history: async (_id: string, _revision: string, offset: number) => {
        offsets.push(offset);
        return { revision: 'a', commits: [], has_more: true, next_offset: offset + 30 };
      },
    } as any);
    const view = createElement(Routes, {}, createElement(Route, { path: '/cells/:id/history', element: createElement(RepositoryView, { presenter, origin: 'http://localhost', tab: 'history' }) }));
    await mounted(view, async container => {
      assert.deepEqual(offsets, [expected]);
      assert.ok(container.querySelector('a[href="/cells/c/branches"]'));
      assert.match(container.textContent!, /Commit history/);
      const older = Array.from(container.querySelectorAll('a')).find(a => a.textContent === 'Older commits')!;
      await act(async () => older.click());
      assert.deepEqual(offsets, [expected, expected + 30]);
    }, `/cells/c/history?offset=${query}`);
  }
});

test('collaborator settings use profile grants and never offer to revoke the owner', async () => {
  await mounted(createElement(SettingsPanel, { presenter: {} as any, cell, busy: false }), async container => {
    const rows = Array.from(container.querySelectorAll('.member-list li'));
    assert.equal(rows.length, 2);
    assert.equal(rows.find(row => row.textContent?.includes('me'))?.querySelector('button'), null);
    assert.equal(rows.find(row => row.textContent?.includes('other'))?.querySelector('button')?.textContent, 'Revoke');
    assert.match(container.textContent!, /profile JSON/i);
    assert.match(container.textContent!, /no username lookup/i);
    assert.ok(container.querySelector('#member-profile'));
  });
});

test('issues search and status filters retain expandable details and the visible create form', async () => {
  const issues = [
    { id: 'i1', title: 'Fix garden', body: 'Water the plants', closed: false },
    { id: 'i2', title: 'Archive seeds', body: 'Stored safely', closed: true },
  ];
  await mounted(createElement(IssuesPanel, { presenter: {} as any, state: { issues, busy: false } as any }), async (container, window) => {
    assert.ok(container.querySelector('#issue-title'));
    assert.equal(container.querySelectorAll('.issue-list details').length, 2);
    const select = container.querySelector('#issue-status') as HTMLSelectElement;
    assert.ok(select);
    await act(async () => { select.value = 'closed'; select.dispatchEvent(new window.Event('change', { bubbles: true }) as any); });
    assert.doesNotMatch(container.querySelector('.issue-list')!.textContent!, /Fix garden/);
    assert.match(container.querySelector('.issue-list')!.textContent!, /Archive seeds/);
    await change(container, window, '#issue-search', 'water');
    assert.match(container.textContent!, /No issues match/);
    await act(async () => { select.value = 'open'; select.dispatchEvent(new window.Event('change', { bubbles: true }) as any); });
    assert.match(container.querySelector('.issue-list')!.textContent!, /Fix garden/);
    assert.equal(container.querySelector('.issue-list details')!.hasAttribute('open'), false);
    assert.ok(container.querySelector('#issue-body'));
  });
});

async function change(container: HTMLElement, window: Window, selector: string, value: string) {
  const input = container.querySelector(selector) as HTMLInputElement;
  await act(async () => {
    Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')!.set!.call(input, value);
    input.dispatchEvent(new window.Event('input', { bubbles: true }) as any);
  });
}

test('dashboard filters repositories and sorts by name with branch counts', async () => {
  const presenter = new AdminPresenter({
    status: async () => ({ identity: { id: 'me', name: 'Ada', email: 'a@b' }, frame: { id: 'f', active: true }, cells: 2, capabilities: [] }),
    cells: async () => [{ ...cell, id: 'z', name: 'Zebra' }, { ...cell, id: 'a', name: 'Alpha' }],
    peers: async () => [],
  } as any);
  await mounted(createElement(AdminView, { presenter, origin: 'http://localhost' }), async (container, window) => {
    assert.deepEqual(Array.from(container.querySelectorAll('.repo-row strong')).map(x => x.textContent), ['Alpha', 'Zebra']);
    assert.match(container.querySelector('.repo-list')!.textContent!, /1 branch/);
    assert.ok(container.querySelector('#repository-filter'));
    await change(container, window, '#repository-filter', 'zeb');
    assert.deepEqual(Array.from(container.querySelectorAll('.repo-row strong')).map(x => x.textContent), ['Zebra']);
    assert.match(container.textContent!, /1 of 2 CELLs/);
    assert.equal(container.querySelector('#repo-name'), null);
    await act(async () => button(container, 'New CELL').click());
    assert.ok(container.querySelector('#repo-name'));
    assert.ok(container.querySelector('details.peer-configuration'));
  });
});

const cell = { id: 'c', name: 'Garden', slug: 'garden', owner: 'me', version: 'v', refs: { 'refs/heads/main': 'a' }, members: { me: 'owner', other: 'read' }, ssh_remote: 'comb-test:garden.git' };
async function mounted(component: any, check: (container: HTMLDivElement, window: Window) => Promise<void>, route = '/') {
  const window = new Window({ url: 'http://localhost/' });
  const previous = { window: globalThis.window, document: globalThis.document };
  Object.assign(globalThis, { window, document: window.document, IS_REACT_ACT_ENVIRONMENT: true });
  const container = document.createElement('div');
  const root = createRoot(container);
  try {
    await act(async () => root.render(createElement(MemoryRouter, { initialEntries: [route] }, component)));
    await check(container, window);
  } finally {
    await act(async () => root.unmount());
    Object.assign(globalThis, previous);
    delete (globalThis as any).IS_REACT_ACT_ENVIRONMENT;
    await window.happyDOM.close();
  }
}
const button = (container: HTMLElement, name: string) => Array.from(container.querySelectorAll('button')).find(b => b.textContent === name)!;

test('Code clone disclosure preserves both remote inputs and reports clipboard denial honestly', async () => {
  await mounted(createElement(RepositoryRemotes, { cell, origin: 'http://localhost' }), async (container, window) => {
    assert.equal(container.querySelector('details > summary')?.textContent, 'Get the code ↗');
    assert.equal((container.querySelector('#git-remote') as HTMLInputElement).value, 'http://localhost/git/garden.git');
    assert.equal((container.querySelector('#ssh-remote') as HTMLInputElement).value, cell.ssh_remote);
    Object.defineProperty(window.navigator, 'clipboard', { configurable: true, value: { writeText: async () => { throw new Error('Denied'); } } });
    const previous = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
    Object.defineProperty(globalThis, 'navigator', { configurable: true, value: window.navigator });
    try {
      await act(async () => button(container, 'Copy SSH URL').click());
      assert.match(container.textContent!, /Could not copy.*select.*manually/i);
      assert.doesNotMatch(container.textContent!, /Copied SSH/);
      assert.match(container.textContent!, /Never embed credentials/);
    } finally {
      if (previous) Object.defineProperty(globalThis, 'navigator', previous); else delete (globalThis as any).navigator;
    }
  });
});
