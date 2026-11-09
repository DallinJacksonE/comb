import { test } from 'node:test';
import assert from 'node:assert/strict';
import { act, createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createRoot } from 'react-dom/client';
import { Window } from 'happy-dom';
import { AdminView } from '../src/views/AdminView.tsx';
import { AdminPresenter } from '../src/presenter/AdminPresenter.ts';
import { MemoryRouter } from 'react-router-dom';
const view = (props: Parameters<typeof AdminView>[0]) => createElement(MemoryRouter, {}, createElement(AdminView, props));

const status = { identity: { id: 'me', name: 'Ada', email: 'ada@local' }, frame: { id: 'frame', active: true }, cells: 1, capabilities: ['git'] };
test('unavailable view offers unlock guidance and Retry without a token form', () => {
  const p = new AdminPresenter({} as any);
  p.state = { ...p.state, error: 'Failed to fetch' };
  const html = renderToStaticMarkup(view({ presenter: p, origin: 'http://localhost:7331' }));
  assert.match(html, /Frame unavailable/);
  assert.match(html, /comb/);
  assert.match(html, /unlock/i);
  assert.match(html, /Retry/);
  assert.doesNotMatch(html, /type="password"|Local management token|<form|Disconnect/);
});

test('connected list links to a dedicated stable repository page rather than inline details', () => {
  const p = new AdminPresenter({} as any);
  const cell = { id: 'real-id', name: 'garden', slug: 'garden', owner: 'me', version: 'v1', refs: { 'refs/heads/main': 'abc123' }, members: { me: 'owner' } };
  p.state = { ...p.state, status, cells: [cell], detail: cell };
  const html = renderToStaticMarkup(view({ presenter: p, origin: 'http://localhost:7331' }));
  for (const text of ['Ada', 'garden', 'href="/cells/real-id"', 'configured peer', 'Register peer', 'Refresh', 'New CELL']) assert.ok(html.includes(text), text);
  assert.doesNotMatch(html, /New issue|Explore \+/);
  assert.doesNotMatch(html, /Disconnect/);
});

test('mount connects automatically; Retry reconnects after failure and Refresh reloads', async () => {
  const window = new Window({ url: 'http://localhost:7331' });
  const previous = { window: globalThis.window, document: globalThis.document };
  Object.assign(globalThis, { window, document: window.document, IS_REACT_ACT_ENVIRONMENT: true });
  let calls = 0;
  const p = new AdminPresenter({ status: async () => { calls++; if (calls === 1) throw new TypeError('Failed to fetch'); return status; }, cells: async () => [], peers: async () => [] } as any);
  const container = document.createElement('div');
  const root = createRoot(container);
  try {
    await act(async () => { root.render(view({ presenter: p, origin: window.location.origin })); });
    assert.equal(calls, 1);
    assert.match(container.textContent!, /Frame unavailable/);
    const button = (text: string) => Array.from(container.querySelectorAll('button')).find(b => b.textContent === text)!;
    await act(async () => { button('Retry').click(); });
    assert.equal(calls, 2);
    assert.match(container.textContent!, /Ada/);
    await act(async () => { button('Refresh').click(); });
    assert.equal(calls, 3);
  } finally {
    await act(async () => { root.unmount(); });
    Object.assign(globalThis, previous);
    delete (globalThis as any).IS_REACT_ACT_ENVIRONMENT;
    await window.happyDOM.close();
  }
});
