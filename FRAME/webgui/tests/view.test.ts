import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { AdminView } from '../src/views/AdminView.tsx';
import { AdminPresenter } from '../src/presenter/AdminPresenter.ts';

test('view asks for a local token; connected view renders real identity, inline repo data and prototype limitations', () => {
  const p = new AdminPresenter({ setToken() {} } as any);
  let html = renderToStaticMarkup(createElement(AdminView, { presenter: p, origin: 'http://localhost:7331' }));
  assert.match(html, /Local management token/);
  assert.match(html, /type="password"/);
  assert.doesNotMatch(html, /Create account/);
  const cell = { id: 'real-id', name: 'garden', owner: 'me', version: 'v1', refs: { 'refs\/heads\/main': 'abc123' }, members: { me: 'owner' } };
  p.state = { ...p.state, status: { identity: { id: 'me', name: 'Ada', email: 'ada@local' }, frame: { id: 'frame', active: true }, cells: 1, capabilities: ['git'] }, cells: [cell], detail: cell };
  html = renderToStaticMarkup(createElement(AdminView, { presenter: p, origin: 'http://localhost:7331' }));
  for (const text of ['Ada', 'garden', 'abc123', 'http://localhost:7331/git/real-id.git', 'management token as the password', 'Not available', 'New issue', 'Register peer']) assert.ok(html.includes(text), text);
});
