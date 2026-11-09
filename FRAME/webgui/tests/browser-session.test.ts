import './dom.ts';
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { readFileSync } from 'node:fs';
import { act, createElement, useEffect } from 'react';
import { createRoot } from 'react-dom/client';
import { Window } from 'happy-dom';
import { HttpAdminService } from '../src/service/HttpAdminService.ts';
import type { BrowserSession, BrowserSessionService } from '../src/service/BrowserSessionService.ts';

const remote = { mode: 'remote' as const, authenticated: false, frame_id: 'frame-1', profile: { signature: 'signed-profile' } };

test('browser session transport uses only relative marked no-store same-origin cookie requests', async () => {
  const { HttpBrowserSessionService } = await import('../src/service/BrowserSessionService.ts');
  const calls: { url: string; init: RequestInit }[] = [];
  const service = new HttpBrowserSessionService(async function (this: unknown, url, init) {
    assert.equal(this, undefined);
    calls.push({ url: String(url), init: init! });
    return Response.json(remote);
  });
  assert.deepEqual(await service.load(), remote);
  await service.login('secret argument');
  await service.logout();
  assert.deepEqual(calls.map(c => c.url), Array(3).fill('/api/browser/session'));
  assert.deepEqual(calls.map(c => c.init.method), ['GET', 'POST', 'DELETE']);
  for (const { init } of calls) {
    assert.equal(init.credentials, 'same-origin');
    assert.equal(init.cache, 'no-store');
    assert.equal(new Headers(init.headers).get('X-Comb-Webgui'), '1');
  }
  assert.equal(new Headers(calls[1].init.headers).get('Content-Type'), 'application/json');
  assert.deepEqual(JSON.parse(calls[1].init.body as string), { token: 'secret argument' });
  assert.equal(calls[0].init.body, undefined);
  assert.equal(calls[2].init.body, undefined);
});

function fakeService(overrides: Partial<BrowserSessionService> = {}): BrowserSessionService {
  return { load: async () => remote, login: async () => ({ ...remote, authenticated: true }), logout: async () => remote, ...overrides };
}

test('presenter observes local or remote session, login and logout without retaining tokens', async () => {
  const { BrowserSessionPresenter } = await import('../src/presenter/BrowserSessionPresenter.ts');
  const tokens: string[] = [];
  const presenter = new BrowserSessionPresenter(fakeService({ login: async token => { tokens.push(token); return { ...remote, authenticated: true }; } }));
  let updates = 0;
  const unsubscribe = presenter.subscribe(() => updates++);
  assert.equal(presenter.state.session, null);
  await presenter.load();
  assert.deepEqual(presenter.state.session, remote);
  assert.equal(await presenter.login(''), false);
  assert.match(presenter.state.error, /token/i);
  assert.equal(tokens.length, 0);
  assert.equal(await presenter.login('transient-secret'), true);
  assert.equal((presenter.state.session as BrowserSession | null)?.authenticated, true);
  assert.deepEqual(tokens, ['transient-secret']);
  assert.doesNotMatch(JSON.stringify(presenter), /transient-secret/);
  assert.equal(await presenter.logout(), true);
  assert.equal((presenter.state.session as BrowserSession | null)?.authenticated, false);
  assert.ok(updates > 0);
  unsubscribe();
  const before = updates;
  await presenter.load();
  assert.equal(updates, before);
  const local = new BrowserSessionPresenter(fakeService({ load: async () => ({ ...remote, mode: 'local', authenticated: false }) }));
  await local.load();
  assert.equal(local.state.session?.mode, 'local');
});

async function mounted(presenter: any, check: (container: HTMLDivElement, window: Window) => Promise<void>, child?: any) {
  const { BrowserSessionView } = await import('../src/views/BrowserSessionView.tsx');
  const window = new Window({ url: 'https://frame.example/' });
  const previous = { window: globalThis.window, document: globalThis.document };
  Object.assign(globalThis, { window, document: window.document, IS_REACT_ACT_ENVIRONMENT: true });
  const container = document.createElement('div');
  const root = createRoot(container);
  try {
    await act(async () => root.render(createElement(BrowserSessionView, { presenter }, child ?? createElement('div', { id: 'private' }, 'Private repository'))));
    await check(container, window);
  } finally {
    await act(async () => root.unmount());
    Object.assign(globalThis, previous);
    delete (globalThis as any).IS_REACT_ACT_ENVIRONMENT;
    await window.happyDOM.close();
  }
}

async function typeToken(container: HTMLElement, window: Window, value: string) {
  const input = container.querySelector('input')!;
  await act(async () => {
    Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')!.set!.call(input, value);
    input.dispatchEvent(new window.Event('input', { bubbles: true }) as any);
  });
}

test('local gate transparently renders children without any credential UI or toolbar', async () => {
  const { BrowserSessionPresenter } = await import('../src/presenter/BrowserSessionPresenter.ts');
  const presenter = new BrowserSessionPresenter(fakeService({ load: async () => ({ ...remote, mode: 'local' }) }));
  await mounted(presenter, async (container, window) => {
    const original = container.querySelector('#private');
    await act(async () => window.dispatchEvent(new window.Event('focus')));
    assert.equal(container.querySelector('#private'), original);
    assert.equal(container.innerHTML, '<div id="private">Private repository</div>');
  });
});

test('remote gate mounts private children only after login, clears token and unmounts on expiry', async () => {
  const { BrowserSessionPresenter } = await import('../src/presenter/BrowserSessionPresenter.ts');
  const tokens: string[] = [];
  const presenter = new BrowserSessionPresenter(fakeService({ login: async token => { tokens.push(token); return { ...remote, authenticated: true }; } }));
  let mounts = 0;
  let unmounts = 0;
  function Private() {
    useEffect(() => { mounts++; return () => { unmounts++; }; }, []);
    return createElement('div', { id: 'private' }, 'Private repository');
  }
  await mounted(presenter, async (container, window) => {
    assert.equal(mounts, 0);
    assert.equal(container.querySelector('#private'), null);
    assert.match(container.textContent!, /remote admin management token/i);
    assert.match(container.textContent!, /not.*FRAME unlock.*SSH password/i);
    assert.equal(container.querySelector('#browser-token')?.getAttribute('type'), 'password');
    await typeToken(container, window, 'transient-login-token');
    const input = container.querySelector('input')!;
    await act(async () => container.querySelector('form')!.dispatchEvent(new window.Event('submit', { bubbles: true, cancelable: true }) as any));
    assert.deepEqual(tokens, ['transient-login-token']);
    assert.equal(input.value, '');
    assert.equal(mounts, 1);
    assert.ok(container.querySelector('#private'));
    assert.match(container.textContent!, /frame-1/);
    assert.match(container.textContent!, /signed-profile/);
    assert.match(container.textContent!, /out-of-band/i);
    assert.match(container.textContent!, /does not.*(prove|verify)/i);
    assert.equal(container.querySelector('input'), null);
    await act(async () => { await presenter.sessionExpired(); });
    assert.equal(unmounts, 1);
    assert.equal(container.querySelector('#private'), null);
    assert.equal(container.querySelector('input')!.value, '');
    await typeToken(container, window, 'next-token');
    await act(async () => container.querySelector('form')!.dispatchEvent(new window.Event('submit', { bubbles: true, cancelable: true }) as any));
    await act(async () => Array.from(container.querySelectorAll('button')).find(b => b.textContent === 'Sign out')!.click());
    assert.equal(container.querySelector('#private'), null);
    assert.equal(unmounts, 2);
  }, createElement(Private));
});

test('unavailable backend remains gated with retry and local unlock guidance', async () => {
  const { BrowserSessionPresenter } = await import('../src/presenter/BrowserSessionPresenter.ts');
  let attempts = 0;
  const presenter = new BrowserSessionPresenter(fakeService({ load: async () => { if (++attempts === 1) throw new Error('Locked'); return { ...remote, mode: 'local' }; } }));
  await mounted(presenter, async container => {
    assert.equal(container.querySelector('#private'), null);
    assert.ok(container.querySelector('[role="alert"]'));
    assert.match(container.textContent!, /unlock.*FRAME.*locally/i);
    await act(async () => container.querySelector('button')!.click());
    assert.ok(container.querySelector('#private'));
    assert.equal(attempts, 2);
  });
});

test('main gates the routed app and constructs fresh private presenters on each mount', () => {
  const main = readFileSync(new URL('../src/main.tsx', import.meta.url), 'utf8');
  assert.match(main, /<BrowserSessionView presenter=\{session\}>/);
  assert.match(main, /function PrivateApp\(/);
  assert.match(main, /useState\(\(\) => new AdminPresenter\(service\)\)/);
  assert.match(main, /useState\(\(\) => new RepositoryPresenter\(service\)\)/);
  assert.match(main, /new HttpAdminService\(undefined,.*session\.sessionExpired\(/);
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}

test('management 401 immediately hides session and rechecks, ignoring stale login completion', async () => {
  const { BrowserSessionPresenter } = await import('../src/presenter/BrowserSessionPresenter.ts');
  const pending = deferred<BrowserSession>();
  const recheck = deferred<BrowserSession>();
  let loads = 0;
  const presenter = new BrowserSessionPresenter(fakeService({
    load: async () => ++loads === 1 ? { ...remote, authenticated: true } : recheck.promise,
    login: async () => pending.promise,
  }));
  await presenter.load();
  const login = presenter.login('secret');
  const admin = new HttpAdminService(async () => new Response('', { status: 401 }), () => { void presenter.sessionExpired(); });
  await assert.rejects(admin.status(), /401/);
  assert.equal(presenter.state.session, null);
  assert.equal(loads, 2);
  pending.resolve({ ...remote, authenticated: true });
  assert.equal(await login, false);
  assert.equal(presenter.state.session, null);
  recheck.resolve(remote);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal((presenter.state.session as BrowserSession | null)?.authenticated, false);
});

test('load, login and logout fail closed without reflecting server secrets', async () => {
  const { BrowserSessionPresenter } = await import('../src/presenter/BrowserSessionPresenter.ts');
  const fail = async () => { throw new Error('secret-reflected-token'); };
  const presenter = new BrowserSessionPresenter(fakeService({ load: fail, login: fail, logout: fail }));
  assert.equal(await presenter.load(), false);
  assert.equal(presenter.state.session, null);
  assert.ok(presenter.state.error);
  assert.equal(await presenter.login('secret-reflected-token'), false);
  assert.doesNotMatch(JSON.stringify(presenter.state), /secret-reflected-token/);
  const authenticated = new BrowserSessionPresenter(fakeService({ load: async () => ({ ...remote, authenticated: true }), logout: fail }));
  await authenticated.load();
  const logout = authenticated.logout();
  assert.equal(authenticated.state.session, null);
  assert.equal(await logout, false);
  assert.equal(authenticated.state.session, null);
  assert.ok(authenticated.state.error);
});

