#!/usr/bin/env node
// Exercise the built GUI with real Chromium browser provenance, isolated from user data.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const binary = path.join(root, 'target/debug/comb');
const scratch = process.env.TMPDIR;
assert(scratch, 'Set TMPDIR to a private scratch directory');
const directory = await mkdtemp(path.join(scratch, 'comb-browser-'));
const data = path.join(directory, 'frame');
const env = { ...process.env, COMB_PASSWORD: 'browser-smoke-fixture-password' };
delete env.COMB_TOKEN;
const children = [];
let browserSocket;
let hostile;
const delay = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
async function until(probe, label) {
  console.log(`Checking: ${label}`);
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    try { const result = await probe(); if (result) return result; } catch { /* startup race */ }
    await delay(100);
  }
  throw new Error(`Timed out: ${label}`);
}
async function freePort() {
  const listener = net.createServer();
  await new Promise(resolve => listener.listen(0, '127.0.0.1', resolve));
  const port = listener.address().port;
  await new Promise(resolve => listener.close(resolve));
  return port;
}
function cli(arguments_) {
  console.log(`Fixture CLI: ${arguments_.filter(value => !value.startsWith('http:')).join(' ')}`);
  const result = spawnSync(binary, ['--data', data, ...arguments_], { env, encoding: 'utf8', timeout: 120000 });
  assert.equal(result.status, 0, 'Fixture CLI command failed (secret-bearing output withheld)');
  return result.stdout;
}
function start(command, arguments_) {
  const child = spawn(command, arguments_, { env, stdio: 'ignore' });
  children.push(child);
  return child;
}

try {
  cli(['user', '--name', 'Browser Fixture', '--email', 'browser@test']);
  const management = await freePort();
  const peer = await freePort();
  const debugging = await freePort();
  const origin = `http://127.0.0.1:${management}`;
  const servingArguments = ['--data', data, 'serve', '--managed', '--listen', `127.0.0.1:${management}`,
    '--ssh-listen', '127.0.0.1:0',
    '--peer-listen', `127.0.0.1:${peer}`, '--assets', path.join(root, 'FRAME/webgui/dist')];
  let daemon = start(binary, servingArguments);
  await until(() => {
    const result = spawnSync(binary, ['--data', data, 'service-status'], { env, stdio: 'ignore' });
    return result.status === 0;
  }, 'managed service readiness');
  cli(['webgui']);
  await until(async () => (await fetch(origin)).ok, 'unlocked HTTP listener');

  start(process.env.COMB_CHROMIUM || 'chromium', ['--headless', '--no-sandbox', '--disable-gpu',
    '--no-first-run', '--no-default-browser-check', '--disable-dev-shm-usage',
    `--user-data-dir=${path.join(directory, 'chromium')}`, `--remote-debugging-port=${debugging}`, 'about:blank']);
  const targets = await until(async () => {
    const response = await fetch(`http://127.0.0.1:${debugging}/json/list`);
    const targets = await response.json();
    return targets.find(target => target.type === 'page');
  }, 'Chromium debugging endpoint');
  browserSocket = new WebSocket(targets.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { browserSocket.onopen = resolve; browserSocket.onerror = reject; });
  let sequence = 0;
  const pending = new Map();
  browserSocket.onmessage = event => {
    const message = JSON.parse(event.data);
    if (pending.has(message.id)) {
      pending.get(message.id)(message);
      pending.delete(message.id);
    }
  };
  async function cdp(method, params = {}) {
    const id = ++sequence;
    const response = new Promise((resolve, reject) => {
      const timer = setTimeout(() => { pending.delete(id); reject(new Error(`CDP timeout: ${method}`)); }, 5000);
      pending.set(id, message => { clearTimeout(timer); resolve(message); });
    });
    browserSocket.send(JSON.stringify({ id, method, params }));
    const message = await response;
    assert(!message.error, JSON.stringify(message.error));
    return message.result;
  }
  async function evaluate(expression) {
    const response = await cdp('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
    assert(!response.exceptionDetails, JSON.stringify(response.exceptionDetails));
    return response.result.value;
  }
  await cdp('Page.navigate', { url: origin });
  try {
    await until(() => evaluate('document.body.innerText.includes("Browser Fixture")'), 'automatic GUI connection');
  } catch (error) {
    console.error(await evaluate('document.body.innerText'));
    throw error;
  }
  assert.equal(await evaluate('!!document.querySelector("input[type=password]")'), false);
  await evaluate('[...document.querySelectorAll("button")].find(b => b.textContent === "New CELL").click()');
  await until(() => evaluate('!!document.querySelector("#repo-name")'), 'create form');
  await evaluate(`(() => { const input = document.querySelector('#repo-name');
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, 'Browser-created CELL');
    input.dispatchEvent(new Event('input', { bubbles: true })); })()`);
  await delay(100);
  await evaluate('document.querySelector("#repo-name").form.requestSubmit()');
  await until(() => evaluate('document.body.innerText.includes("Browser-created CELL") && !document.querySelector("#repo-name")'), 'browser CELL creation and form reset');
  await cdp('Page.reload');
  await until(() => evaluate('document.body.innerText.includes("Browser-created CELL")'), 'automatic reconnect after reload');
  assert.equal(await evaluate('localStorage.length + sessionStorage.length'), 0);

  hostile = createServer((_, response) => { response.setHeader('Content-Type', 'text/html'); response.end('<title>Different origin fixture</title>'); });
  await new Promise(resolve => hostile.listen(0, '127.0.0.1', resolve));
  const hostileOrigin = `http://127.0.0.1:${hostile.address().port}`;
  await cdp('Page.navigate', { url: hostileOrigin });
  await until(() => evaluate('document.title === "Different origin fixture"'), 'different-origin page');
  const blocked = await evaluate(`fetch(${JSON.stringify(origin + '/api/cells')}, { method: 'POST',
    headers: { 'X-Comb-Webgui': '1', 'Content-Type': 'application/json' }, body: JSON.stringify({ name: 'Unauthorized CELL' })
  }).then(() => false, () => true)`);
  assert.equal(blocked, true, 'An unrelated origin must not gain management access');
  await cdp('Page.navigate', { url: origin });
  await until(() => evaluate('document.body.innerText.includes("Browser-created CELL")'), 'return to GUI');
  assert.equal(await evaluate('document.body.innerText.includes("Unauthorized CELL")'), false);

  // Already-loaded pages must stop managing when the daemon restarts locked.
  daemon.kill('SIGTERM');
  await new Promise(resolve => daemon.once('exit', resolve));
  daemon = start(binary, servingArguments);
  await until(() => {
    const result = spawnSync(binary, ['--data', data, 'service-status'], { env, stdio: 'ignore' });
    return result.status === 0;
  }, 'locked restart');
  await evaluate('[...document.querySelectorAll("button")].find(b => /refresh/i.test(b.textContent)).click()');
  await until(() => evaluate('document.body.innerText.includes("comb cell list")'), 'unlock guidance after restart');
  cli(['webgui']);
  await evaluate('[...document.querySelectorAll("button")].find(b => /retry/i.test(b.textContent)).click()');
  await until(() => evaluate('document.body.innerText.includes("Browser-created CELL")'), 'retry after CLI unlock');

  const cell = JSON.parse(cli(['--api-url', origin, 'cell', 'list'])).find(cell => cell.name === 'Browser-created CELL');
  assert.equal(cell.slug, 'browser-created-cell');
  const credential = cli(['token']).trim();
  const work = path.join(directory, 'work');
  await mkdir(path.join(work, 'src'), { recursive: true });
  const readme = '# Browser README\n\nThis **renders safely**.\n\n<script>window.__readmeUnsafe = true</script>\n\n![remote](https://invalid.example/tracker)\n\n[unsafe](javascript:alert(1))\n';
  await writeFile(path.join(work, 'README.md'), readme);
  await writeFile(path.join(work, 'src', 'main.rs'), 'fn main() { println!("browser-code-fixture"); }\n');
  const git = (args, cwd = work) => {
    console.log(`Fixture Git: ${args[0]}`);
    const result = spawnSync('git', ['-c', `http.extraHeader=Authorization: Bearer ${credential}`, ...args], {
      cwd, env: { ...env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0',
        GIT_AUTHOR_NAME: 'Fixture', GIT_AUTHOR_EMAIL: 'fixture@test', GIT_COMMITTER_NAME: 'Fixture', GIT_COMMITTER_EMAIL: 'fixture@test' },
      encoding: 'utf8', timeout: 20000,
    });
    assert.equal(result.status, 0, 'Real Git fixture command failed (credentials withheld)');
    return result.stdout;
  };
  git(['init', '--initial-branch=main']);
  git(['add', '.']);
  git(['commit', '-m', 'Publish browser fixture']);
  git(['push', `${origin}/git/${cell.slug}.git`, 'main']);
  git(['branch', 'feature/browser']);
  git(['push', `${origin}/git/${cell.slug}.git`, 'feature/browser']);
  git(['ls-remote', `${origin}/git/${cell.id}.git`]);
  await evaluate('[...document.querySelectorAll("a")].find(a => a.textContent.includes("Browser-created CELL")).click()');
  await until(() => evaluate('[...document.querySelectorAll("h1,h2")].some(h => h.textContent === "Browser README")'), 'default rendered README');
  assert.equal(await evaluate('[...document.querySelectorAll("strong")].some(e => e.textContent === "renders safely")'), true);
  assert.equal(await evaluate('!!window.__readmeUnsafe || !!document.querySelector("img[src*=invalid],a[href^=javascript]")'), false);
  assert.equal(await evaluate('location.pathname'), `/cells/${cell.id}`);
  await cdp('Page.reload');
  await until(() => evaluate('document.body.innerText.includes("Browser README")'), 'repo deep-link reload');
  await evaluate('[...document.querySelectorAll(".file-list a")].find(a => new URL(a.href).searchParams.get("path") === "src").click()');
  await until(() => evaluate('document.body.innerText.includes("main.rs")'), 'directory browsing');
  await evaluate('[...document.querySelectorAll(".file-list a")].find(a => new URL(a.href).searchParams.get("path") === "src/main.rs").click()');
  await until(() => evaluate('document.body.innerText.includes("browser-code-fixture")'), 'source-file display');
  await evaluate('[...document.querySelectorAll("a")].find(a => /^History/.test(a.textContent.trim())).click()');
  await until(() => evaluate('document.body.innerText.includes("Publish browser fixture")'), 'real commit history');
  assert.equal(await evaluate('document.body.innerText.includes("Fixture")'), true);
  await cdp('Page.reload');
  await until(() => evaluate('document.body.innerText.includes("Publish browser fixture")'), 'history deep-link reload');
  await evaluate('[...document.querySelectorAll("a")].find(a => a.textContent.trim() === "Browse files").click()');
  await until(() => evaluate('document.body.innerText.includes("Browser README")'), 'immutable commit source browsing');
  assert.match(await evaluate('location.search'), /revision=[0-9a-f]{40}/);
  await evaluate('[...document.querySelectorAll("a")].find(a => /^Branches/.test(a.textContent.trim())).click()');
  await until(() => evaluate(`(() => {
    const link = [...document.querySelectorAll('section[aria-label="Repository branches"] a')].find(a => a.textContent.trim() === 'feature/browser');
    if (!link || document.querySelector('.activity').textContent) return false;
    link.click(); return true;
  })()`), 'branch list and branch navigation');
  await until(() => evaluate('document.querySelector("#branch")?.value === "refs/heads/feature/browser"'), 'branch code selection');
  await evaluate('document.querySelector(".clone-menu > summary").click()');
  assert.equal(await evaluate('document.querySelector("#git-remote").value'), `${origin}/git/${cell.slug}.git`);
  await cdp('Browser.grantPermissions', { origin, permissions: ['clipboardReadWrite', 'clipboardSanitizedWrite'] });
  await cdp('Emulation.setFocusEmulationEnabled', { enabled: true });
  await evaluate('[...document.querySelectorAll("button")].find(b => b.textContent === "Copy HTTP URL").click()');
  try {
    await until(() => evaluate('document.querySelector(".clone-content").innerText.includes("Copied HTTP URL.")'), 'real clipboard copy');
  } catch (error) {
    console.error(await evaluate('document.querySelector(".clone-content")?.textContent'));
    throw error;
  }
  // Headless Chromium may have no OS clipboard backend; assert the native write
  // promise/feedback above, not cross-process clipboard persistence.
  await cdp('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
  assert.equal(await evaluate('document.documentElement.scrollWidth <= window.innerWidth'), true, 'Repository layout must fit narrow screens');
  await evaluate('document.querySelector(".clone-menu > summary").click()');
  await cdp('Emulation.clearDeviceMetricsOverride');
  await evaluate('[...document.querySelectorAll("a")].find(a => /^Issues/.test(a.textContent.trim())).click()');
  await until(() => evaluate('!!document.querySelector("#issue-title")'), 'Issues tab');
  async function fill(id, value) {
    await until(async () => {
      const filled = await evaluate(`(() => { const input = document.getElementById(${JSON.stringify(id)});
        if (!(input instanceof HTMLInputElement)) return false;
        Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, ${JSON.stringify(value)});
        input.dispatchEvent(new Event('input', { bubbles: true })); return true; })()`);
      await delay(100);
      return filled && await evaluate(`document.getElementById(${JSON.stringify(id)})?.value === ${JSON.stringify(value)}`);
    }, `stable input ${id}`);
  }
  await fill('issue-title', 'Browser-created issue');
  await evaluate('document.querySelector("#issue-title").form.requestSubmit()');
  await until(() => evaluate('document.body.innerText.includes("Browser-created issue") && document.querySelector("#issue-title").value === ""'), 'issue creation and draft reset');
  await evaluate('[...document.querySelectorAll("a")].find(a => /^Settings/.test(a.textContent.trim())).click()');
  await until(() => evaluate('!!document.querySelector("#rename-name")'), 'Settings tab');
  await fill('rename-name', 'Friendly Browser Repo');
  await evaluate('document.querySelector("#rename-name").form.requestSubmit()');
  await until(() => evaluate('document.querySelector("#git-remote")?.value.endsWith("/git/friendly-browser-repo.git")'), 'rename and slug URL update');
  git(['ls-remote', `${origin}/git/friendly-browser-repo.git`]);
  git(['clone', `${origin}/git/friendly-browser-repo.git`, path.join(directory, 'clone')]);
  const clonedReadme = await readFile(path.join(directory, 'clone', 'README.md'), 'utf8');
  assert.equal(clonedReadme, readme);
  await fill('delete-confirmation', 'wrong name');
  assert.equal(await evaluate('document.querySelector("#delete-confirmation").form.querySelector("button").disabled'), true);
  await fill('delete-confirmation', 'Friendly Browser Repo');
  await evaluate('document.querySelector("#delete-confirmation").form.requestSubmit()');
  await until(() => evaluate('location.pathname === "/" && document.body.innerText.includes("No cells yet")'), 'confirmed local deletion returns refreshed list');
  assert.equal(JSON.parse(cli(['--api-url', origin, 'cell', 'list'])).length, 0);
  const keptReadme = await readFile(path.join(work, 'README.md'), 'utf8');
  assert.equal(keptReadme, readme, 'Local deletion must not delete independent working copies');
  console.log('PASS: unlocked auto-connect/reload, restart/retry, origin isolation, real Git push/clone via slug plus ID compatibility, routed code/README, real history and immutable source, branch navigation, native clipboard feedback, narrow-screen layout, safe Markdown, issues, rename, confirmed local delete and preserved worktrees.');
} finally {
  browserSocket?.close();
  if (hostile) await new Promise(resolve => hostile.close(resolve));
  for (const child of children.reverse()) {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGTERM');
      await Promise.race([new Promise(resolve => child.once('exit', resolve)), delay(3000)]);
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    }
  }
  await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
}
