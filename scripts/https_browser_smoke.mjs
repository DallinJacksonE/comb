#!/usr/bin/env node
// Real browser HTTPS/session integration; trust is isolated to a disposable NSS DB.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import https from 'node:https';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
assert(process.env.TMPDIR, 'Set TMPDIR to private scratch storage');
const directory = await mkdtemp(path.join(process.env.TMPDIR, 'comb-https-browser-'));
const data = path.join(directory, 'frame');
const binary = path.join(root, 'target/debug/comb');
const env = { ...process.env, COMB_PASSWORD: 'https-smoke-fixture-password' };
delete env.COMB_TOKEN;
const children = [];
let socket;
let proxy;
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
function run(command, args, options = {}) {
  const result = spawnSync(command, args, { env, encoding: 'utf8', timeout: 20000, ...options });
  assert.equal(result.status, 0, `${command} fixture failed (output withheld)`);
  return result.stdout;
}
const cli = args => run(binary, ['--data', data, ...args]);
function start(command, args, options = {}) {
  const child = spawn(command, args, { env, stdio: 'ignore', ...options });
  children.push(child);
  return child;
}
async function port() {
  const listener = net.createServer();
  await new Promise(resolve => listener.listen(0, '127.0.0.1', resolve));
  const value = listener.address().port;
  await new Promise(resolve => listener.close(resolve));
  return value;
}
async function until(probe, label) {
  console.log(`Checking: ${label}`);
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    try { const value = await probe(); if (value) return value; } catch { /* readiness race */ }
    await delay(100);
  }
  throw new Error(`Timed out: ${label}`);
}
async function stop(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill('SIGTERM');
  await Promise.race([new Promise(resolve => child.once('exit', resolve)), delay(4000)]);
  if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
}
try {
  const caKey = path.join(directory, 'ca.key');
  const caCert = path.join(directory, 'ca.pem');
  const key = path.join(directory, 'server.key');
  const cert = path.join(directory, 'server.pem');
  run('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=COMB isolated browser fixture CA', '-keyout', caKey, '-out', caCert]);
  run('openssl', ['req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=127.0.0.1', '-keyout', key, '-out', path.join(directory, 'server.csr')]);
  await writeFile(path.join(directory, 'extensions'), 'subjectAltName=IP:127.0.0.1,DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n');
  run('openssl', ['x509', '-req', '-in', path.join(directory, 'server.csr'), '-CA', caCert, '-CAkey', caKey, '-CAcreateserial', '-days', '1', '-extfile', path.join(directory, 'extensions'), '-out', cert]);
  const browserHome = path.join(directory, 'browser-home');
  const nss = path.join(browserHome, '.pki', 'nssdb');
  await mkdir(nss, { recursive: true });
  run('certutil', ['-N', '-d', `sql:${nss}`, '--empty-password']);
  run('certutil', ['-A', '-d', `sql:${nss}`, '-n', 'COMB isolated fixture CA', '-t', 'C,,', '-i', caCert]);
  cli(['user', '--name', 'HTTPS Fixture', '--email', 'https@test', '--ssh-config', path.join(directory, 'ssh-config')]);
  const local = await port();
  const web = await port();
  const peer = await port();
  const debugging = await port();
  const origin = `https://127.0.0.1:${web}`;
  const ca = await readFile(caCert);
  const request = (route, options = {}) => new Promise((resolve, reject) => {
    const req = https.request(`${origin}${route}`, { ca, ...options }, response => {
      let body = '';
      response.on('data', chunk => { body += chunk; });
      response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, body }));
    });
    req.on('error', reject);
    req.setTimeout(5000, () => req.destroy(new Error('HTTPS fixture request timeout')));
    req.end(options.body);
  });
  const serving = ['serve', '--managed', '--listen', `127.0.0.1:${local}`, '--peer-listen', `127.0.0.1:${peer}`, '--ssh-listen', '127.0.0.1:0', '--web-listen', `127.0.0.1:${web}`, '--web-origin', origin, '--tls-cert', cert, '--tls-key', key, '--assets', path.join(root, 'FRAME/webgui/dist')];
  let daemon = start(binary, ['--data', data, ...serving]);
  await until(() => {
    const result = spawnSync(binary, ['--data', data, 'service-status'], { env, stdio: 'ignore' });
    return result.status === 0;
  }, 'locked managed service readiness');
  await assert.rejects(request('/api/browser/session'), 'Locked FRAME must not expose HTTPS');
  cli(['webgui']);
  await until(async () => (await request('/')).status === 200, 'validated HTTPS certificate and listener');
  assert.equal((await request('/api/cells')).status, 401, 'Public listener cannot auto-authenticate');
  const authHeaders = { 'X-Comb-Webgui': '1', 'Sec-Fetch-Site': 'same-origin', Origin: origin };
  const anonymous = await request('/api/browser/session', { headers: authHeaders });
  assert.equal(JSON.parse(anonymous.body).authenticated, false);
  const token = cli(['token']).trim();
  start(process.env.COMB_CHROMIUM || 'chromium', ['--headless', '--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--no-first-run', '--no-default-browser-check', `--user-data-dir=${path.join(directory, 'chromium')}`, `--remote-debugging-port=${debugging}`, 'about:blank'], {
    env: { ...env, HOME: browserHome, XDG_CONFIG_HOME: path.join(browserHome, '.config') },
  });
  const target = await until(async () => (await (await fetch(`http://127.0.0.1:${debugging}/json/list`)).json()).find(target => target.type === 'page'), 'Chromium debugging endpoint');
  socket = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject; });
  let sequence = 0;
  const pending = new Map();
  socket.onmessage = event => {
    const message = JSON.parse(event.data);
    pending.get(message.id)?.(message);
  };
  async function cdp(method, params = {}) {
    const id = ++sequence;
    const response = new Promise((resolve, reject) => {
      const timer = setTimeout(() => { pending.delete(id); reject(new Error(`CDP timeout: ${method}`)); }, 10000);
      pending.set(id, message => { clearTimeout(timer); pending.delete(id); resolve(message); });
    });
    socket.send(JSON.stringify({ id, method, params }));
    const message = await response;
    assert(!message.error, JSON.stringify(message.error));
    return message.result;
  }
  async function evaluate(expression) {
    const response = await cdp('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
    assert(!response.exceptionDetails, 'Browser evaluation failed (secret-bearing expression withheld)');
    return response.result.value;
  }
  await cdp('Page.navigate', { url: origin });
  await until(() => evaluate('!!document.querySelector("#browser-token")'), 'trusted HTTPS browser login (no certificate-error bypass)');
  assert.equal(await evaluate('window.isSecureContext'), true);
  assert.equal(await evaluate('document.body.innerText.includes("HTTPS Fixture")'), false, 'No private identity before login');
  await evaluate(`(() => { const input = document.querySelector('#browser-token'); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, ${JSON.stringify(token)}); input.dispatchEvent(new Event('input', { bubbles: true })); })()`);
  await delay(100);
  await evaluate('document.querySelector("#browser-token").form.requestSubmit()');
  await until(() => evaluate('document.body.innerText.includes("HTTPS Fixture")'), 'authenticated remote dashboard');
  assert.equal(await evaluate('localStorage.length + sessionStorage.length'), 0);
  assert.equal(await evaluate('document.cookie.includes("comb_session")'), false, 'Session must be HttpOnly');
  const cookies = (await cdp('Network.getCookies', { urls: [origin] })).cookies;
  const cookie = cookies.find(cookie => cookie.name === '__Host-comb_session');
  assert(cookie?.secure && cookie.httpOnly && cookie.sameSite === 'Strict');
  assert.equal((await request('/api/cells', { headers: { Cookie: `${cookie.name}=${cookie.value}`, ...authHeaders } })).status, 200);
  assert.equal((await request('/api/cells', { method: 'POST', headers: { Cookie: `${cookie.name}=${cookie.value}`, ...authHeaders, Origin: 'https://attacker.example', 'Content-Type': 'application/json' }, body: JSON.stringify({ name: 'Unauthorized' }) })).status, 401);
  await cdp('Page.reload');
  await until(() => evaluate('document.body.innerText.includes("HTTPS Fixture")'), 'session persistence on reload');
  await evaluate('[...document.querySelectorAll("button")].find(b => b.textContent.trim() === "Sign out").click()');
  await until(() => evaluate('!!document.querySelector("#browser-token")'), 'logout returns to login');
  assert.equal((await request('/api/cells', { headers: { Cookie: `${cookie.name}=${cookie.value}`, ...authHeaders } })).status, 401, 'Logged-out cookie cannot be replayed');
  // A real server restart discards in-memory sessions and closes the HTTPS listener.
  await stop(daemon);
  await assert.rejects(request('/'), 'Stopped FRAME must close HTTPS');
  daemon = start(binary, ['--data', data, ...serving]);
  await until(() => spawnSync(binary, ['--data', data, 'service-status'], { env, stdio: 'ignore' }).status === 0, 'managed restart');
  await assert.rejects(request('/'), 'Restarted managed FRAME must remain locked');
  cli(['webgui']);
  await until(async () => (await request('/')).status === 200, 'HTTPS after local unlock');
  assert.equal((await request('/api/cells', { headers: { Cookie: `${cookie.name}=${cookie.value}`, ...authHeaders } })).status, 401);
  await stop(daemon);
  const upstreamPort = await port();
  const proxyServing = serving.slice(0, serving.indexOf('--web-listen'));
  proxyServing.push('--web-listen', `127.0.0.1:${upstreamPort}`, '--web-origin', origin, '--web-behind-proxy', '--assets', path.join(root, 'FRAME/webgui/dist'));
  daemon = start(binary, ['--data', data, ...proxyServing]);
  await until(() => spawnSync(binary, ['--data', data, 'service-status'], { env, stdio: 'ignore' }).status === 0, 'explicit proxy-mode managed service');
  cli(['webgui']);
  proxy = https.createServer({ key: await readFile(key), cert: await readFile(cert) }, (incoming, outgoing) => {
    // Model an operator-trusted TLS edge; preserve the public Host and headers.
    const upstream = http.request({ host: '127.0.0.1', port: upstreamPort, path: incoming.url, method: incoming.method, headers: incoming.headers }, response => {
      outgoing.writeHead(response.statusCode, response.headers);
      response.pipe(outgoing);
    });
    upstream.on('error', () => { outgoing.writeHead(502); outgoing.end(); });
    incoming.pipe(upstream);
  });
  await new Promise(resolve => proxy.listen(web, '127.0.0.1', resolve));
  assert.equal((await request('/api/cells', { headers: { ...authHeaders, 'X-Forwarded-Host': 'localhost:7331', 'X-Forwarded-Proto': 'http' } })).status, 401);
  await cdp('Page.navigate', { url: origin });
  await until(() => evaluate('!!document.querySelector("#browser-token")'), 'HTTPS proxy login boundary');
  await evaluate(`(() => { const input = document.querySelector('#browser-token'); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, ${JSON.stringify(token)}); input.dispatchEvent(new Event('input', { bubbles: true })); })()`);
  await delay(100);
  await evaluate('document.querySelector("#browser-token").form.requestSubmit()');
  await until(() => evaluate('document.body.innerText.includes("HTTPS Fixture")'), 'authenticated HTTPS proxy dashboard');
  console.log('PASS: independently trusted HTTPS in Node and Chromium, remote login, protected dashboard, HttpOnly/Secure/Strict cookie, CSRF rejection, reload, logout/replay, locked restart and explicit TLS-proxy hosting without forwarded-header elevation.');
} finally {
  socket?.close();
  if (proxy) { proxy.closeAllConnections(); await new Promise(resolve => proxy.close(resolve)); }
  for (const child of children.reverse()) await stop(child);
  await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}
