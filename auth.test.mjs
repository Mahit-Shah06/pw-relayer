import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm, stat } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createApp } from './server.mjs';
import { createPwAuth } from './pw-auth.mjs';

const secret = 'owner-secret-for-testing-only-32-characters';
const phone = '9876543210';
const providerToken = 'provider-token-never-send-to-browser';
const success = data => new Response(JSON.stringify({ success: true, data }), { headers: { 'Content-Type': 'application/json' } });

test('owner login, CSRF, OTP, persistence and disconnect over HTTP', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'pw-auth-http-'));
  const calls = [];
  const mock = async (url, options) => {
    calls.push({ url, body: JSON.parse(options.body) });
    return url.includes('get-otp') ? success({}) : success({ access_token: providerToken, expires_in: 3600 });
  };
  const configPath = path.join(dir, 'sources.json');
  await writeFile(configPath, '{"sources":[]}');
  let app = createApp({ configPath, dataDir: dir, token: secret, pwRequest: mock });
  let base = '', cookie = '', csrf = '';
  async function start() { const address = await app.start(0, '127.0.0.1'); base = `http://127.0.0.1:${address.port}`; }
  const post = (route, body, extra = {}) => fetch(base + '/admin/api/' + route, {
    method: 'POST', headers: { Origin: base, 'Content-Type': 'application/json', Cookie: cookie, 'X-CSRF-Token': csrf, ...extra }, body: JSON.stringify(body)
  });
  async function login() {
    const response = await post('login', { key: secret });
    assert.equal(response.status, 200);
    const header = response.headers.get('set-cookie');
    assert.match(header, /HttpOnly/); assert.match(header, /Secure/); assert.match(header, /SameSite=Strict/);
    cookie = header.split(';')[0]; csrf = (await response.json()).csrf;
  }
  try {
    await start();
    assert.equal((await fetch(base + '/', { redirect: 'manual' })).headers.get('location'), '/admin/');
    const page = await fetch(base + '/admin/');
    assert.match(await page.text(), /Verify owner access/);
    assert.match(page.headers.get('content-security-policy'), /frame-ancestors 'none'/);
    assert.equal((await post('pw/send-otp', { phone })).status, 401);
    assert.equal(calls.length, 0);
    assert.equal((await post('login', { key: secret }, { Origin: 'https://wrong.example' })).status, 403);
    assert.equal((await post('login', { key: 'wrong' })).status, 401);
    await login();
    assert.equal((await post('pw/send-otp', { phone }, { 'X-CSRF-Token': 'wrong' })).status, 403);
    assert.equal((await post('pw/send-otp', { phone: '../invalid' })).status, 400);
    const sent = await post('pw/send-otp', { phone });
    assert.equal(sent.status, 200);
    assert.equal((await sent.json()).maskedPhone, '+91 ••••••3210');
    assert.equal((await post('pw/send-otp', { phone })).status, 429);
    assert.equal(calls.length, 1);
    const result = await post('pw/verify-otp', { otp: '123456' });
    assert.equal(result.status, 200);
    const body = await result.text();
    assert.equal(JSON.parse(body).connected, true);
    assert.ok(!body.includes(providerToken)); assert.ok(!body.includes(phone));
    assert.equal(calls[1].body.otp, '123456');
    const encrypted = await readFile(path.join(dir, '.pw-session.enc'), 'utf8');
    assert.ok(!encrypted.includes(providerToken)); assert.ok(!encrypted.includes('123456'));
    assert.equal((await stat(path.join(dir, '.pw-session.enc'))).mode & 0o777, 0o600);
    assert.equal((await post('pw/verify-otp', { otp: '123456' })).status, 400);
    await app.stop();
    app = createApp({ configPath, dataDir: dir, token: secret, pwRequest: mock });
    await start();
    assert.equal((await fetch(base + '/admin/api/session', { headers: { Cookie: cookie } })).status, 401);
    await login();
    const session = await (await fetch(base + '/admin/api/session', { headers: { Cookie: cookie } })).json();
    assert.equal(session.pw.connected, true);
    assert.equal((await post('pw/disconnect', {})).status, 200);
    await assert.rejects(readFile(path.join(dir, '.pw-session.enc')), { code: 'ENOENT' });
    assert.equal((await post('logout', {})).status, 200);
    assert.equal((await fetch(base + '/admin/api/session', { headers: { Cookie: cookie } })).status, 401);
  } finally { await app.stop(); await rm(dir, { recursive: true, force: true }); }
});

test('PW session expires, credentials stay origin-bound, wrong encryption key fails closed', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'pw-auth-store-'));
  let time = 1000000;
  const auth = createPwAuth({ dataDir: dir, secret, now: () => time, request: async url => success(url.includes('get-otp') ? {} : { access_token: providerToken, expires_in: 60 }) });
  try {
    await auth.sendOtp('owner', phone);
    await assert.rejects(auth.verifyOtp('different-owner', '123456'), { status: 400 });
    await auth.verifyOtp('owner', '123456');
    assert.equal(auth.authorization('https://api.penpencil.co/v1/example'), `Bearer ${providerToken}`);
    assert.throws(() => auth.authorization('https://api.penpencil.co.attacker.example/'), /only be sent/);
    const wrong = createPwAuth({ dataDir: dir, secret: 'a-different-secret' });
    await wrong.load(); assert.equal(wrong.state().connected, false); assert.equal(wrong.state().unreadable, true);
    time += 61000;
    assert.equal(auth.state().connected, false); assert.equal(auth.state().expired, true);
    assert.throws(() => auth.authorization('https://api.penpencil.co/'), /login required/);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('no automatic OTP retries; verification attempts are bounded and errors are redacted', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'pw-auth-limit-'));
  let count = 0;
  const auth = createPwAuth({ dataDir: dir, secret, request: async url => {
    count++;
    if (url.includes('get-otp')) return success({});
    return new Response(JSON.stringify({ success: false, error: { message: providerToken } }), { status: 400 });
  } });
  try {
    await auth.sendOtp('owner', phone);
    for (let i = 0; i < 5; i++) await assert.rejects(auth.verifyOtp('owner', '123456'), error => error.status === 502 && !error.message.includes(providerToken));
    await assert.rejects(auth.verifyOtp('owner', '123456'), { status: 429 });
    assert.equal(count, 6);
    let sends = 0;
    const failed = createPwAuth({ dataDir: dir, secret, request: async () => { sends++; throw new Error('network failure'); } });
    await assert.rejects(failed.sendOtp('owner', phone), { status: 502 });
    await assert.rejects(failed.sendOtp('owner', phone), { status: 429 });
    assert.equal(sends, 1);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
