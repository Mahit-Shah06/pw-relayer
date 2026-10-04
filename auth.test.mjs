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
    assert.equal(options.headers['client-type'], 'WEB');
    assert.equal(options.headers['client-id'], '5eb393ee95fab7468a79d189');
    calls.push({ url, body: JSON.parse(options.body) });
    if (JSON.parse(options.body).otp === '000000') return new Response('<!DOCTYPE html>private-provider-page', { status: 502 });
    return url.includes('get-otp') ? success({}) : success({ access_token: providerToken, expires_in: 3600 });
  };
  const configPath = path.join(dir, 'sources.json');
  await writeFile(configPath, '{"sources":[]}');
  let app = createApp({ pwCaptchaSiteKey: 'test-site-key', configPath, dataDir: dir, token: secret, pwRequest: mock });
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
    const sent = await post('pw/send-otp', { phone: ' 98765 43210 ', captchaToken: 'test-captcha-token' });
    assert.equal(calls[0].body.username, phone);
    assert.equal(calls[0].url, 'https://api.penpencil.co/v1/users/get-otp-secure?smsType=0');
    assert.equal(calls[0].body.captchaToken, 'test-captcha-token');
    assert.equal(calls[0].body.captchaSiteKey, 'test-site-key');
    assert.equal(sent.status, 200);
    assert.equal((await sent.json()).maskedPhone, '+91 ••••••3210');
    assert.equal((await post('pw/send-otp', { phone })).status, 429);
    assert.equal(calls.length, 1);
    const rejected = await post('pw/verify-otp', { otp: '000000' });
    assert.equal(rejected.status, 424);
    assert.match(rejected.headers.get('content-type'), /application\/json/);
    const failure = await rejected.json();
    assert.equal(failure.code, 'PW_NON_JSON');
    assert.equal(failure.providerStatus, 502);
    assert.ok(!JSON.stringify(failure).includes('private-provider-page'));
    const result = await post('pw/verify-otp', { otp: '123456' });
    assert.equal(result.status, 200);
    const body = await result.text();
    assert.equal(JSON.parse(body).connected, true);
    assert.ok(!body.includes(providerToken)); assert.ok(!body.includes(phone));
    assert.equal(calls.at(-1).body.otp, '123456');
    const encrypted = await readFile(path.join(dir, '.pw-session.enc'), 'utf8');
    assert.ok(!encrypted.includes(providerToken)); assert.ok(!encrypted.includes('123456'));
    assert.equal((await stat(path.join(dir, '.pw-session.enc'))).mode & 0o777, 0o600);
    assert.equal((await post('pw/verify-otp', { otp: '123456' })).status, 400);
    await app.stop();
    app = createApp({ pwCaptchaSiteKey: 'test-site-key', configPath, dataDir: dir, token: secret, pwRequest: mock });
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
  const auth = createPwAuth({ captchaSiteKey: 'test-site-key', dataDir: dir, secret, now: () => time, request: async url => success(url.includes('get-otp') ? {} : { access_token: providerToken, expires_in: 60 }) });
  try {
    await auth.sendOtp('owner', phone, 'test-captcha-token');
    await assert.rejects(auth.verifyOtp('different-owner', '123456'), { status: 400 });
    await auth.verifyOtp('owner', '123456');
    assert.equal(auth.authorization('https://api.penpencil.co/v1/example'), `Bearer ${providerToken}`);
    assert.throws(() => auth.authorization('https://api.penpencil.co.attacker.example/'), /only be sent/);
    const wrong = createPwAuth({ captchaSiteKey: 'test-site-key', dataDir: dir, secret: 'a-different-secret' });
    await wrong.load(); assert.equal(wrong.state().connected, false); assert.equal(wrong.state().unreadable, true);
    time += 61000;
    assert.equal(auth.state().connected, false); assert.equal(auth.state().expired, true);
    assert.throws(() => auth.authorization('https://api.penpencil.co/'), /login required/);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('no automatic OTP retries; verification attempts are bounded and errors are redacted', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'pw-auth-limit-'));
  let count = 0;
  const auth = createPwAuth({ captchaSiteKey: 'test-site-key', dataDir: dir, secret, request: async url => {
    count++;
    if (url.includes('get-otp')) return success({});
    return new Response(JSON.stringify({ success: false, error: { message: providerToken } }), { status: 400 });
  } });
  try {
    await auth.sendOtp('owner', phone, 'test-captcha-token');
    for (let i = 0; i < 5; i++) await assert.rejects(auth.verifyOtp('owner', '123456'), error => error.status === 424 && !error.message.includes(providerToken));
    await assert.rejects(auth.verifyOtp('owner', '123456'), { status: 429 });
    assert.equal(count, 6);
    let sends = 0;
    const failed = createPwAuth({ captchaSiteKey: 'test-site-key', dataDir: dir, secret, request: async () => { sends++; throw new Error('network failure'); } });
    await assert.rejects(failed.sendOtp('owner', phone, 'test-captcha-token'), { status: 424 });
    await assert.rejects(failed.sendOtp('owner', phone, 'test-captcha-token'), { status: 429 });
    assert.equal(sends, 1);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('provider diagnostics distinguish HTML, DNS, TLS, timeout, and rejection without leaking payloads', async () => {
  const cases = [
    ['PW_NON_JSON', async () => new Response('<!DOCTYPE html>private-response', { status: 403 })],
    ['PW_DNS', async () => { throw new Error('private-response', { cause: { code: 'ENOTFOUND' } }); }],
    ['PW_TLS', async () => { throw new Error('private-response', { cause: { code: 'CERT_HAS_EXPIRED' } }); }],
    ['PW_TIMEOUT', async () => { const error = new Error('private-response'); error.name = 'TimeoutError'; throw error; }],
    ['PW_CHALLENGE', async () => new Response(JSON.stringify({ success: false, error: { message: 'Security Error private-response' } }), { status: 403 })],
    ['PW_RATE_LIMIT', async () => new Response('<!DOCTYPE html>', { status: 429 })]
  ];
  for (const [code, request] of cases) {
    const events = [];
    const auth = createPwAuth({ captchaSiteKey: 'test-site-key', dataDir: '/unused', secret, request, log: event => events.push(event) });
    await assert.rejects(auth.sendOtp('owner', phone, 'test-captcha-token'), error => {
      assert.equal(error.details.code, code);
      assert.equal(error.status, code === 'PW_RATE_LIMIT' ? 429 : 424);
      assert.match(error.message, /Reference:/);
      assert.equal(events[0].event, 'pw.request.started');
      assert.equal(events[1].requestId, error.details.requestId);
      return true;
    });
    const logs = JSON.stringify(events);
    for (const value of [phone, secret, providerToken, 'private-response']) assert.ok(!logs.includes(value));
  }
});


test('phone normalization removes formatting spaces without truncating or accepting letters', async () => {
  const { normalizePhone } = await import('./public/phone.js');
  for (const value of ['98765 43210', ' 98765 43210 ', '98765\u00a043210', '98 765 43 210']) assert.equal(normalizePhone(value), phone);
  assert.equal(normalizePhone('98765432101'), '98765432101');
  assert.equal(normalizePhone('98765a43210'), '98765a43210');
  assert.equal(normalizePhone(null), null);
});

test('imported tokens are remotely verified, encrypted, and never replace a good session after rejection', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'pw-token-import-'));
  const events = [], calls = [];
  let time = Date.now(), reject = false, unverified = false;
  const request = async (url, options) => {
    calls.push({ url, options });
    return reject ? new Response(JSON.stringify({ success: false, message: 'private-token-debug' }), { status: 401 }) : success({ isVerified: !unverified });
  };
  const auth = createPwAuth({ captchaSiteKey: 'test-site-key', dataDir: dir, secret, request, now: () => time, log: event => events.push(event) });
  try {
    for (const prefix of ['', 'Bearer ', 'Authorization: Bearer ']) {
      time += 6000;
      const state = await auth.importToken(prefix + providerToken);
      assert.equal(state.connected, true); assert.equal(state.method, 'token');
      assert.ok(!JSON.stringify(state).includes(providerToken));
      assert.equal(calls.at(-1).url, 'https://api.penpencil.co/v3/oauth/verify-token');
      assert.equal(calls.at(-1).options.headers.Authorization, `Bearer ${providerToken}`);
      assert.equal(calls.at(-1).options.redirect, 'error');
      assert.ok(!calls.at(-1).options.body.includes(providerToken));
    }
    const before = await readFile(path.join(dir, '.pw-session.enc'), 'utf8');
    assert.ok(!before.includes(providerToken));
    const reloaded = createPwAuth({ captchaSiteKey: 'test-site-key', dataDir: dir, secret, request });
    await reloaded.load();
    assert.equal(reloaded.authorization('https://api.penpencil.co/test'), `Bearer ${providerToken}`);
    time += 6000; reject = true;
    await assert.rejects(auth.importToken('another-token-value-for-testing'), error => error.details.code === 'PW_TOKEN_REJECTED');
    assert.equal(await readFile(path.join(dir, '.pw-session.enc'), 'utf8'), before);
    assert.equal(auth.authorization('https://api.penpencil.co/test'), `Bearer ${providerToken}`);
    time += 6000; reject = false; unverified = true;
    await assert.rejects(auth.importToken('another-token-value-for-testing'), error => error.details.code === 'PW_TOKEN_UNVERIFIED');
    assert.equal(await readFile(path.join(dir, '.pw-session.enc'), 'utf8'), before);
    const count = calls.length;
    await assert.rejects(auth.importToken('Bearer abc\r\nInjected: header'), { status: 400 });
    const expired = `header.${Buffer.from(JSON.stringify({ exp: Math.floor(time / 1000) - 1 })).toString('base64url')}.signature`;
    await assert.rejects(auth.importToken(expired), /expired/);
    assert.equal(calls.length, count);
    const logs = JSON.stringify(events);
    for (const value of [providerToken, 'another-token-value-for-testing', 'private-token-debug', secret]) assert.ok(!logs.includes(value));
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('token-import HTTP route requires owner access and CSRF, and never echoes the token', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'pw-token-http-'));
  const configPath = path.join(dir, 'sources.json');
  await writeFile(configPath, '{"sources":[]}');
  let calls = 0;
  const app = createApp({ pwCaptchaSiteKey: 'test-site-key', configPath, dataDir: dir, token: secret, pwRequest: async () => { calls++; return success({ isVerified: true }); } });
  try {
    const address = await app.start(0, '127.0.0.1');
    const base = `http://127.0.0.1:${address.port}`;
    let cookie = '', csrf = '';
    const post = (route, body) => fetch(base + '/admin/api/' + route, { method: 'POST', headers: { Origin: base, 'Content-Type': 'application/json', Cookie: cookie, 'X-CSRF-Token': csrf }, body: JSON.stringify(body) });
    assert.equal((await post('pw/import-token', { token: providerToken })).status, 401);
    const login = await post('login', { key: secret });
    cookie = login.headers.get('set-cookie').split(';')[0];
    assert.equal((await post('pw/import-token', { token: providerToken })).status, 403);
    assert.equal(calls, 0);
    csrf = (await login.json()).csrf;
    const response = await post('pw/import-token', { token: `Bearer ${providerToken}` });
    assert.equal(response.status, 200);
    const text = await response.text();
    assert.equal(JSON.parse(text).connected, true);
    assert.ok(!text.includes(providerToken));
    assert.equal(calls, 1);
    assert.equal((await post('pw/import-token', { token: providerToken })).status, 429);
    assert.equal(calls, 1);
  } finally { await app.stop(); await rm(dir, { recursive: true, force: true }); }
});


test('secure OTP requires configured CAPTCHA and a fresh browser token before any provider request', async () => {
  let calls = 0;
  const request = async () => { calls++; return success({}); };
  const unconfigured = createPwAuth({ dataDir: '/unused', secret, captchaSiteKey: '', request });
  assert.equal(unconfigured.state().otp.available, false);
  await assert.rejects(unconfigured.sendOtp('owner', phone, 'token'), { status: 409, details: { code: 'PW_OTP_CONFIGURATION' } });
  const configured = createPwAuth({ dataDir: '/unused', secret, captchaSiteKey: 'test-site-key', request });
  await assert.rejects(configured.sendOtp('owner', phone), { status: 400, details: { code: 'PW_CAPTCHA_REQUIRED' } });
  assert.equal(calls, 0);
});

test('deprecated OTP response is identified without retry or legacy fallback', async () => {
  let calls = 0;
  const events = [];
  const auth = createPwAuth({ dataDir: '/unused', secret, captchaSiteKey: 'test-site-key', log: event => events.push(event), request: async () => {
    calls++;
    return new Response(JSON.stringify({ success: false, errorMessage: 'Flow is deprecated, please use secure flow' }), { status: 403 });
  } });
  await assert.rejects(auth.sendOtp('owner', phone, 'private-captcha-token'), error => error.details.code === 'PW_OTP_DEPRECATED' && error.details.providerStatus === 403);
  assert.equal(calls, 1);
  assert.ok(!JSON.stringify(events).includes('private-captcha-token'));
  assert.ok(!JSON.stringify(events).includes(phone));
});
