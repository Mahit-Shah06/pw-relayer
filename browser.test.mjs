import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { createPwBrowser, loginTokens } from './pw-browser.mjs';
const url = 'https://api.penpencil.co/v3/oauth/token';
const data = { success: true, data: { access_token: 'test-access-token-123456', refresh_token: 'test-refresh-token-123456' } };
function fixture() {
  let clock = 0, closed = 0, imported, handler;
  const page = new EventEmitter();
  Object.assign(page, { setDefaultTimeout() {}, goto: async () => {}, url: () => 'https://www.pw.live/', screenshot: async () => Buffer.from('frame'), mouse: { click: async () => {}, wheel: async () => {} }, keyboard: { insertText: async () => {}, press: async () => {} } });
  const context = new EventEmitter();
  Object.assign(context, { route: async (_, h) => { handler = h; }, newPage: async () => page });
  const browser = createPwBrowser({ enabled: true, now: () => clock, pw: { importToken: async (...args) => { imported = args; return { connected: true }; } }, launchBrowser: async () => ({ newContext: async () => context, close: async () => { closed++; } }) });
  const capture = async () => {
    await page.listeners('response')[0]({ url: () => url, ok: () => true, headers: () => ({}), body: async () => Buffer.from(JSON.stringify(data)), request: () => ({ method: () => 'POST', headers: () => ({ randomid: 'device-123' }) }) });
  };
  return { browser, capture, advance: () => { clock = 600001; }, get closed() { return closed; }, get imported() { return imported; }, route: async (url, top = true) => {
    let allowed;
    await handler({ request: () => ({ url: () => url, isNavigationRequest: () => true, frame: () => ({ parentFrame: () => top ? null : {} }) }), continue: () => { allowed = true; }, abort: () => { allowed = false; } });
    return allowed;
  } };
}
test('browser accepts tokens only from the official successful OAuth login response', () => {
  assert.equal(loginTokens('https://evil.example/v3/oauth/token', 'POST', data), null);
  assert.equal(loginTokens(url, 'GET', data), null);
  assert.equal(loginTokens(url, 'POST', { ...data, success: false }), null);
  assert.equal(loginTokens(url, 'POST', { success: true, data: { access_token: '<html>' } }), null);
  assert.equal(loginTokens(url, 'POST', data).refreshToken, data.data.refresh_token);
});
test('remote browser binds owner, limits navigation, saves tokens privately and closes', async () => {
  const f = fixture();
  try {
    await f.browser.start('alice');
    assert.equal(f.browser.state('bob').active, false);
    await assert.rejects(f.browser.frame('bob'), { status: 409 });
    await assert.rejects(f.browser.input('bob', { type: 'key', key: 'Enter' }), { status: 409 });
    await assert.rejects(f.browser.start('bob'), { status: 409 });
    assert.equal(await f.route('http://127.0.0.1:8080'), false);
    assert.equal(await f.route('https://evil.example/'), false);
    assert.equal(await f.route('https://api.penpencil.co/'), false);
    assert.equal(await f.route('https://www.pw.live/study'), true);
    assert.equal(await f.route('https://challenges.cloudflare.com/widget', false), true);
    await assert.rejects(f.browser.save('alice'), { status: 409 });
    await f.capture();
    assert.equal(f.browser.state('alice').ready, true);
    assert.ok(!JSON.stringify(f.browser.state('alice')).includes(data.data.access_token));
    assert.deepEqual(await f.browser.save('alice'), { connected: true });
    assert.deepEqual(f.imported, [data.data.access_token, data.data.refresh_token, 'device-123']);
    assert.equal(f.closed, 1);
    assert.equal(f.browser.state('alice').active, false);
  } finally { await f.browser.close(); }
});
test('browser expires, rejects unsupported controls and stays closed when disabled', async () => {
  const disabled = createPwBrowser({ enabled: false });
  await assert.rejects(disabled.start('alice'), { status: 409 });
  const f = fixture();
  try {
    await f.browser.start('alice');
    await assert.rejects(f.browser.input('alice', { type: 'key', key: 'F12' }), { status: 400 });
    await assert.rejects(f.browser.input('alice', { type: 'click', x: -1, y: 0 }), { status: 400 });
    f.advance();
    await assert.rejects(f.browser.frame('alice'), { status: 410 });
    assert.equal(f.closed, 1);
  } finally { await f.browser.close(); }
});
