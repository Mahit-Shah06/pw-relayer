import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { createPwAuth } from './pw-auth.mjs';
import { createApp } from './server.mjs';
const secret = 'refresh-tests-owner-key-at-least-32-characters';
const access = 'original-access-token-for-tests';
const refreshToken = 'original-refresh-token-for-tests';
const nextAccess = 'renewed-access-token-for-tests';
const nextRefresh = 'rotated-refresh-token-for-tests';
const success = data => new Response(JSON.stringify({ success: true, data }));
const jwt = exp => `header.${Buffer.from(JSON.stringify({ exp })).toString('base64url')}.signature`;

test('scheduled renewal deduplicates callers, rotates both tokens and survives restart', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'pw-renew-'));
  let time = Date.now(), renewals = 0;
  const request = async (url, options) => {
    if (url.includes('verify-token')) return success({ isVerified: true });
    renewals++;
    const body = JSON.parse(options.body);
    assert.equal(body.client_id, 'test-client'); assert.equal(body.client_secret, 'test-client-secret');
    assert.equal(body.refresh_token, refreshToken);
    assert.equal(options.headers.Randomid, 'original-device');
    await new Promise(r => setTimeout(r, 10));
    return success({ access_token: nextAccess, refresh_token: nextRefresh, expires_in: 3600 });
  };
  const auth = createPwAuth({ dataDir: dir, secret, now: () => time, request, clientId: 'test-client', clientSecret: 'test-client-secret', log: () => {} });
  try {
    await auth.importToken(jwt(Math.floor(time / 1000) + 600), refreshToken, 'original-device');
    await auth.maintain(); assert.equal(renewals, 0);
    time += 550000;
    await Promise.all([auth.maintain(), auth.refresh(), auth.ensureAuthorization('https://api.penpencil.co/test')]);
    assert.equal(renewals, 1);
    assert.equal(auth.authorization('https://api.penpencil.co/test'), `Bearer ${nextAccess}`);
    assert.equal(auth.state().refreshStatus, 'enabled');
    const disk = await readFile(path.join(dir, '.pw-session.enc'), 'utf8');
    for (const value of [refreshToken, nextAccess, nextRefresh]) assert.ok(!disk.includes(value));
    let used;
    const loaded = createPwAuth({ dataDir: dir, secret, now: () => time, request: async (url, options) => { used = JSON.parse(options.body).refresh_token; return success({ access_token: access, expires_in: 3600 }); }, log: () => {} });
    await loaded.load(); time += 31000;
    await loaded.refresh({ force: true });
    assert.equal(used, nextRefresh);
    time += 31000; await loaded.refresh({ force: true }); assert.equal(used, nextRefresh);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('temporary failures back off and recover; revocation stops retries across restart', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'pw-renew-fail-'));
  let time = Date.now(), mode = 'network', calls = 0;
  const request = async url => {
    if (url.includes('verify-token')) return success({ isVerified: true });
    calls++;
    if (mode === 'network') throw new Error('network down');
    if (mode === 'revoked') return new Response(JSON.stringify({ success: false, error: { message: 'invalid_grant' } }), { status: 400 });
    return success({ access_token: nextAccess, refresh_token: nextRefresh, expires_in: 3600 });
  };
  const auth = createPwAuth({ dataDir: dir, secret, now: () => time, request, log: () => {} });
  try {
    await auth.importToken(access, refreshToken);
    await assert.rejects(auth.refresh({ force: true }));
    assert.equal(auth.state().refreshStatus, 'retrying');
    assert.equal(auth.state().connected, true);
    await assert.rejects(auth.refresh({ force: true }), { status: 429 });
    await auth.maintain(); assert.equal(calls, 1);
    time += 61000; mode = 'success'; await auth.maintain();
    assert.equal(calls, 2); assert.equal(auth.state().refreshError, null);
    time += 31000; mode = 'revoked'; await assert.rejects(auth.refresh({ force: true }));
    assert.equal(auth.state().refreshStatus, 'login_required'); assert.equal(auth.state().connected, false);
    const loaded = createPwAuth({ dataDir: dir, secret, now: () => time, request, log: () => {} });
    await loaded.load(); time += 86400000; await loaded.maintain();
    assert.equal(calls, 3); assert.equal(loaded.state().refreshStatus, 'login_required');
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('OTP retains a refresh token; access-only imports remain supported', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'pw-renew-otp-'));
  const auth = createPwAuth({ dataDir: dir, secret, request: async url => success(url.includes('get-otp') ? {} : url.includes('verify-token') ? { isVerified: true } : { access_token: access, refresh_token: refreshToken, expires_in: 3600 }), log: () => {} });
  try {
    await auth.sendOtp('owner', '9876543210'); await auth.verifyOtp('owner', '123456');
    assert.equal(auth.state().autoRefresh, true);
    await auth.importToken(access);
    assert.equal(auth.state().autoRefresh, false);
    await assert.rejects(auth.refresh({ force: true }), { status: 409 });
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('PW relay renews after a 401 and retries exactly once with the new token', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'pw-renew-relay-'));
  let renewals = 0; const used = [];
  const provider = async url => {
    if (url.includes('verify-token')) return success({ isVerified: true });
    renewals++; return success({ access_token: nextAccess, refresh_token: nextRefresh, expires_in: 3600 });
  };
  const auth = createPwAuth({ dataDir: dir, secret, request: provider, log: () => {} });
  await auth.importToken(access, refreshToken);
  const configPath = path.join(dir, 'sources.json');
  await writeFile(configPath, JSON.stringify({ sources: [{ id: 'pw-data', type: 'relay', auth: 'pw', url: 'https://api.penpencil.co/test-resource' }] }));
  const app = createApp({ configPath, dataDir: dir, token: secret, pwRequest: provider, sourceRequest: async (url, options) => {
    used.push(options.headers.Authorization);
    return new Response(options.headers.Authorization === `Bearer ${nextAccess}` ? 'ok' : 'expired', { status: options.headers.Authorization === `Bearer ${nextAccess}` ? 200 : 401 });
  } });
  try {
    const address = await app.start(0, '127.0.0.1');
    const response = await fetch(`http://127.0.0.1:${address.port}/relay/pw-data`, { headers: { Authorization: `Bearer ${secret}` } });
    assert.equal(response.status, 200); assert.equal(await response.text(), 'ok');
    assert.equal(renewals, 1); assert.deepEqual(used, [`Bearer ${access}`, `Bearer ${nextAccess}`]);
  } finally { await app.stop(); await rm(dir, { recursive: true, force: true }); }
});
