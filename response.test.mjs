import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseApiResponse } from './public/api-response.js';

test('HTML gateway failures give actionable errors without exposing response content', async () => {
  for (const status of [200, 403, 502]) {
    const response = new Response('<!DOCTYPE html><html>secret-gateway-debug-data</html>', { status, headers: { 'Content-Type': 'text/html' } });
    await assert.rejects(parseApiResponse(response, 'login'), error => {
      assert.equal(error.status, status);
      assert.match(error.message, new RegExp(`HTTP ${status}`));
      assert.match(error.message, /Owner login received an HTML page/);
      assert.ok(!error.message.includes('secret-gateway-debug-data'));
      assert.ok(!error.message.includes('Unexpected token'));
      return true;
    });
  }
});

test('Cloudflare challenge response carries a request ID for diagnosis', async () => {
  const response = new Response('<!DOCTYPE html>', { status: 403, headers: { 'Content-Type': 'text/html', 'cf-mitigated': 'challenge', 'cf-ray': '123456-TEST' } });
  await assert.rejects(parseApiResponse(response, 'pw/send-otp'), /Send OTP.*Cloudflare returned a browser challenge.*123456-TEST/);
});

test('valid API responses, JSON errors and malformed JSON are handled distinctly', async () => {
  assert.deepEqual(await parseApiResponse(new Response('{"connected":true}', { headers: { 'Content-Type': 'application/json' } }), 'session'), { connected: true });
  await assert.rejects(parseApiResponse(new Response('{"error":"Incorrect owner key."}', { status: 401, headers: { 'Content-Type': 'application/json' } }), 'login'), error => error.status === 401 && error.message === 'Incorrect owner key.');
  await assert.rejects(parseApiResponse(new Response('<!DOCTYPE html>', { status: 502, headers: { 'Content-Type': 'application/json' } }), 'session'), /Login check returned an invalid API response \(HTTP 502\)/);
});
