// Connectivity checks only: no credentials, OTP requests, or response bodies.
const origin = process.env.PUBLIC_ORIGIN || 'https://pw.itzzsuperrr.me';
const checks = [
  ['local-health', `http://127.0.0.1:${process.env.PORT || 8080}/healthz`],
  ['local-login-route', `http://127.0.0.1:${process.env.PORT || 8080}/admin/api/session`],
  ['public-login-route', new URL('/admin/api/session', origin).href],
  ['pw-connectivity-only', 'https://api.penpencil.co/']
];
for (const [check, url] of checks) {
  const started = Date.now();
  try {
    const response = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(15000) });
    const result = { check, status: response.status, type: response.headers.get('content-type'), elapsedMs: Date.now() - started };
    await response.body?.cancel();
    console.log(JSON.stringify(result));
  } catch (error) {
    const raw = error.cause?.code || error.code || error.name;
    const code = typeof raw === 'string' && /^[A-Z_a-z]{1,50}$/.test(raw) ? raw : 'NETWORK_ERROR';
    console.log(JSON.stringify({ check, error: code, elapsedMs: Date.now() - started }));
  }
}
console.log('Expected: local-health 200; login routes 401 JSON. Any PW HTTP response confirms connectivity only, not OTP support. No OTP was sent.');
