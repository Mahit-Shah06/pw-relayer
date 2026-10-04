import { randomBytes, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { LoginError } from './pw-auth.mjs';

const assets = new Map([
  ['/admin', ['index.html', 'text/html; charset=utf-8']],
  ['/admin/', ['index.html', 'text/html; charset=utf-8']],
  ['/admin/app.js', ['app.js', 'text/javascript; charset=utf-8']],
  ['/admin/api-response.js', ['api-response.js', 'text/javascript; charset=utf-8']],
  ['/admin/style.css', ['style.css', 'text/css; charset=utf-8']]
]);
function equal(a, b) { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && timingSafeEqual(x, y); }
async function json(req) {
  if (!/^application\/json(?:;|$)/i.test(req.headers['content-type'] || '')) throw new LoginError(415, 'JSON is required.');
  const chunks = []; let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 4096) throw new LoginError(413, 'Request too large.');
    chunks.push(chunk);
  }
  try {
    const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error();
    return value;
  } catch { throw new LoginError(400, 'Invalid JSON.'); }
}
export function createAdmin({ token, pw, now = Date.now, publicOrigin = process.env.PUBLIC_ORIGIN }) {
  const sessions = new Map();
  let attempts = 0, resetAt = 0;
  const cookie = (value, age) => `pw_owner=${value}; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=${age}`;
  return async function admin(req, res, url) {
    if (url.pathname !== '/' && !url.pathname.startsWith('/admin')) return false;
    const send = (code, body) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(body)); };
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    try {
      if (url.pathname === '/' && req.method === 'GET') { res.writeHead(302, { Location: '/admin/' }); res.end(); return true; }
      if (assets.has(url.pathname) && req.method === 'GET') {
        const [name, type] = assets.get(url.pathname);
        const body = await readFile(new URL(`./public/${name}`, import.meta.url));
        res.writeHead(200, { 'Content-Type': type }); res.end(body); return true;
      }
      if (!url.pathname.startsWith('/admin/api/')) { send(404, { error: 'Not found' }); return true; }
      if (!['GET', 'POST'].includes(req.method)) throw new LoginError(405, 'Method not allowed.');
      if (req.method === 'POST') {
        const expected = publicOrigin || `${req.headers['x-forwarded-proto'] === 'https' ? 'https' : 'http'}://${req.headers.host}`;
        if (req.headers.origin !== expected) throw new LoginError(403, 'Open this page directly on the relay domain and try again.');
      }
      for (const [id, s] of sessions) if (s.expiresAt <= now()) { sessions.delete(id); pw.cancelPending(id); }
      if (url.pathname === '/admin/api/login' && req.method === 'POST') {
        if (now() >= resetAt) { attempts = 0; resetAt = now() + 60000; }
        if (++attempts > 10) throw new LoginError(429, 'Too many unlock attempts. Wait one minute.');
        const body = await json(req);
        if (typeof body.key !== 'string' || !equal(body.key, token)) throw new LoginError(401, 'Incorrect owner key.');
        if (sessions.size >= 16) { const old = sessions.keys().next().value; sessions.delete(old); pw.cancelPending(old); }
        const id = randomBytes(32).toString('hex'), csrf = randomBytes(32).toString('hex');
        sessions.set(id, { csrf, expiresAt: now() + 8 * 3600000 });
        res.setHeader('Set-Cookie', cookie(id, 8 * 3600));
        send(200, { csrf, pw: pw.state() }); return true;
      }
      const id = /(?:^|;\s*)pw_owner=([a-f0-9]{64})(?:;|$)/.exec(req.headers.cookie || '')?.[1];
      const session = sessions.get(id);
      if (!session) throw new LoginError(401, 'Verify owner access first.');
      if (url.pathname === '/admin/api/session' && req.method === 'GET') { send(200, { csrf: session.csrf, pw: pw.state() }); return true; }
      if (req.method !== 'POST') throw new LoginError(405, 'Use POST.');
      if (!equal(req.headers['x-csrf-token'] || '', session.csrf)) throw new LoginError(403, 'Session check failed. Reload the page.');
      const body = await json(req);
      switch (url.pathname) {
        case '/admin/api/logout':
          sessions.delete(id); pw.cancelPending(id);
          res.setHeader('Set-Cookie', cookie('', 0)); send(200, { ok: true }); break;
        case '/admin/api/pw/send-otp': send(200, await pw.sendOtp(id, body.phone)); break;
        case '/admin/api/pw/verify-otp': send(200, await pw.verifyOtp(id, body.otp)); break;
        case '/admin/api/pw/disconnect': send(200, await pw.disconnect()); break;
        default: throw new LoginError(404, 'Not found.');
      }
    } catch (error) {
      send(error instanceof LoginError ? error.status : 500, { error: error instanceof LoginError ? error.message : 'Could not complete the operation. Check server storage and try again.' });
    }
    return true;
  };
}
