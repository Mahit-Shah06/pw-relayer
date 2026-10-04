import { readFile, writeFile, rename, unlink, mkdir } from 'node:fs/promises';
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes, randomUUID } from 'node:crypto';
import path from 'node:path';

const API = 'https://api.penpencil.co';
const ORGANIZATION = '5eb393ee95fab7468a79d189';
export class LoginError extends Error {
  constructor(status, message, details = {}) { super(message); this.status = status; this.details = details; }
}

// This adapter follows the existing local PW client's request format. It is not
// a documented public integration. Never retry OTP sends or bypass challenges.
export function createPwAuth({ dataDir, secret, request = fetch, now = Date.now, log = event => console.info(JSON.stringify(event)) }) {
  const filename = path.join(dataDir, '.pw-session.enc');
  const key = Buffer.from(hkdfSync('sha256', secret, 'pw-relayer', 'pw-session-v1', 32));
  let saved = null, pending = null, busy = false, nextSendAt = 0, unreadable = false;
  function state() {
    const expired = saved?.expiresAt !== null && saved?.expiresAt <= now();
    return {
      connected: Boolean(saved && !expired),
      expired: Boolean(saved && expired),
      maskedPhone: saved?.maskedPhone || null,
      connectedAt: saved?.connectedAt || null,
      expiresAt: saved?.expiresAt || null,
      unreadable,
      retryAfter: Math.max(0, Math.ceil((nextSendAt - now()) / 1000))
    };
  }
  async function exclusive(fn) {
    if (busy) throw new LoginError(409, 'Another account operation is in progress.');
    busy = true;
    try { return await fn(); } finally { busy = false; }
  }
  async function api(route, payload, device) {
    const requestId = randomUUID();
    const operation = route.includes('get-otp') ? 'send-otp' : 'verify-otp';
    const started = now();
    let response, text, result;
    const record = (event, fields = {}) => log({ event, operation, requestId, elapsedMs: now() - started, ...fields });
    const fail = (code, message, status = 424, extra = {}) => {
      const details = { code, requestId, ...(response ? { providerStatus: response.status } : {}), ...extra };
      record('pw.request.failed', details);
      return new LoginError(status, `${message} Reference: ${requestId}.`, details);
    };
    record('pw.request.started');
    try {
      response = await request(API + route, {
        method: 'POST', redirect: 'error', signal: AbortSignal.timeout(15000),
        headers: { 'Content-Type': 'application/json', Accept: 'application/json', Origin: 'https://www.pw.live', Referer: 'https://www.pw.live/', Randomid: device },
        body: JSON.stringify(payload)
      });
      const chunks = []; let size = 0;
      for await (const chunk of response.body) {
        size += chunk.length;
        if (size > 128 * 1024) throw new Error('PW_RESPONSE_TOO_LARGE');
        chunks.push(Buffer.from(chunk));
      }
      text = Buffer.concat(chunks).toString('utf8');
    } catch (error) {
      const known = new Set(['ENOTFOUND', 'EAI_AGAIN', 'ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'ENETUNREACH', 'EHOSTUNREACH', 'UND_ERR_CONNECT_TIMEOUT', 'UND_ERR_HEADERS_TIMEOUT', 'UND_ERR_BODY_TIMEOUT', 'CERT_HAS_EXPIRED', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY']);
      const rawCode = error.cause?.code || error.code;
      const networkCode = known.has(rawCode) ? rawCode : 'UNKNOWN';
      if (error.name === 'TimeoutError' || /TIMEOUT|TIMEDOUT/.test(networkCode)) throw fail('PW_TIMEOUT', 'The VPS connection to PW timed out. Check outbound connectivity to api.penpencil.co.', 424, { networkCode });
      if (['ENOTFOUND', 'EAI_AGAIN'].includes(networkCode)) throw fail('PW_DNS', 'The VPS could not resolve api.penpencil.co. Check the server DNS resolver.', 424, { networkCode });
      if (/CERT|ISSUER|SIGNATURE/.test(networkCode)) throw fail('PW_TLS', 'The VPS could not verify PW’s TLS certificate. Check the server clock and CA certificates.', 424, { networkCode });
      if (error.message === 'PW_RESPONSE_TOO_LARGE') throw fail('PW_RESPONSE_TOO_LARGE', 'PW returned an unexpectedly large response.');
      throw fail('PW_NETWORK', 'The VPS could not complete its connection to PW.', 424, { networkCode });
    }
    if (response.status === 429) throw fail('PW_RATE_LIMIT', 'PW is limiting requests. Wait before trying again.', 429);
    try { result = JSON.parse(text); } catch {
      const html = /^\s*(?:<!doctype\s+html|<html)/i.test(text);
      const message = `PW returned ${html ? 'an HTML page' : 'non-JSON data'} (HTTP ${response.status}), so its login API did not complete this request.`;
      throw fail('PW_NON_JSON', message + (response.status === 403 ? ' PW refused access from this server; try the official PW site.' : ''));
    }
    if (!response.ok || result?.success !== true) {
      // Classify recognized messages, but never forward/log provider response text:
      // it may include the phone number, OTP, or credentials.
      const detail = String(result?.error?.message || result?.message || '').toLowerCase();
      if (/captcha|challenge|security error/.test(detail)) throw fail('PW_CHALLENGE', 'PW requires an additional security check. Complete login on its official site; this connector cannot complete that challenge.');
      if (operation === 'verify-otp' && /invalid.*otp|incorrect.*otp|otp.*invalid|otp.*incorrect/.test(detail)) throw fail('PW_INVALID_OTP', 'PW rejected the verification code. Check it and try again.', 400);
      if (operation === 'verify-otp' && /expir/.test(detail)) throw fail('PW_EXPIRED_OTP', 'PW reports that the code or login request expired. Request a new OTP.', 400);
      throw fail('PW_REJECTED', `PW rejected the ${operation === 'send-otp' ? 'OTP request' : 'verification'} (HTTP ${response.status}). Its login requirements may have changed.`);
    }
    record('pw.request.succeeded', { providerStatus: response.status });
    return result.data;
  }
  async function persist(value) {
    await mkdir(dataDir, { recursive: true, mode: 0o700 });
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
    const tmp = `${filename}.${randomUUID()}.tmp`;
    try {
      await writeFile(tmp, JSON.stringify({ v: 1, iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: ciphertext.toString('base64') }), { mode: 0o600, flag: 'wx' });
      await rename(tmp, filename);
    } finally { await unlink(tmp).catch(() => {}); }
  }
  return {
    state,
    async load() {
      try {
        const envelope = JSON.parse(await readFile(filename, 'utf8'));
        if (envelope.v !== 1) throw new Error('Unsupported session format');
        const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.iv, 'base64'));
        decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
        const value = JSON.parse(Buffer.concat([decipher.update(Buffer.from(envelope.data, 'base64')), decipher.final()]).toString('utf8'));
        if (typeof value.accessToken !== 'string' || !value.accessToken) throw new Error('Invalid session');
        saved = value;
      } catch (err) {
        if (err.code !== 'ENOENT') unreadable = true;
      }
    },
    sendOtp(ownerId, phone) {
      return exclusive(async () => {
        if (typeof phone !== 'string' || !/^[6-9]\d{9}$/.test(phone)) throw new LoginError(400, 'Enter a valid 10-digit Indian mobile number.');
        if (now() < nextSendAt) throw new LoginError(429, 'Wait 60 seconds between OTP requests.');
        nextSendAt = now() + 60000;
        pending = null;
        const device = randomUUID();
        await api('/v1/users/get-otp?smsType=0', { username: phone, countryCode: '+91', organizationId: ORGANIZATION }, device);
        pending = { ownerId, phone, device, expiresAt: now() + 5 * 60000, attempts: 0 };
        return { sent: true, maskedPhone: `+91 ••••••${phone.slice(-4)}`, retryAfter: 60 };
      });
    },
    verifyOtp(ownerId, otp) {
      return exclusive(async () => {
        if (!pending || pending.ownerId !== ownerId || pending.expiresAt <= now()) throw new LoginError(400, 'Request a new OTP from this browser session.');
        if (typeof otp !== 'string' || !/^\d{4,8}$/.test(otp)) throw new LoginError(400, 'Enter the numeric OTP from your message.');
        if (pending.attempts >= 5) { pending = null; throw new LoginError(429, 'Too many attempts. Request a new OTP.'); }
        pending.attempts++;
        const data = await api('/v3/oauth/token?smsType=0&fallback=true', {
          username: pending.phone, otp, client_id: 'system-admin', grant_type: 'password', organizationId: ORGANIZATION
        }, pending.device);
        if (typeof data?.access_token !== 'string' || !data.access_token || /[\r\n]/.test(data.access_token)) throw new LoginError(424, 'PW returned no usable access token.', { code: 'PW_NO_TOKEN' });
        let expiresAt = null;
        const ttl = Number(data.expires_in);
        if (Number.isFinite(ttl) && ttl > 0 && ttl <= 366 * 86400) expiresAt = now() + ttl * 1000;
        try {
          const exp = JSON.parse(Buffer.from(data.access_token.split('.')[1], 'base64url').toString()).exp;
          // JWT expiry is used only as a hint, never as proof that PW accepts the token.
          if (Number.isFinite(exp) && exp > 0) expiresAt = expiresAt === null ? exp * 1000 : Math.min(expiresAt, exp * 1000);
        } catch { /* Opaque tokens are valid too. */ }
        const value = { accessToken: data.access_token, expiresAt, connectedAt: now(), maskedPhone: `+91 ••••••${pending.phone.slice(-4)}` };
        await persist(value);
        saved = value; pending = null; unreadable = false;
        return state();
      });
    },
    disconnect() {
      return exclusive(async () => {
        await unlink(filename).catch(err => { if (err.code !== 'ENOENT') throw err; });
        saved = null; pending = null; unreadable = false;
        return state();
      });
    },
    cancelPending(ownerId) { if (pending?.ownerId === ownerId) pending = null; },
    authorization(url) {
      if (new URL(url).origin !== API) throw new Error('PW credentials can only be sent to the PW API origin');
      if (!state().connected) throw new Error('PW login required');
      return `Bearer ${saved.accessToken}`;
    }
  };
}
