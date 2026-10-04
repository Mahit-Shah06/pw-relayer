import { readFile, writeFile, rename, unlink, mkdir } from 'node:fs/promises';
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes, randomUUID } from 'node:crypto';
import path from 'node:path';

const API = 'https://api.penpencil.co';
const ORGANIZATION = '5eb393ee95fab7468a79d189';
export class LoginError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

// This adapter follows the existing local PW client's request format. It is not
// a documented public integration. Never retry OTP sends or bypass challenges.
export function createPwAuth({ dataDir, secret, request = fetch, now = Date.now }) {
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
    let response, result;
    try {
      response = await request(API + route, {
        method: 'POST', redirect: 'error', signal: AbortSignal.timeout(15000),
        headers: { 'Content-Type': 'application/json', Accept: 'application/json', Origin: 'https://www.pw.live', Referer: 'https://www.pw.live/', Randomid: device },
        body: JSON.stringify(payload)
      });
      const chunks = []; let size = 0;
      for await (const chunk of response.body) {
        size += chunk.length;
        if (size > 128 * 1024) throw new Error('Oversized response');
        chunks.push(Buffer.from(chunk));
      }
      result = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch {
      throw new LoginError(502, 'PW could not be reached or returned an unsupported response. Try the official PW site if this continues.');
    }
    if (!response.ok || result.success !== true) {
      if (response.status === 429) throw new LoginError(429, 'PW is limiting requests. Wait before trying again.');
      throw new LoginError(502, `PW did not accept this request (HTTP ${response.status}). The OTP may be invalid or expired, or PW may require a challenge on its official site.`);
    }
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
        if (typeof data?.access_token !== 'string' || !data.access_token || /[\r\n]/.test(data.access_token)) throw new LoginError(502, 'PW returned no usable access token.');
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
