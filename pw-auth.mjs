import { readFile, writeFile, rename, unlink, mkdir } from 'node:fs/promises';
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes, randomUUID } from 'node:crypto';
import path from 'node:path';
import { normalizePhone } from './public/phone.js';

const API = 'https://api.penpencil.co';
const ORGANIZATION = '5eb393ee95fab7468a79d189';
export class LoginError extends Error {
  constructor(status, message, details = {}) { super(message); this.status = status; this.details = details; }
}

// This adapter follows the existing local PW client's request format. It is not
// a documented public integration. Never retry OTP sends or bypass challenges.
export function createPwAuth({ dataDir, secret, request = fetch, now = Date.now, log = event => console.info(JSON.stringify(event)), clientId = process.env.PW_CLIENT_ID || 'system-admin', clientSecret = process.env.PW_CLIENT_SECRET || '', captchaSiteKey = process.env.PW_CAPTCHA_SITE_KEY || '' }) {
  const filename = path.join(dataDir, '.pw-session.enc');
  const key = Buffer.from(hkdfSync('sha256', secret, 'pw-relayer', 'pw-session-v1', 32));
  let saved = null, pending = null, busy = false, nextSendAt = 0, nextImportAt = 0, unreadable = false;
  let renewal = null, renewalTimer = null, stopping = false;
  function state() {
    const expired = saved?.expiresAt !== null && saved?.expiresAt <= now();
    return {
      connected: Boolean(saved && !expired && !saved.needsLogin),
      expired: Boolean(saved && expired),
      maskedPhone: saved?.maskedPhone || null,
      connectedAt: saved?.connectedAt || null,
      method: saved?.method || 'otp',
      expiresAt: saved?.expiresAt || null,
      unreadable,
      otp: { available: Boolean(captchaSiteKey), siteKey: captchaSiteKey || null },
      autoRefresh: Boolean(saved?.refreshToken),
      refreshStatus: saved?.needsLogin ? 'login_required' : renewal ? 'refreshing' : !saved?.refreshToken ? 'unavailable' : saved.nextRetryAt > now() ? 'retrying' : 'enabled',
      lastRefreshedAt: saved?.lastRefreshedAt || null,
      nextRetryAt: saved?.nextRetryAt || null,
      refreshError: saved?.refreshError || null,
      retryAfter: Math.max(0, Math.ceil((nextSendAt - now()) / 1000))
    };
  }
  async function exclusive(fn) {
    if (busy) throw new LoginError(409, 'Another account operation is in progress.');
    busy = true;
    try { return await fn(); } finally { busy = false; }
  }
  async function api(route, payload, device, authorization) {
    const requestId = randomUUID();
    const operation = route.includes('refresh-token') ? 'refresh-token' : route.includes('verify-token') ? 'verify-token' : route.includes('get-otp') ? 'send-otp' : 'verify-otp';
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
        headers: { 'Content-Type': 'application/json', Accept: 'application/json', Origin: 'https://www.pw.live', Referer: 'https://www.pw.live/', Randomid: device, 'client-type': 'WEB', 'client-id': ORGANIZATION, ...(authorization ? { Authorization: authorization, organizationid: ORGANIZATION } : {}) },
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
      const detail = String(result?.error?.message || result?.errorMessage || result?.message || '').toLowerCase();
      if (/flow is deprecated|use secure flow/.test(detail)) throw fail('PW_OTP_DEPRECATED', 'PW has retired this OTP flow. Secure login requires its approved CAPTCHA verification.');
      if (/captcha|challenge|security error/.test(detail)) throw fail('PW_CHALLENGE', 'PW requires an additional security check. Complete login on its official site; this connector cannot complete that challenge.');
      if (operation === 'refresh-token' && /invalid_grant|refresh.*(?:expir|revok|invalid)|invalid.*refresh/.test(detail)) throw fail('PW_REFRESH_INVALID', 'PW says the refresh token is no longer valid. Reconnect your account.');
      if (operation === 'refresh-token') throw fail('PW_REFRESH_REJECTED', `PW rejected session renewal (HTTP ${response.status}). Reconnect if the refresh token expired or was revoked; the server may also require PW client configuration.`);
      if (operation === 'verify-token') throw fail('PW_TOKEN_REJECTED', `PW rejected this session (HTTP ${response.status}). Sign in on PW and copy a fresh Authorization value.`);
      if (operation === 'verify-otp' && /invalid.*otp|incorrect.*otp|otp.*invalid|otp.*incorrect/.test(detail)) throw fail('PW_INVALID_OTP', 'PW rejected the verification code. Check it and try again.', 400);
      if (operation === 'verify-otp' && /expir/.test(detail)) throw fail('PW_EXPIRED_OTP', 'PW reports that the code or login request expired. Request a new OTP.', 400);
      throw fail('PW_REJECTED', `PW rejected the ${operation === 'send-otp' ? 'OTP request' : 'verification'} (HTTP ${response.status}). Its login requirements may have changed.`);
    }
    record('pw.request.succeeded', { providerStatus: response.status });
    return result.data;
  }
  function tokenExpiry(accessToken, expiresIn) {
    let expiresAt = null;
    const ttl = Number(expiresIn);
    if (Number.isFinite(ttl) && ttl > 0 && ttl <= 366 * 86400) expiresAt = now() + ttl * 1000;
    try {
      const exp = JSON.parse(Buffer.from(accessToken.split('.')[1], 'base64url').toString()).exp;
      // Expiry is only a hint. PW must verify imported credentials remotely.
      if (Number.isFinite(exp) && exp > 0) expiresAt = expiresAt === null ? exp * 1000 : Math.min(expiresAt, exp * 1000);
    } catch { /* Opaque tokens are also supported. */ }
    return expiresAt;
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
  function usableToken(value) {
    return typeof value === 'string' && value.length >= 16 && value.length <= 16000 && /^[A-Za-z0-9._~+\/=-]+$/.test(value);
  }
  function renewalTime(expiresAt) {
    return expiresAt === null ? null : expiresAt - Math.min(120000, Math.max(1000, (expiresAt - now()) / 10));
  }
  async function saveFailure(code, terminal) {
    saved = { ...saved, needsLogin: terminal, refreshError: code, refreshFailures: (saved.refreshFailures || 0) + 1 };
    saved.nextRetryAt = terminal ? null : now() + Math.min(900000, 60000 * 2 ** Math.min(saved.refreshFailures - 1, 4));
    try { await persist(saved); } catch { log({ event: 'pw.session.persist_failed' }); }
  }
  function refresh({ force = false, rejectedToken } = {}) {
    if (stopping) return Promise.reject(new LoginError(503, 'The server is restarting. Try again shortly.'));
    if (renewal) return renewal;
    if (!saved?.refreshToken || saved.needsLogin) return Promise.reject(new LoginError(409, 'A new PW login or refresh token is required.'));
    if (rejectedToken && rejectedToken !== `Bearer ${saved.accessToken}`) return Promise.resolve(state());
    if (saved.nextRetryAt > now()) return Promise.reject(new LoginError(429, 'Renewal will retry after the displayed backoff time.'));
    if (saved.lastRefreshedAt && now() - saved.lastRefreshedAt < 30000) return force ? Promise.reject(new LoginError(429, 'The session was renewed recently. Wait 30 seconds before testing again.')) : Promise.resolve(state());
    if (!force && !saved.refreshError && (saved.renewAt === null || (saved.renewAt ?? renewalTime(saved.expiresAt)) > now())) return Promise.resolve(state());
    if (busy) return Promise.reject(new LoginError(409, 'Another account operation is in progress.'));
    renewal = exclusive(async () => {
      try {
        const data = await api('/v3/oauth/refresh-token', {
          client_id: clientId, ...(clientSecret ? { client_secret: clientSecret } : {}), refresh_token: saved.refreshToken
        }, saved.deviceId || randomUUID(), `Bearer ${saved.accessToken}`);
        if (!usableToken(data?.access_token) || (data.refresh_token !== undefined && !usableToken(data.refresh_token))) throw new LoginError(424, 'PW returned invalid renewal credentials.', { code: 'PW_BAD_REFRESH' });
        const expiresAt = tokenExpiry(data.access_token, data.expires_in);
        if (expiresAt !== null && expiresAt <= now()) throw new LoginError(424, 'PW returned an expired access token.', { code: 'PW_BAD_REFRESH' });
        // Keep the latest rotation in memory even if the disk write fails.
        saved = { ...saved, accessToken: data.access_token, refreshToken: data.refresh_token ?? saved.refreshToken,
          expiresAt, renewAt: renewalTime(expiresAt), lastRefreshedAt: now(), needsLogin: false,
          refreshError: null, refreshFailures: 0, nextRetryAt: null };
        try { await persist(saved); } catch {
          saved.needsLogin = true; saved.refreshError = 'STORAGE_ERROR';
          log({ event: 'pw.session.persist_failed' });
          throw new LoginError(500, 'Renewed tokens could not be saved. Check server storage before reconnecting.', { code: 'STORAGE_ERROR' });
        }
        return state();
      } catch (error) {
        if (error.details?.code !== 'STORAGE_ERROR') {
          const terminal = [400, 401, 403].includes(error.details?.providerStatus) || ['PW_CHALLENGE', 'PW_BAD_REFRESH', 'PW_REFRESH_INVALID'].includes(error.details?.code);
          await saveFailure(error.details?.code || 'PW_REFRESH_FAILED', terminal);
        }
        throw error;
      }
    }).finally(() => { renewal = null; });
    return renewal;
  }
  async function maintain() {
    if (stopping || !saved?.refreshToken || saved.needsLogin || busy || (saved.nextRetryAt || 0) > now()) return;
    const due = saved.renewAt ?? renewalTime(saved.expiresAt);
    if ((saved.refreshError && saved.nextRetryAt <= now()) || (due !== null && due <= now())) { try { await refresh(); } catch { /* State and safe logs carry the failure. */ } }
  }
  return {
    state,
    refresh,
    maintain,
    startRenewal() {
      stopping = false;
      if (renewalTimer) return;
      renewalTimer = setInterval(() => { void maintain(); }, 30000); renewalTimer.unref();
      void maintain();
    },
    async stopRenewal() { stopping = true; clearInterval(renewalTimer); renewalTimer = null; await renewal?.catch(() => {}); },
    async ensureAuthorization(url) {
      if (new URL(url).origin !== API) throw new Error('PW credentials can only be sent to the PW API origin');
      await maintain();
      if (renewal) await renewal.catch(() => {});
      if (!state().connected) throw new Error('PW login required');
      return `Bearer ${saved.accessToken}`;
    },
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
    sendOtp(ownerId, phone, captchaToken) {
      phone = normalizePhone(phone);
      return exclusive(async () => {
        if (typeof phone !== 'string' || !/^[6-9]\d{9}$/.test(phone)) throw new LoginError(400, 'Enter a valid 10-digit Indian mobile number.');
        if (!captchaSiteKey) throw new LoginError(409, 'Direct OTP is unavailable: PW requires a CAPTCHA configuration that accepts this domain. Sign in on PW and use Existing session.', { code: 'PW_OTP_CONFIGURATION' });
        if (now() < nextSendAt) throw new LoginError(429, 'Wait 60 seconds between OTP requests.');
        if (typeof captchaToken !== 'string' || !captchaToken.trim() || captchaToken.length > 4096) throw new LoginError(400, 'Complete the CAPTCHA before requesting an OTP.', { code: 'PW_CAPTCHA_REQUIRED' });
        nextSendAt = now() + 60000;
        pending = null;
        const device = randomUUID();
        await api('/v1/users/get-otp-secure?smsType=0', { username: phone, countryCode: '+91', organizationId: ORGANIZATION, captchaToken, captchaSiteKey }, device);
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
          username: pending.phone, otp, client_id: clientId, ...(clientSecret ? { client_secret: clientSecret } : {}), grant_type: 'password', organizationId: ORGANIZATION
        }, pending.device);
        if (typeof data?.access_token !== 'string' || !data.access_token || /[\r\n]/.test(data.access_token)) throw new LoginError(424, 'PW returned no usable access token.', { code: 'PW_NO_TOKEN' });
        const expiresAt = tokenExpiry(data.access_token, data.expires_in);
        const value = { accessToken: data.access_token, expiresAt, connectedAt: now(), method: 'otp', refreshToken: usableToken(data.refresh_token) ? data.refresh_token : null, deviceId: pending.device, renewAt: renewalTime(expiresAt), maskedPhone: `+91 ••••••${pending.phone.slice(-4)}` };
        await persist(value);
        saved = value; pending = null; unreadable = false;
        return state();
      });
    },
    importToken(input, refreshInput = '', deviceInput = '') {
      return exclusive(async () => {
        if (typeof input !== 'string' || input.length > 16000) throw new LoginError(400, 'Paste the Authorization value from your own PW session.');
        const accessToken = input.trim().replace(/^authorization:\s*/i, '').replace(/^bearer\s+/i, '');
        if (accessToken.length < 16 || !/^[A-Za-z0-9._~+\/=-]+$/.test(accessToken)) throw new LoginError(400, 'Paste a token or Bearer token value, without quotes, line breaks, or other headers.');
        if (typeof refreshInput !== 'string' || (refreshInput.trim() && !usableToken(refreshInput.trim()))) throw new LoginError(400, 'Enter a valid refresh token without Bearer or other headers.');
        if (typeof deviceInput !== 'string' || (deviceInput && !/^[a-zA-Z0-9_-]{1,128}$/.test(deviceInput))) throw new LoginError(400, 'Invalid PW device ID.');
        const refreshToken = refreshInput.trim() || null;
        const expiresAt = tokenExpiry(accessToken);
        if (expiresAt !== null && expiresAt <= now()) throw new LoginError(400, 'This token has expired. Sign in on PW and copy a fresh Authorization value.');
        if (now() < nextImportAt) throw new LoginError(429, 'Wait five seconds before checking another session.');
        nextImportAt = now() + 5000;
        const device = deviceInput || randomUUID();
        const data = await api('/v3/oauth/verify-token', { randomId: device, organizationId: ORGANIZATION }, device, `Bearer ${accessToken}`);
        if (data?.isVerified !== true) throw new LoginError(424, 'PW did not confirm this session. Nothing was saved. Sign in on PW and try a fresh token.', { code: 'PW_TOKEN_UNVERIFIED' });
        const value = { accessToken, refreshToken, deviceId: device, expiresAt, renewAt: renewalTime(expiresAt), connectedAt: now(), method: 'token', maskedPhone: null };
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
