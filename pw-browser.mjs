import { spawn } from 'node:child_process';
import { LoginError } from './pw-auth.mjs';

const WIDTH = 1000, HEIGHT = 760;
const official = url => { try { const u = new URL(url); return u.protocol === 'https:' && (u.hostname === 'pw.live' || u.hostname.endsWith('.pw.live')); } catch { return false; } };
const resourceAllowed = url => {
  try {
    const u = new URL(url);
    return u.protocol === 'https:' && !u.username && !u.password && (!u.port || u.port === '443') &&
      ['pw.live', 'penpencil.co', 'cloudfront.net', 'challenges.cloudflare.com', 'fonts.googleapis.com', 'fonts.gstatic.com'].some(host => u.hostname === host || u.hostname.endsWith('.' + host));
  } catch { return false; }
};
// Only a successful login response from PW's fixed API can supply credentials.
export function loginTokens(url, method, result, headers = {}) {
  const u = new URL(url);
  if (u.origin !== 'https://api.penpencil.co' || !/^\/v[13]\/oauth\/token$/.test(u.pathname) || method !== 'POST' || result?.success !== true) return null;
  const data = result.data;
  const valid = value => typeof value === 'string' && value.length >= 16 && value.length <= 16000 && /^[A-Za-z0-9._~+/=-]+$/.test(value);
  if (!valid(data?.access_token)) return null;
  return { token: data.access_token, refreshToken: valid(data.refresh_token) ? data.refresh_token : '', deviceId: /^[a-zA-Z0-9_-]{1,128}$/.test(headers.randomid || '') ? headers.randomid : '' };
}
async function launch() {
  const { chromium } = await import('playwright');
  const browserEnv = Object.fromEntries(['PATH', 'HOME', 'USER', 'LOGNAME', 'LANG', 'XDG_RUNTIME_DIR'].filter(key => process.env[key]).map(key => [key, process.env[key]]));
  const display = spawn('Xvfb', ['-displayfd', '3', '-screen', '0', `${WIDTH}x${HEIGHT}x24`, '-nolisten', 'tcp'], { env: browserEnv, stdio: ['ignore', 'ignore', 'ignore', 'pipe'] });
  let browser;
  try {
    const number = await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('Display startup timeout')), 10000);
      let output = '';
      display.on('error', error => { clearTimeout(timeout); reject(error); });
      display.on('exit', () => { clearTimeout(timeout); reject(new Error('Display exited')); });
      display.stdio[3].on('data', chunk => { output += chunk; if (/^\d+\n$/.test(output)) { clearTimeout(timeout); resolve(output.trim()); } });
    });
    browser = await chromium.launch({ headless: false, chromiumSandbox: true, ...(process.env.PW_BROWSER_EXECUTABLE ? { executablePath: process.env.PW_BROWSER_EXECUTABLE } : {}), env: { ...browserEnv, DISPLAY: `:${number}` }, timeout: 20000 });
    browser.on('disconnected', () => display.kill());
    return browser;
  } catch (error) { await browser?.close().catch(() => {}); display.kill(); throw error; }
}
export function createPwBrowser({ pw, enabled = process.env.PW_BROWSER_ENABLED === 'true', launchBrowser = launch, now = Date.now } = {}) {
  let current = null, starting = false;
  async function close(owner) {
    if (!current || (owner && current.owner !== owner)) return;
    const old = current; current = null; old.tokens = null; clearInterval(old.timer);
    await old.browser?.close().catch(() => {});
  }
  function owned(owner) {
    if (!current || current.owner !== owner) throw new LoginError(409, 'Start your PW browser session first.');
    if (now() >= current.expiresAt) { void close(owner); throw new LoginError(410, 'Browser session expired. Open a new one.'); }
    return current;
  }
  function state(owner) {
    if (!current || current.owner !== owner) return { enabled, active: false };
    return { enabled, active: true, ready: Boolean(current.tokens), expiresAt: current.expiresAt, origin: 'https://www.pw.live', width: WIDTH, height: HEIGHT };
  }
  async function input(owner, body) {
    const s = owned(owner);
    if (s.busy) throw new LoginError(429, 'Browser is busy. Try again.');
    s.busy = true;
    try {
      if (body.type === 'click' && Number.isFinite(body.x) && Number.isFinite(body.y) && body.x >= 0 && body.x < WIDTH && body.y >= 0 && body.y < HEIGHT) await s.page.mouse.click(body.x, body.y);
      else if (body.type === 'text' && typeof body.text === 'string' && body.text.length <= 256) await s.page.keyboard.insertText(body.text);
      else if (body.type === 'key' && ['Enter', 'Tab', 'Shift+Tab', 'Backspace', 'Delete', 'ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', 'Escape', 'Control+A', 'Home', 'End'].includes(body.key)) await s.page.keyboard.press(body.key);
      else if (body.type === 'scroll' && Number.isFinite(body.y) && Math.abs(body.y) <= 1000) await s.page.mouse.wheel(0, body.y);
      else throw new LoginError(400, 'Unsupported browser input.');
      return state(owner);
    } finally { s.busy = false; }
  }
  return {
    state, close, input,
    async start(owner) {
      if (!enabled) throw new LoginError(409, 'PW browser login is not enabled on this server.');
      if (starting || current) throw new LoginError(409, 'A PW browser is already open. Close it or wait for it to expire.');
      starting = true;
      const s = { owner, tokens: null, expiresAt: now() + 10 * 60000, busy: false };
      current = s;
      try {
        s.browser = await launchBrowser();
        if (current !== s) { await s.browser.close(); throw new LoginError(409, 'Browser session was cancelled.'); }
        const context = await s.browser.newContext({ viewport: { width: WIDTH, height: HEIGHT }, acceptDownloads: false, serviceWorkers: 'block' });
        await context.route('**/*', route => {
          const req = route.request();
          const topNavigation = req.isNavigationRequest() && !req.frame().parentFrame();
          return (resourceAllowed(req.url()) && (!topNavigation || official(req.url()))) ? route.continue() : route.abort();
        });
        s.page = await context.newPage();
        s.page.setDefaultTimeout(10000);
        context.on('page', page => { if (page !== s.page) void page.close().catch(() => {}); });
        s.page.on('dialog', dialog => void dialog.dismiss().catch(() => {}));
        s.page.on('response', async response => {
          try {
            const url = new URL(response.url());
            if (url.origin !== 'https://api.penpencil.co' || !/^\/v[13]\/oauth\/token$/.test(url.pathname) || !response.ok() || !official(s.page.url())) return;
            if (Number(response.headers()['content-length']) > 128 * 1024) return;
            const body = await response.body();
            if (body.length > 128 * 1024 || current !== s) return;
            const tokens = loginTokens(response.url(), response.request().method(), JSON.parse(body), response.request().headers());
            if (tokens) s.tokens = tokens;
          } catch { /* Never print provider bodies, browser errors, or credentials. */ }
        });
        s.timer = setInterval(() => { if (now() >= s.expiresAt) void close(owner); }, 5000);
        s.timer.unref();
        await s.page.goto('https://www.pw.live/', { waitUntil: 'domcontentloaded', timeout: 30000 });
        return state(owner);
      } catch (error) {
        await close(owner);
        if (error instanceof LoginError) throw error;
        throw new LoginError(503, 'Could not open PW in the server browser. Check browser installation and outbound connectivity.');
      } finally { starting = false; }
    },
    async frame(owner) {
      const s = owned(owner);
      if (!s.page || s.capturing) throw new LoginError(429, 'Browser frame is not ready.');
      s.capturing = true;
      try { return await s.page.screenshot({ type: 'jpeg', quality: 75, timeout: 5000 }); }
      finally { s.capturing = false; }
    },
    async save(owner) {
      const s = owned(owner);
      if (!s.tokens) throw new LoginError(409, 'Complete login on PW in the browser first.');
      if (s.busy) throw new LoginError(429, 'Browser is busy. Try again.');
      s.busy = true;
      try {
        const state = await pw.importToken(s.tokens.token, s.tokens.refreshToken, s.tokens.deviceId);
        await close(owner);
        return state;
      } finally { s.busy = false; }
    }
  };
}
