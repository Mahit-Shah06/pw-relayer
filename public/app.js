import { setupBrowser } from './browser.js';
import { parseApiResponse } from './api-response.js';
import { normalizePhone } from './phone.js';
const $ = id => document.getElementById(id);
let csrf = '', cooldown = 0, working = false, editingSession = false;
const remoteBrowser = setupBrowser({ api, action, account, message });
let captchaKey = '', captchaToken = '', captchaWidget = null, captchaLoading = false;
function message(text, error = false) { $('message').textContent = text; $('message').classList.toggle('error', error); }
function locked() {
  remoteBrowser.hide();
  captchaToken = ''; captchaKey = '';
  if (captchaWidget !== null && window.turnstile) window.turnstile.remove(captchaWidget);
  captchaWidget = null;
  csrf = ''; $('unlock-panel').hidden = false; $('account-panel').hidden = true;
  $('otp-form').hidden = true; $('phone').value = ''; $('otp').value = ''; $('pw-token').value = ''; $('pw-refresh-token').value = ''; $('pw-device-id').value = '';
}
function account(pw) {
  editingSession = false;
  captchaKey = pw.otp?.siteKey || '';
  $('otp-unavailable').hidden = Boolean(captchaKey);
  $('phone-form').hidden = !captchaKey;
  $('unlock-panel').hidden = true; $('account-panel').hidden = false;
  $('connected-panel').hidden = !pw.connected; $('login-panel').hidden = pw.connected;
  cooldown = Math.max(cooldown, Date.now() + (pw.retryAfter || 0) * 1000);
  if (pw.connected) {
    $('otp-form').hidden = true; $('otp').value = ''; $('phone').value = '';
    $('pw-token').value = ''; $('pw-refresh-token').value = ''; $('pw-device-id').value = '';
    $('account-detail').textContent = pw.maskedPhone || 'PW account';
    $('session-expiry').textContent = pw.expiresAt ? new Date(pw.expiresAt).toLocaleString() : 'Unknown';
  }
  const renewal = pw.refreshStatus === 'login_required' ? 'Login required' : !pw.autoRefresh ? 'Off' : pw.refreshStatus === 'retrying' ? `Retry: ${new Date(pw.nextRetryAt).toLocaleString()}` : pw.lastRefreshedAt ? `Last renewed: ${new Date(pw.lastRefreshedAt).toLocaleString()}` : 'Not yet verified';
  $('renewal-status').textContent = renewal;
  $('renew-now').hidden = !pw.autoRefresh;
  if (pw.refreshStatus === 'login_required') message(renewal, true);
  else if (pw.expired) message('Session expired. Sign in again.', true);
  if (pw.unreadable) message('Saved session unreadable. Sign in again.', true);
}
async function api(route, body) {
  const response = await fetch(`/admin/api/${route}`, {
    method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', cache: 'no-store',
    headers: { 'Content-Type': 'application/json', ...(csrf ? { 'X-CSRF-Token': csrf } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) })
  });
  if (response.status === 401) locked();
  return parseApiResponse(response, route);
}
function tick() {
  const seconds = Math.max(0, Math.ceil((cooldown - Date.now()) / 1000));
  $('send-otp').disabled = working || seconds > 0 || !captchaKey || !captchaToken;
  $('send-otp').textContent = seconds ? `Request another in ${seconds}s` : 'Send OTP →';
}
async function action(task) {
  if (working) return;
  working = true; document.querySelectorAll('button').forEach(b => b.disabled = true);
  message('Working…');
  try { await task(); } catch (error) { message(error.message || 'Connection failed. Try again.', true); }
  finally { working = false; document.querySelectorAll('button').forEach(b => b.disabled = false); tick(); }
}
$('unlock-form').addEventListener('submit', event => {
  event.preventDefault();
  void action(async () => {
    const key = $('owner-key').value; $('owner-key').value = '';
    const data = await api('login', { key }); csrf = data.csrf; remoteBrowser.configure(data.browser);
    message(''); account(data.pw);
  });
});
function method(name) {
  $('token-panel').hidden = name !== 'token';
  $('otp-panel').hidden = name !== 'otp';
  $('use-token').setAttribute('aria-pressed', String(name === 'token'));
  $('use-otp').setAttribute('aria-pressed', String(name === 'otp'));
  $('pw-token').value = ''; $('pw-refresh-token').value = ''; $('pw-device-id').value = ''; $('otp').value = '';
  message('');
  if (name === 'otp' && captchaKey) void mountCaptcha();
}
$('use-token').addEventListener('click', () => method('token'));
$('use-otp').addEventListener('click', () => method('otp'));
$('token-form').addEventListener('submit', event => {
  event.preventDefault();
  void action(async () => {
    const refreshToken = $('pw-refresh-token').value;
    const deviceId = $('pw-device-id').value.trim();
    const token = $('pw-token').value; $('pw-token').value = ''; $('pw-refresh-token').value = ''; $('pw-device-id').value = '';
    const data = await api('pw/import-token', { token, refreshToken, deviceId });
    message('Session saved.'); account(data);
  });
});
async function mountCaptcha() {
  if (captchaLoading || captchaWidget !== null) return;
  captchaLoading = true;
  try {
    if (!window.turnstile) await new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
      script.async = true;
      const timeout = setTimeout(() => reject(new Error('CAPTCHA could not load. Reload and try again.')), 15000);
      script.onload = () => { clearTimeout(timeout); resolve(); };
      script.onerror = () => { clearTimeout(timeout); reject(new Error('CAPTCHA could not load. Check browser extensions and reload.')); };
      document.head.append(script);
    });
    if (!csrf || !captchaKey) return;
    captchaWidget = window.turnstile.render('#pw-captcha', {
      sitekey: captchaKey, theme: 'dark', size: 'flexible', retry: 'never',
      callback: token => { captchaToken = token; tick(); },
      'expired-callback': () => { captchaToken = ''; tick(); },
      'error-callback': code => {
        captchaToken = ''; tick();
        message(String(code) === '110200' ? 'PW’s CAPTCHA does not authorize this domain. Sign in on PW and use Existing session.' : 'CAPTCHA verification failed. Reload or use Existing session.', true);
      }
    });
  } catch (error) { message(error.message, true); }
  finally { captchaLoading = false; }
}
function resetCaptcha() {
  captchaToken = '';
  if (captchaWidget !== null && window.turnstile) window.turnstile.reset(captchaWidget);
  tick();
}
$('phone').addEventListener('input', () => {
  const field = $('phone');
  const original = field.value;
  const caret = field.selectionStart ?? original.length;
  const cleaned = normalizePhone(original);
  if (cleaned !== original) {
    const nextCaret = normalizePhone(original.slice(0, caret)).length;
    field.value = cleaned;
    field.setSelectionRange(nextCaret, nextCaret);
  }
});
$('phone-form').addEventListener('submit', event => {
  event.preventDefault();
  void action(async () => {
    const phone = normalizePhone($('phone').value);
    $('otp-form').hidden = true; $('otp').value = '';
    // Match the server's no-retry policy even when the upstream request fails.
    cooldown = Date.now() + 60000;
    let data;
    try { data = await api('pw/send-otp', { phone, captchaToken }); } finally { resetCaptcha(); }
    $('otp-destination').textContent = `Sent to ${data.maskedPhone}`;
    $('otp-form').hidden = false; $('otp').focus(); message('OTP sent.');
  });
});
$('otp-form').addEventListener('submit', event => {
  event.preventDefault();
  void action(async () => {
    const otp = $('otp').value; $('otp').value = '';
    const data = await api('pw/verify-otp', { otp });
    message('PW session saved.'); account(data);
  });
});
$('replace-session').addEventListener('click', () => {
  editingSession = true; $('connected-panel').hidden = true; $('login-panel').hidden = false; method('token');
  message('');
});
$('renew-now').addEventListener('click', () => void action(async () => {
  try { const data = await api('pw/refresh', {}); account(data); message('Renewal completed.'); }
  catch (error) {
    try { const data = await api('session'); account(data.pw); } catch { /* Keep original failure. */ }
    throw error;
  }
}));
setInterval(async () => {
  if (!csrf || working || editingSession || document.hidden || $('connected-panel').hidden) return;
  try { const data = await api('session'); account(data.pw); } catch { /* Existing UI and normal requests report failures. */ }
}, 30000);
$('lock').addEventListener('click', () => void action(async () => { await api('logout', {}); locked(); message(''); }));
$('disconnect').addEventListener('click', () => void action(async () => { const data = await api('pw/disconnect', {}); account(data); message('Session removed.'); }));
setInterval(tick, 1000);
(async () => {
  try { const data = await api('session'); csrf = data.csrf; remoteBrowser.configure(data.browser); message(''); account(data.pw); }
  catch (error) {
    locked();
    if (error.status === 401) message('');
    else message(error.message || 'Could not reach the login service. Reload and try again.', true);
  }
})();
