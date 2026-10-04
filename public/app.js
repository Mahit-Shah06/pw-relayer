'use strict';
const $ = id => document.getElementById(id);
let csrf = '', cooldown = 0, working = false;
function message(text, error = false) { $('message').textContent = text; $('message').classList.toggle('error', error); }
function locked() {
  csrf = ''; $('unlock-panel').hidden = false; $('account-panel').hidden = true;
  $('otp-form').hidden = true; $('phone').value = ''; $('otp').value = '';
}
function account(pw) {
  $('unlock-panel').hidden = true; $('account-panel').hidden = false;
  $('connected-panel').hidden = !pw.connected; $('login-panel').hidden = pw.connected;
  cooldown = Math.max(cooldown, Date.now() + (pw.retryAfter || 0) * 1000);
  if (pw.connected) {
    $('otp-form').hidden = true; $('otp').value = ''; $('phone').value = '';
    $('account-detail').textContent = `${pw.maskedPhone} · Connected ${new Date(pw.connectedAt).toLocaleString()}`;
  }
  if (pw.expired) message('Your saved PW token has expired. Connect again with a new OTP.', true);
  if (pw.unreadable) message('The previous saved session could not be opened. Please connect again.', true);
}
async function api(route, body) {
  const response = await fetch(`/admin/api/${route}`, {
    method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', cache: 'no-store',
    headers: { 'Content-Type': 'application/json', ...(csrf ? { 'X-CSRF-Token': csrf } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) })
  });
  const data = await response.json();
  if (!response.ok) { if (response.status === 401) locked(); throw new Error(data.error || 'Request failed.'); }
  return data;
}
function tick() {
  const seconds = Math.max(0, Math.ceil((cooldown - Date.now()) / 1000));
  $('send-otp').disabled = working || seconds > 0;
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
    const data = await api('login', { key }); csrf = data.csrf;
    message('Console unlocked.'); account(data.pw);
  });
});
$('phone-form').addEventListener('submit', event => {
  event.preventDefault();
  void action(async () => {
    const phone = $('phone').value.trim();
    $('otp-form').hidden = true; $('otp').value = '';
    // Match the server's no-retry policy even when the upstream request fails.
    cooldown = Date.now() + 60000;
    const data = await api('pw/send-otp', { phone });
    $('otp-destination').textContent = `Sent to ${data.maskedPhone}`;
    $('otp-form').hidden = false; $('otp').focus(); message('OTP requested. Check your phone.');
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
$('lock').addEventListener('click', () => void action(async () => { await api('logout', {}); locked(); message('Console locked. Your saved PW session is retained.'); }));
$('disconnect').addEventListener('click', () => void action(async () => { const data = await api('pw/disconnect', {}); account(data); message('Saved PW session removed from this relay.'); }));
setInterval(tick, 1000);
(async () => {
  try { const data = await api('session'); csrf = data.csrf; message(''); account(data.pw); }
  catch { locked(); message('Unlock to manage your connection.'); }
})();
