export function setupBrowser({ api, action, account, message }) {
  const $ = id => document.getElementById(id);
  let active = false, busy = false, timer, generation = 0, queue = Promise.resolve(), queued = 0;
  const canvas = $('browser-screen'), ctx = canvas.getContext('2d');
  function hide() { active = false; generation++; clearTimeout(timer); $('browser-room').hidden = true; $('browser-text').value = ''; ctx.clearRect(0, 0, canvas.width, canvas.height); }
  async function poll() {
    const gen = generation;
    try {
      const state = await api('pw/browser/status');
      if (gen !== generation) return;
      if (!state.active) { hide(); message('PW browser closed or expired. Open a new session if needed.'); return; }
      $('browser-save').disabled = !state.ready || busy;
      $('browser-state').textContent = state.ready ? 'PW returned a session. Click Save session to verify and store it.' : 'Sign in on the PW page below. Complete any CAPTCHA yourself.';
      const img = new Image();
      await new Promise((resolve, reject) => {
        img.onload = resolve; img.onerror = reject;
        img.src = `/admin/api/pw/browser/frame?t=${Date.now()}`;
      });
      if (gen === generation) ctx.drawImage(img, 0, 0);
    } catch { if (active) $('browser-state').textContent = 'Waiting for the browser… If it does not recover, close and reopen it.'; }
    finally { if (active && gen === generation) timer = setTimeout(poll, 800); }
  }
  function show() { active = true; generation++; $('browser-room').hidden = false; canvas.focus(); void poll(); }
  function input(body) {
    if (!active || queued >= 64) return;
    const gen = generation;
    queued++;
    queue = queue.then(async () => {
      if (!active || gen !== generation) return;
      busy = true;
      try { await api('pw/browser/input', body); }
      catch (error) { $('browser-state').textContent = error.message; }
      finally { busy = false; }
    }).finally(() => { queued--; });
    return queue;
  }
  $('browser-open').addEventListener('click', () => void action(async () => {
    const existing = await api('pw/browser/status');
    if (!existing.active) await api('pw/browser/start', {});
    show(); message('PW browser opened.');
  }));
  const run = task => action(async () => {
    try { await task(); } catch (error) { $('browser-state').textContent = error.message; throw error; }
  });
  $('browser-close').addEventListener('click', () => void run(async () => { await api('pw/browser/close', {}); hide(); message('PW browser closed.'); }));
  $('browser-save').addEventListener('click', () => void run(async () => {
    const state = await api('pw/browser/save', {}); hide(); account(state); message('PW session verified and saved.');
  }));
  canvas.addEventListener('click', event => {
    canvas.focus();
    const r = canvas.getBoundingClientRect();
    void input({ type: 'click', x: Math.min(999, Math.max(0, (event.clientX - r.left) * canvas.width / r.width)), y: Math.min(759, Math.max(0, (event.clientY - r.top) * canvas.height / r.height)) });
  });
  canvas.addEventListener('keydown', event => {
    if (event.altKey || ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() !== 'a')) return;
    event.preventDefault();
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'a') void input({ type: 'key', key: 'Control+A' });
    else if (event.key.length === 1) void input({ type: 'text', text: event.key });
    else if (['Enter', 'Tab', 'Backspace', 'Delete', 'ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', 'Escape', 'Home', 'End'].includes(event.key)) void input({ type: 'key', key: event.shiftKey && event.key === 'Tab' ? 'Shift+Tab' : event.key });
  });
  canvas.addEventListener('wheel', event => { event.preventDefault(); void input({ type: 'scroll', y: Math.max(-1000, Math.min(1000, event.deltaY)) }); }, { passive: false });
  $('browser-type').addEventListener('submit', event => {
    event.preventDefault(); const text = $('browser-text').value; $('browser-text').value = '';
    void input({ type: 'text', text });
  });
  $('browser-enter').addEventListener('click', () => void input({ type: 'key', key: 'Enter' }));
  return { hide, configure: state => { $('browser-open').hidden = !state?.enabled; } };
}
