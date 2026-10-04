import http from 'node:http';
import { readFile, mkdir, rename, unlink, stat } from 'node:fs/promises';
import { createReadStream, createWriteStream } from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { Readable, Transform } from 'node:stream';
import { createHmac, timingSafeEqual, randomUUID } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export function createApp({ configPath = process.env.CONFIG_PATH || './sources.json', dataDir = process.env.DATA_DIR || './data', token = process.env.ACCESS_TOKEN, interval = Number(process.env.SYNC_INTERVAL_SECONDS || 300) * 1000 } = {}) {
  if (!token || token.length < 32) throw new Error('ACCESS_TOKEN must contain at least 32 characters');
  if (!Number.isFinite(interval) || interval < 1000) throw new Error('Invalid sync interval');
  const states = new Map();
  let timer, syncing = false, active = 0;
  function equal(a, b) { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && timingSafeEqual(x, y); }
  function sign(id, url) { return createHmac('sha256', token).update(`${id}\n${url}`).digest('hex'); }
  async function config() {
    const c = JSON.parse(await readFile(configPath, 'utf8'));
    if (!Array.isArray(c.sources)) throw new Error('sources must be an array');
    const ids = new Set();
    for (const s of c.sources) {
      if (!/^[a-zA-Z0-9_-]{1,64}$/.test(s.id) || ids.has(s.id)) throw new Error('Invalid or duplicate source id');
      ids.add(s.id);
      if (!['relay', 'hls', 'file'].includes(s.type)) throw new Error('Invalid source type');
      validate(s, s.url);
      if (s.maxBytes !== undefined && (!Number.isSafeInteger(s.maxBytes) || s.maxBytes < 1)) throw new Error('Invalid maxBytes');
    }
    return c.sources;
  }
  function validate(s, url) {
    const u = new URL(url);
    const origin = new URL(s.url).origin;
    if (!['http:', 'https:'].includes(u.protocol) || u.username || u.password || u.hash) throw new Error('Invalid URL');
    if (u.origin !== origin && !(s.allowedOrigins || []).includes(u.origin)) throw new Error('Origin not allowed');
    return u;
  }
  function headers(s, url, range) {
    // Credentials only go to the source origin unless explicitly configured for another origin.
    const origin = new URL(url).origin;
    const h = { ...(origin === new URL(s.url).origin ? s.headers : s.originHeaders?.[origin]) };
    for (const [k, v] of Object.entries(s.headerEnv || {})) {
      if (origin === new URL(s.url).origin && process.env[v]) h[k] = process.env[v];
    }
    if (range) h.Range = range;
    h['Accept-Encoding'] = 'identity';
    return h;
  }
  async function upstream(s, initial, range, signal) {
    let url = initial;
    for (let redirects = 0; redirects <= 5; redirects++) {
      validate(s, url);
      let response;
      for (let attempt = 0; attempt < 3; attempt++) {
        const timeout = AbortSignal.timeout(30000);
        response = await fetch(url, { headers: headers(s, url, range), redirect: 'manual', signal: signal ? AbortSignal.any([signal, timeout]) : timeout });
        if (![429, 502, 503, 504].includes(response.status) || attempt === 2) break;
        await response.body?.cancel();
        await new Promise(r => setTimeout(r, 250 * 2 ** attempt));
      }
      if ([301, 302, 303, 307, 308].includes(response.status)) {
        const location = response.headers.get('location');
        await response.body?.cancel();
        if (!location) throw new Error('Missing redirect location');
        url = new URL(location, url).href;
      } else return { response, url };
    }
    throw new Error('Too many redirects');
  }
  function limited(max) {
    let size = 0;
    return new Transform({ transform(chunk, encoding, cb) { size += chunk.length; cb(size > max ? new Error('Size limit exceeded') : null, chunk); } });
  }
  function rewrite(s, base, body) {
    const link = value => {
      const url = new URL(value, base).href;
      validate(s, url);
      const q = new URLSearchParams({ url, sig: sign(s.id, url) });
      return `/relay/${s.id}?${q}`;
    };
    if (!body.trimStart().startsWith('#EXTM3U')) throw new Error('Invalid HLS playlist');
    return body.split('\n').map(line => {
      if (!line.trim()) return line;
      if (line.startsWith('#')) return line.replace(/URI="([^"]+)"/g, (_, uri) => `URI="${link(uri)}"`);
      return link(line.trim());
    }).join('\n');
  }
  async function sync() {
    if (syncing) return;
    syncing = true;
    try {
      const sources = await config();
      for (const s of sources.filter(s => s.type === 'file')) {
        const tmp = path.join(dataDir, `${s.id}.${randomUUID()}.tmp`);
        try {
          const { response } = await upstream(s, s.url);
          if (response.status !== 200) { await response.body?.cancel(); throw new Error(`HTTP ${response.status}`); }
          await pipeline(Readable.fromWeb(response.body), limited(s.maxBytes || 100 * 1024 * 1024), createWriteStream(tmp, { flags: 'wx', mode: 0o600 }));
          await rename(tmp, path.join(dataDir, s.id));
          states.set(s.id, { ok: true, lastSuccess: new Date().toISOString() });
        } catch {
          await unlink(tmp).catch(() => {});
          states.set(s.id, { ...states.get(s.id), ok: false, lastFailure: new Date().toISOString(), error: 'Download failed; check source URL, credentials, size limit, and connectivity' });
        }
      }
    } catch { console.error('Configuration could not be loaded; sync skipped'); }
    finally { syncing = false; }
  }
  const server = http.createServer(async (req, res) => {
    const send = (status, data) => { res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(data)); };
    const controller = new AbortController();
    res.on('close', () => controller.abort());
    try {
      const u = new URL(req.url, 'http://localhost');
      if (u.pathname === '/healthz' && req.method === 'GET') return send(200, { ok: true });
      if (!equal(req.headers.authorization || '', `Bearer ${token}`)) return send(401, { error: 'Unauthorized' });
      if (!['GET', 'HEAD'].includes(req.method)) return send(405, { error: 'Method not allowed' });
      if (active >= 32) return send(503, { error: 'Busy' });
      active++;
      try {
        const sources = await config();
        if (u.pathname === '/status') return send(200, { syncing, sources: sources.map(s => ({ id: s.id, type: s.type, ...(states.get(s.id) || { ok: null }) })) });
        const match = /^\/(relay|files)\/([a-zA-Z0-9_-]+)$/.exec(u.pathname);
        const s = match && sources.find(s => s.id === match[2]);
        if (!s) return send(404, { error: 'Not found' });
        if (match[1] === 'files') {
          if (s.type !== 'file') return send(404, { error: 'Not a stored source' });
          const file = path.join(dataDir, s.id);
          let info;
          try { info = await stat(file); } catch { return send(404, { error: 'File not downloaded yet' }); }
          let start = 0, end = info.size - 1, status = 200;
          if (req.headers.range) {
            const m = /^bytes=(\d*)-(\d*)$/.exec(req.headers.range);
            if (!m || (!m[1] && !m[2])) { res.setHeader('Content-Range', `bytes */${info.size}`); return send(416, { error: 'Invalid range' }); }
            start = m[1] ? Number(m[1]) : Math.max(0, info.size - Number(m[2]));
            end = m[1] && m[2] ? Math.min(Number(m[2]), end) : end;
            if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start > end || start >= info.size) { res.setHeader('Content-Range', `bytes */${info.size}`); return send(416, { error: 'Invalid range' }); }
            status = 206;
            res.setHeader('Content-Range', `bytes ${start}-${end}/${info.size}`);
          }
          res.writeHead(status, { 'Content-Type': s.contentType || 'application/octet-stream', 'Content-Length': Math.max(0, end - start + 1), 'Accept-Ranges': 'bytes', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
          if (req.method === 'HEAD' || !info.size) return res.end();
          await pipeline(createReadStream(file, { start, end }), res);
          return;
        }
        if (s.type === 'file') return send(404, { error: 'Use /files for stored sources' });
        const url = u.searchParams.get('url') || s.url;
        if (u.searchParams.has('url') && !equal(u.searchParams.get('sig') || '', sign(s.id, url))) return send(403, { error: 'Invalid relay signature' });
        const { response, url: finalUrl } = await upstream(s, url, req.headers.range, controller.signal);
        if (!response.ok) {
          await response.body?.cancel();
          states.set(s.id, { ok: false, upstreamStatus: response.status });
          return send(response.status === 416 ? 416 : 502, { error: 'Upstream rejected request', upstreamStatus: response.status });
        }
        const type = response.headers.get('content-type') || 'application/octet-stream';
        const playlist = s.type === 'hls' && (url === s.url || /\.m3u8$/i.test(new URL(finalUrl).pathname) || /mpegurl/i.test(type));
        res.setHeader('Cache-Control', 'no-store');
        res.setHeader('X-Content-Type-Options', 'nosniff');
        if (playlist) {
          const chunks = [];
          let size = 0;
          for await (const chunk of response.body) {
            size += chunk.length;
            if (size > 2 * 1024 * 1024) throw new Error('Playlist size limit exceeded');
            chunks.push(Buffer.from(chunk));
          }
          const body = rewrite(s, finalUrl, Buffer.concat(chunks).toString('utf8'));
          res.writeHead(200, { 'Content-Type': 'application/vnd.apple.mpegurl' });
          res.end(req.method === 'HEAD' ? undefined : body);
        } else {
          for (const name of ['content-range', 'accept-ranges']) if (response.headers.has(name)) res.setHeader(name, response.headers.get(name));
          res.writeHead(response.status, { 'Content-Type': type });
          if (req.method === 'HEAD') { await response.body?.cancel(); res.end(); }
          else await pipeline(Readable.fromWeb(response.body), res);
        }
        states.set(s.id, { ok: true, lastSuccess: new Date().toISOString() });
      } finally { active--; }
    } catch {
      if (!res.headersSent) send(502, { error: 'Request failed; check source configuration and connectivity' });
      else res.destroy();
    }
  });
  return { server, sync, async start(port = Number(process.env.PORT || 8080), host = process.env.HOST || '0.0.0.0') {
    await config(); await mkdir(dataDir, { recursive: true });
    // Remove partial downloads from previous crashes; only run one instance per data directory.
    const { readdir } = await import('node:fs/promises');
    for (const f of await readdir(dataDir)) if (/^[\w-]+\.[\da-f-]+\.tmp$/.test(f)) await unlink(path.join(dataDir, f));
    await new Promise(resolve => server.listen(port, host, resolve));
    void sync(); timer = setInterval(sync, interval); timer.unref();
    return server.address();
  }, async stop() { clearInterval(timer); server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); } };
}
if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const app = createApp();
  await app.start();
  console.log('pw-relayer listening');
  for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, async () => { await app.stop(); process.exit(0); });
}
