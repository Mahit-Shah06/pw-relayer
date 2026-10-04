import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createApp } from './server.mjs';

test('connector, HLS relay, authentication, storage and failure recovery', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'pw-relayer-'));
  let failed = false;
  const upstream = http.createServer((req, res) => {
    if (req.headers.authorization !== 'Bearer upstream-secret') { res.writeHead(401); return res.end(); }
    if (failed) { res.writeHead(403); return res.end('expired'); }
    if (req.url === '/live.m3u8') { res.setHeader('Content-Type', 'application/vnd.apple.mpegurl'); return res.end('#EXTM3U\n#EXT-X-MAP:URI="init.mp4"\n#EXTINF:4,\nsegment.ts\n'); }
    if (req.url === '/redirect') { res.writeHead(302, { Location: 'http://example.invalid/nope' }); return res.end(); }
    res.end(req.url === '/segment.ts' ? 'segment-data' : '0123456789');
  });
  await new Promise(r => upstream.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${upstream.address().port}`;
  const source = (id, type, url) => ({ id, type, url: base + url, headers: { Authorization: 'Bearer upstream-secret' } });
  const configPath = path.join(dir, 'sources.json');
  await writeFile(configPath, JSON.stringify({ sources: [source('notes', 'file', '/notes'), source('live', 'hls', '/live.m3u8'), source('redirect', 'relay', '/redirect')] }));
  const token = 'test-token-that-is-at-least-32-characters';
  const app = createApp({ configPath, dataDir: path.join(dir, 'data'), token, interval: 999999 });
  try {
    const address = await app.start(0, '127.0.0.1');
    const target = `http://127.0.0.1:${address.port}`;
    const get = (url, extra = {}) => fetch(target + url, { headers: { Authorization: `Bearer ${token}`, ...extra } });
    assert.equal((await fetch(target + '/status')).status, 401);
    assert.equal((await fetch(target + '/healthz')).status, 200);
    for (let i = 0; i < 100; i++) {
      if ((await (await get('/status')).json()).sources.find(s => s.id === 'notes').ok) break;
      await new Promise(r => setTimeout(r, 10));
    }
    assert.equal(await (await get('/files/notes')).text(), '0123456789');
    const range = await get('/files/notes', { Range: 'bytes=2-5' });
    assert.equal(range.status, 206); assert.equal(await range.text(), '2345');
    assert.equal(await (await get('/files/notes', { Range: 'bytes=-3' })).text(), '789');
    assert.equal((await get('/files/notes', { Range: 'bytes=99-' })).status, 416);
    const playlist = await (await get('/relay/live')).text();
    assert.match(playlist, /URI="\/relay\/live\?/);
    const segment = playlist.split('\n').find(l => l.startsWith('/relay/'));
    assert.equal(await (await get(segment)).text(), 'segment-data');
    assert.equal((await get(segment.replace('sig=', 'sig=bad'))).status, 403);
    assert.equal((await get('/relay/redirect')).status, 502);
    failed = true; await app.sync();
    assert.equal(await (await get('/files/notes')).text(), '0123456789');
    const status = await (await get('/status')).json();
    assert.equal(status.sources.find(s => s.id === 'notes').ok, false);
    assert.ok(!JSON.stringify(status).includes('upstream-secret'));
  } finally {
    await app.stop(); upstream.closeAllConnections(); await new Promise(r => upstream.close(r));
    await rm(dir, { recursive: true, force: true });
  }
});
