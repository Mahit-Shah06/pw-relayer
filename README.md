# pw-relayer

A dependency-free Node.js 22 HTTP connector, HLS relay, and local file store. Configure direct media, document, or data URLs. Includes an owner-only PW OTP login page. The PW adapter follows the request format in the existing local PW client; it is not a documented public integration and has not been validated with a real PW account. Course discovery, token renewal, DRM handling, and a viewer/player are not implemented.

## Start on a VPS

Install Docker with Compose, then run in this directory:

```sh
cp sources.example.json sources.json
cp .env.example .env
openssl rand -hex 32
```

Put the generated secret in `.env` as `ACCESS_TOKEN`. Edit `sources.json` with real source URLs; remove unused examples. If needed, set `SOURCE_AUTHORIZATION=Bearer your-source-token` in `.env`.

```sh
docker compose up -d --build
docker compose ps
docker compose logs --tail 100
```

The service listens at `127.0.0.1:8080` on the VPS. Put your HTTPS gateway in front of it. The Docker volume `relay-data` persists downloads across container recreation; `docker compose down -v` deletes it.

## Routes

Relay, file, and status routes require `Authorization: Bearer <ACCESS_TOKEN>`. `/healthz` is public. `/` redirects to `/admin/`; the owner console uses a separate protected cookie session after you enter the same owner key.

| Route | Function |
| --- | --- |
| `GET /healthz` | Process liveness only |
| `GET /status` | Per-source results from file syncs and relay requests |
| `GET /relay/lecture` | HLS playlist with rewritten segment, variant, and URI attribute links |
| `GET /relay/data` | Stream a configured HTTP resource |
| `GET /files/notes` | Latest completed download, with byte ranges and HEAD support |

Example:

```sh
curl -H 'Authorization: Bearer YOUR_ACCESS_TOKEN' http://127.0.0.1:8080/status
curl -H 'Authorization: Bearer YOUR_ACCESS_TOKEN' http://127.0.0.1:8080/files/notes -o notes.pdf
```

Your website backend/gateway should authenticate visitors and attach the service token. Do not embed that token in public JavaScript. HLS clients must authenticate every playlist/segment request, or use your authenticated gateway. Preserve `/relay/...` routes on that gateway because playlists contain root-relative URLs. A plain browser video/PDF element cannot attach this bearer header by itself. CORS and visitor sessions belong in your gateway.

## Source configuration

- `id`: unique letters, numbers, underscores, or hyphens.
- `type`: `file` for periodic local snapshots, `hls` for playlist rewriting, `relay` for direct HTTP streaming.
- `url`: direct source URL, not a login or course webpage.
- `auth`: optional `"pw"` to use the saved PW session for sources on exactly `https://api.penpencil.co`. PW credentials are never attached to other origins or CDN redirects.
- `headers`: server-side headers for the source origin, e.g. `Authorization` or `Cookie`.
- `headerEnv`: maps HTTP header names to environment variable names.
- `allowedOrigins`: exact additional origins permitted for redirects and HLS resources, including scheme and non-default port. Only add trusted origins.
- `originHeaders`: optional map from an additional origin to its own headers. Source credentials are never automatically copied across origins.
- `maxBytes`: maximum size of a stored file; default 100 MiB.
- `contentType`: MIME type served for a stored file; default `application/octet-stream`.

Configuration is reread for each request and sync. To change mounted configuration, edit the existing `sources.json` file in place; after replacing it via rename, recreate the container so Docker remounts the new file. Environment changes require `docker compose up -d --force-recreate`.

The service fetches files on startup and every `SYNC_INTERVAL_SECONDS` (default 300), sequentially, without overlapping syncs. Downloads use temporary files and atomic replacement; failures preserve the previous good file. One latest file per ID is retained. There is no version history or total disk quota; plan storage for all configured limits plus one temporary download. Removing a source does not delete its existing stored file.

Upstream requests have a 30-second deadline including the body, bounded redirects, and up to three attempts for HTTP 429/502/503/504. Network errors and interrupted bodies are retried on the next file sync or client request. Large downloads must finish within that deadline. HLS is suitable for live streaming because each playlist/segment is a separate request; this service is not an indefinite raw-stream relay, transcoder, or RTMP server. Standard HLS URI lines and quoted URI attributes are rewritten; DASH, HLS variable substitution, content steering, and DRM license workflows are not implemented.

Playlist size is limited to 2 MiB; there are at most 32 simultaneous authenticated requests. HLS segments are fetched per viewer, not cached or recorded. File status is checked periodically; relay status reflects actual requests rather than active probing. Status history resets on restart. Docker restarts exited containers; an unhealthy health check alone does not trigger a restart.

Only trusted administrators should edit source configuration: configured origins can include internal services. Clients cannot choose arbitrary unsigned relay destinations. Signed HLS links still require authentication. URLs and credentials are excluded from status/error responses; avoid enabling gateway query-string logging because rewritten HLS links may contain upstream URL tokens.

## Local development and verification

```sh
node --env-file=.env server.mjs
npm test
```

Tests use a local upstream fixture to cover authentication, downloads, byte ranges, HLS rewriting and segment forwarding, signature rejection, redirect restrictions, and retention after upstream failure. Run only one instance per data directory. No external services or PW credentials are needed for these tests.

## PM2 with an existing Nginx server

Transfer this folder to `~/pw-relayer` on your VPS, then:

```sh
cd ~/pw-relayer
sh setup-local.sh
npm test
pm2 start ecosystem.config.cjs --only pw-relayer
curl --fail http://127.0.0.1:8080/healthz
pm2 save
```

The setup script preserves existing configuration and creates an empty source list on first run. An empty list starts successfully but does not relay content until you configure sources. The PM2 configuration binds to localhost, port 8080, and loads secrets from `.env`. Only run one instance. If PM2 startup is not already enabled, run `pm2 startup` and execute the command it prints, then `pm2 save`.

Use your existing Nginx HTTPS virtual host to proxy the required routes, preserving `/relay/...` and `/files/...`. Inspect its existing routes before changing it. Do not expose port 8080 in the VPS security group. The hostname now opens the owner login console. Existing relay/file routes remain backend endpoints.


## PW OTP login from your domain

After pulling an update on the VPS:

```sh
cd ~/pw-relayer
git pull --ff-only
npm test
pm2 restart pw-relayer
```

Open `https://pw.itzzsuperrr.me/` (or your configured HTTPS domain). Unlock the console with the owner key from `.env`. To display it privately on your VPS:

```sh
node --env-file=.env -p 'process.env.ACCESS_TOKEN'
```

Do not paste the key into chat, public JavaScript, or your Git repository. The page clears the owner-key field after submission and keeps no key in browser storage. Once unlocked, enter your PW mobile number (India, +91), request an OTP, and enter the code. Do not send your OTP to anyone else.

The owner session uses an HttpOnly, Secure, SameSite=Strict cookie, lasts eight hours, and is cleared by server restarts. POST routes require a matching Origin and CSRF token. An optional `PUBLIC_ORIGIN=https://pw.itzzsuperrr.me` in `.env` pins the accepted browser origin; otherwise the app uses the host and HTTPS scheme set by your trusted Nginx proxy. Keep the service bound to localhost when using PM2. HTTPS is required for the owner cookie (browsers allow localhost for local development).

PW authentication endpoints used by this adapter:

- `POST https://api.penpencil.co/v1/users/get-otp?smsType=0`
- `POST https://api.penpencil.co/v3/oauth/token?smsType=0&fallback=true`

These formats were found in the user's existing local PW client, not a public partner API specification. Live acceptance is unverified. PW may change the endpoints, require a challenge, or reject server-originated login. The service reports failure in those cases; it does not bypass CAPTCHA, device checks, or access controls. No real phone number/OTP is used during automated tests, and sending SMS is never automatically retried.

Limits: at most one OTP request per minute, five verification attempts per challenge, and a five-minute local challenge lifetime. Phone/OTP payloads are held only for the active request/challenge and are not logged. Only the last four phone digits are saved. PW tokens never appear in browser responses. The access token is encrypted with AES-256-GCM in `data/.pw-session.enc` using a key derived from `ACCESS_TOKEN`; that file has mode 0600. Keep your `.env` and volume private and back up them together. Changing `ACCESS_TOKEN` makes the old saved session unreadable; connect again to replace it.

“Connected” means a token was returned and saved, and its known expiry has not elapsed; it is not continuous confirmation that PW still accepts the token. Automatic token refresh is not implemented. Revoked/expired sessions require login again. “Sign out” ends browser access while preserving the stored PW session. “Remove saved PW session” deletes this relay's local token, not PW sessions on other devices.

Login alone does not import batches or produce stream URLs. Configured PW API sources can opt into the saved token with `"auth": "pw"`; batch discovery and content importing remain separate work.
