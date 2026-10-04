# pw-relayer

A dependency-free Node.js 22 HTTP connector, HLS relay, and local file store. Configure direct media, document, or data URLs. Includes an owner-only PW login page with OTP and existing-session import. The PW adapter follows the request format in the existing local PW client; it is not a documented public integration and has not been validated with a real PW account. Automatic renewal is supported when a valid PW refresh token is available. Course discovery, DRM handling, and a viewer/player are not implemented.

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

Do not paste the key into chat, public JavaScript, or your Git repository. The page clears the owner-key field after submission and keeps no key in browser storage. Select **Phone & OTP** after unlocking, then enter your PW mobile number (India, +91), request an OTP, and enter the code. Spaces in pasted numbers, including non-breaking spaces, are removed automatically; extra digits and letters are not silently discarded. Do not send your OTP to anyone else.

The owner session uses an HttpOnly, Secure, SameSite=Strict cookie, lasts eight hours, and is cleared by server restarts. POST routes require a matching Origin and CSRF token. An optional `PUBLIC_ORIGIN=https://pw.itzzsuperrr.me` in `.env` pins the accepted browser origin; otherwise the app uses the host and HTTPS scheme set by your trusted Nginx proxy. Keep the service bound to localhost when using PM2. HTTPS is required for the owner cookie (browsers allow localhost for local development).

PW authentication endpoints used by this adapter:

- `POST https://api.penpencil.co/v1/users/get-otp?smsType=0`
- `POST https://api.penpencil.co/v3/oauth/token?smsType=0&fallback=true`

These formats were found in the user's existing local PW client, not a public partner API specification. Live acceptance is unverified. PW may change the endpoints, require a challenge, or reject server-originated login. The service reports failure in those cases; it does not bypass CAPTCHA, device checks, or access controls. No real phone number/OTP is used during automated tests, and sending SMS is never automatically retried.

Limits: at most one OTP request per minute, five verification attempts per challenge, and a five-minute local challenge lifetime. Phone/OTP payloads are held only for the active request/challenge and are not logged. Only the last four phone digits are saved. PW tokens never appear in browser responses. The access token is encrypted with AES-256-GCM in `data/.pw-session.enc` using a key derived from `ACCESS_TOKEN`; that file has mode 0600. Keep your `.env` and volume private and back up them together. Changing `ACCESS_TOKEN` makes the old saved session unreadable; connect again to replace it.

“Connected” means a token was returned and saved, and its known expiry has not elapsed; it is not continuous confirmation that PW still accepts the token. With a refresh token, the relay attempts automatic renewal. Without one, or if PW revokes/rejects renewal, you must connect again. “Sign out” ends browser access while preserving the stored PW session. “Remove saved PW session” deletes this relay's local token, not PW sessions on other devices.

Login alone does not import batches or produce stream URLs. Configured PW API sources can opt into the saved token with `"auth": "pw"`; batch discovery and content importing remain separate work.


## Diagnosing OTP failures

A PM2 status of `online` only confirms the process is running. To test the local/public route and outbound PW connectivity without sending any phone number or OTP:

```sh
npm run diagnose
```

After a failed login attempt, inspect the request diagnostics:

```sh
pm2 logs pw-relayer --lines 40 --nostream
```

`pw.request.started`, `pw.request.failed`, and `pw.request.succeeded` include only the operation, random reference ID, timing, and status/error categories. They never include request bodies, provider response bodies, phone numbers, OTPs, or tokens. Match the page's reference ID to the log entry. `PW_DNS`, `PW_TLS`, and `PW_TIMEOUT` indicate VPS-to-provider connection problems; `PW_NON_JSON`, `PW_REJECTED`, and `PW_CHALLENGE` indicate a response that did not complete the expected login flow. A check against the PW API root may return 404/403; receiving an HTTP response tests connectivity, not successful OTP login.

Provider dependency failures now return structured JSON with HTTP 424 instead of being presented as generic gateway 502 failures. They are still failures. This distinguishes them from an actual Nginx/Cloudflare 502. If the browser still receives HTML and no matching request appears in PM2 logs, inspect the proxy path. If Nginx has inherited error-page interception enabled, set `proxy_intercept_errors off;` inside this site's proxy location, then validate/reload Nginx. Do not replace the Certbot-managed TLS configuration.

The public PW login bundle inspected on 2026-10-04 includes optional CAPTCHA-backed OTP endpoints and CAPTCHA token/site-key fields. The current adapter does not implement that browser challenge flow. A provider HTTP 403 confirms rejection but does not identify whether a challenge, request requirement, or server access restriction caused it; changing endpoint names alone is not a verified fix.


## Import an existing PW session

If OTP login is rejected, use **Existing session** after unlocking your private login page.

1. Sign in to your own account on `https://www.pw.live/` and complete any OTP/CAPTCHA there.
2. Open your browser's Developer Tools → Network, reload PW, and select an authenticated request to `api.penpencil.co`.
3. In **Request Headers**, copy the **Authorization** value. Copy only the value, not all request headers or a full cURL command.
4. Paste it into **PW Authorization value** on your relay and click **Verify & save session**.

The form accepts a raw token, `Bearer <token>`, or `Authorization: Bearer <token>`. It sends the credential only to this relay; the relay verifies it against the fixed PW token-verification endpoint. Redirects are refused. It requires `success: true` and `data.isVerified: true` before replacing the saved session. Invalid, expired, rejected, or unconfirmed tokens are not saved; the previous saved session remains intact. Verification is limited to one attempt per five seconds. Your token is cleared from the form after submission, is not saved in localStorage, is not logged or echoed, and is encrypted in the existing session file.

Treat the copied value like a password. Paste it only into your own HTTPS relay, never into chat or a GitHub issue. It may expire, be revoked, or be bound to PW's original device/session context. Import cannot guarantee PW will accept the token from your VPS. An access-only import cannot renew itself; provide the matching refresh token to configure automatic renewal. Expiry is shown when the token contains an expiry claim; otherwise it is unknown.

The existing-session flow uses `POST /admin/api/pw/import-token`, guarded by owner authentication, CSRF checks, and the same-origin policy. Its upstream verification request follows the public PW SDK format: `POST /v3/oauth/verify-token` with organization and random-device context. The current public SDK also supplies `client-type: WEB` and an organization `client-id` header; these headers are now included in all PW authentication requests. This fixes a request-format difference but has not been verified to resolve the live OTP 403. No real SMS was sent during these changes.


## Automatic renewal

Update the VPS and reload the PM2 configuration (the shutdown grace period now allows time to finish a renewal):

```sh
git pull --ff-only
npm test
pm2 startOrRestart ecosystem.config.cjs --only pw-relayer
pm2 save
```

For an already saved access-only session, click **Update saved session**. Paste a fresh access token and the matching **refresh_token** from PW's successful login response (Network → `oauth/token` → Response), or the same session's `TOKEN_CONTEXT`. You may need to log in once on PW with Developer Tools open to capture that response. If available, supply the original `randomId` under Optional device context. Click **Verify & save session**, then **Test renewal now** to check whether PW accepts renewal from your VPS. A successful access-token verification does not prove the refresh token is valid; the UI explicitly shows when the first renewal is still unverified.

Successful OTP login now retains `refresh_token` automatically when PW returns one. Previously saved access-only sessions cannot acquire a refresh token by themselves.

- The server checks every 30 seconds and on startup. When expiry is known, it attempts renewal shortly before expiry (up to two minutes early).
- PW-authenticated relay/file requests wait for a due renewal before fetching. After an upstream 401, they may trigger one renewal and retry the request once. An arbitrary 403 does not trigger renewal.
- Concurrent renewals share one request. Manual renewals have a 30-second cooldown.
- Rotated access and refresh tokens are encrypted and atomically saved. If PW omits a replacement refresh token, the current one is retained.
- Network/5xx/rate-limit failures preserve the current session and use exponential backoff from one minute to fifteen minutes. Backoff survives restart. An unexpired access token can still be used during a temporary renewal failure.
- Rejected/revoked credentials, security challenges, or invalid renewal responses stop renewal and show **Login required**. They are not retried indefinitely.
- If expiry is unknown, renewal is reactive to a 401 or the manual test; the server does not guess a token lifetime. This is only for sources explicitly configured with `"auth":"pw"`.
- The UI reports the last successful renewal, retry time, and whether a refresh token is available. No credentials are included in the status API or logs.

The refresh request follows PW's public web SDK: `POST https://api.penpencil.co/v3/oauth/refresh-token`, with `client_id`, `refresh_token`, and `client_secret` when configured. `PW_CLIENT_ID` defaults to `system-admin`. If your PW client requires a client secret, set `PW_CLIENT_SECRET` privately in `.env` using the client configuration from your own official PW login request, then restart the process. This is separate from the account access/refresh tokens; do not commit it or send it in chat. The connector does not invent or bypass client credentials. Missing required client configuration can cause renewal to be rejected.

Renewal is covered by simulated provider tests; live PW acceptance still needs the **Test renewal now** check with your session. Signing out, account restrictions, token rotation on another device, or PW security checks can still require another login. Do not run multiple relay instances against the same session directory. A disk-write failure after provider rotation is reported as a storage failure; fix storage and reconnect before relying on persistence.
