# Get your PW login values

Use your own account in desktop Chrome or Edge. These instructions are separate from the relay's minimal login form.

## 1. Unlock your relay

Open https://pw.itzzsuperrr.me and enter **Owner key**. This is your relay's `ACCESS_TOKEN`, not a PW token. If you need to retrieve it, run privately on your VPS:

```sh
cd ~/pw-relayer
node --env-file=.env -p 'process.env.ACCESS_TOKEN'
```

Then choose **Existing session**. If a session is already connected, choose **Update saved session**.

## 2. Capture a fresh PW login

1. Open https://www.pw.live in a separate tab.
2. Open Developer Tools: **F12** or **Ctrl+Shift+I** on Windows/Linux, **Command+Option+I** on macOS.
3. Select **Network**, enable **Preserve log**, and leave the panel open. Make sure network recording is enabled (the record button is red).
4. If already signed in, sign out of PW. Then sign in again with your phone number and OTP. Complete any CAPTCHA on PW.
5. In the Network filter, type `oauth/token`.
6. Select the successful **POST** request to `api.penpencil.co` whose path ends in `/oauth/token`. Query parameters may follow it. Choose the login request, not `verify-token` or an `OPTIONS` request.
7. Open **Response** or **Preview** and expand `data` if needed. Look for `access_token` and `refresh_token`.

[Chrome's Network documentation](https://developer.chrome.com/docs/devtools/network/reference) explains recording, Preserve log, headers, and response inspection.

## 3. Fill the relay fields

| Relay field | Value from PW |
| --- | --- |
| Authorization token | `data.access_token` from the successful login response. Paste just the value, without JSON quotes. |
| Refresh token (optional) | `data.refresh_token` from that same response, without quotes or a `Bearer` prefix. Needed for automatic renewal. |
| Device ID (optional) | In that request's **Headers → Request Headers**, copy `randomid` if present. Header names are case-insensitive. You can also use the same session's `randomid` header on `verify-token`. Leave blank if absent. |

The `Authorization: Bearer ...` value you found on `verify-token` is also accepted in **Authorization token**. It is the access token, not the refresh token. Use a fresh access/refresh pair from the same login.

## 4. Verify the connection

Click **Verify & save session**, then **Test renewal now**. A successful renewal updates **Renewal** to **Last renewed: …**. Saving an access token alone does not prove the refresh token works.

If no login request appears, clear the filter and select **All**, then search again. If login happened before Network was recording, repeat the login with the panel open. If a successful login response has no `refresh_token`, leave that field blank; the access token cannot manufacture one. Renewal then remains off.

Paste credentials only into your own HTTPS relay. Do not share them in chat, screenshots, or exported network logs. PW can expire or revoke a session even when renewal is configured.

## Alternative: no token copying

On the relay choose **Open PW browser**, click PW's **Login/Register**, and complete login in that browser. When **Save session & close** becomes available, click it. The relay captures the returned access token and refresh token, if PW supplies one.
