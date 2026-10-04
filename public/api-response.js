export class ApiError extends Error {
  constructor(message, status) { super(message); this.status = status; }
}
export async function parseApiResponse(response, route) {
  const names = { session: 'Login check', login: 'Owner login', logout: 'Sign out', 'pw/send-otp': 'Send OTP', 'pw/verify-otp': 'Verify OTP', 'pw/disconnect': 'Remove PW session' };
  const label = names[route] || 'Request';
  const type = response.headers.get('content-type') || '';
  const text = await response.text();
  if (!/\bapplication\/(?:[\w.-]+\+)?json\b/i.test(type)) {
    const html = /^\s*(?:<!doctype\s+html|<html)/i.test(text);
    const challenge = response.headers.get('cf-mitigated') === 'challenge';
    const ray = response.headers.get('cf-ray');
    const trace = ray && /^[a-zA-Z0-9-]{1,80}$/.test(ray) ? ` Cloudflare request ID: ${ray}.` : '';
    let hint;
    if (challenge) hint = 'Cloudflare returned a browser challenge. Reload the page and try again; if it persists, check the domain’s Cloudflare security events.';
    else if (response.status >= 500) hint = 'The gateway or relay failed. Check the relay process and Nginx logs.';
    else if (response.status === 403) hint = 'A server or security rule refused the request. Check the domain’s security events.';
    else hint = 'The request may have reached the wrong page or a gateway. Reload and try again.';
    throw new ApiError(`${label} received ${html ? 'an HTML page' : 'a non-JSON response'} instead of API data (HTTP ${response.status}). ${hint}${trace}`, response.status);
  }
  let data;
  try {
    data = JSON.parse(text);
    if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error();
  } catch {
    throw new ApiError(`${label} returned an invalid API response (HTTP ${response.status}). Reload and try again.`, response.status);
  }
  if (!response.ok) throw new ApiError(typeof data.error === 'string' ? data.error : `${label} failed (HTTP ${response.status}).`, response.status);
  return data;
}
