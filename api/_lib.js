// Shared helpers for the serverless functions.
// Kept dependency-free on purpose: no DB, no external packages, easy to audit.

// ---- Input validation -------------------------------------------------------
// Strict allowlist patterns. Anything that does not match is rejected outright.
const DOMAIN_RE =
  /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/i;
const IPV4_RE =
  /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
const CVE_RE = /^CVE-\d{4}-\d{4,7}$/i;

// RFC1918 / loopback / link-local — reject so the tool isn't pointed at internal space.
function isPrivateIp(ip) {
  const o = ip.split('.').map(Number);
  if (o[0] === 10) return true;
  if (o[0] === 127) return true;
  if (o[0] === 169 && o[1] === 254) return true;
  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true;
  if (o[0] === 192 && o[1] === 168) return true;
  if (o[0] === 0) return true;
  return false;
}

function validHost(raw) {
  if (typeof raw !== 'string') return null;
  const v = raw.trim().toLowerCase();
  if (v.length === 0 || v.length > 253) return null;
  if (IPV4_RE.test(v)) return isPrivateIp(v) ? null : v;
  if (DOMAIN_RE.test(v)) {
    // No real TLD is all digits — rejects fake hosts like "999.999.999.999".
    const tld = v.split('.').pop();
    if (!/[a-z]/i.test(tld)) return null;
    return v;
  }
  return null;
}

function validCve(raw) {
  if (typeof raw !== 'string') return null;
  const v = raw.trim().toUpperCase();
  return CVE_RE.test(v) ? v : null;
}

// ---- Rate limiting ----------------------------------------------------------
// Best-effort in-memory token bucket. On serverless this is per-instance and
// resets on cold start, which is fine for a portfolio deployment and costs
// nothing. For production-grade distributed limits, swap `buckets` for Upstash
// Redis / Vercel KV (see README) — the call site does not change.
const buckets = new Map();

function rateLimit(key, limit, windowMs) {
  const now = Date.now();
  let b = buckets.get(key);
  if (!b || now > b.reset) {
    b = { count: 0, reset: now + windowMs };
    buckets.set(key, b);
  }
  b.count += 1;

  // Opportunistic cleanup so the map can't grow unbounded.
  if (buckets.size > 5000) {
    for (const [k, v] of buckets) if (now > v.reset) buckets.delete(k);
  }

  return {
    ok: b.count <= limit,
    remaining: Math.max(0, limit - b.count),
    reset: Math.ceil(b.reset / 1000),
  };
}

function clientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length) return xff.split(',')[0].trim();
  return req.socket?.remoteAddress || 'unknown';
}

// ---- Response helpers -------------------------------------------------------
// No Access-Control-Allow-Origin is set anywhere: the API is same-origin only,
// so it can't be reused as an open CORS proxy by third parties.
function send(res, status, body, cacheControl) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (cacheControl) res.setHeader('Cache-Control', cacheControl);
  res.end(JSON.stringify(body));
}

// ---- Request guards ---------------------------------------------------------
// Cheap door checks that run before any handler logic or upstream call. They
// shrink the attack surface: obvious automated/scanner traffic, oversized
// bodies, and wrong methods are dropped at the edge of the function so they
// never reach the relay code or burn an upstream request.

// Automated-client / scanner UA signatures. A missing or empty UA is treated as
// hostile too — every real browser and our own outbound fetches send one.
const SCANNER_UA_RE =
  /(?:curl\/|python-requests\/|Go-http-client\/|nuclei|zgrab|masscan)/i;

function isBlockedUserAgent(ua) {
  if (typeof ua !== 'string' || ua.trim() === '') return true;
  return SCANNER_UA_RE.test(ua);
}

// Standardized method check. Handlers were doing this inline and inconsistently;
// route everything through here so the 405 (with Allow header) is uniform.
function validateMethod(req, res, allowed = 'GET') {
  if (req.method === allowed) return true;
  res.setHeader('Allow', allowed);
  send(res, 405, { error: 'method_not_allowed' });
  return false;
}

// Single entry guard every handler calls first. Returns true if the request may
// proceed; on rejection it has already written the response.
function guard(req, res, { method = 'GET' } = {}) {
  // 1. Scanner / missing UA -> 403, before any work or upstream call.
  if (isBlockedUserAgent(req.headers['user-agent'])) {
    send(res, 403, { error: 'forbidden' });
    return false;
  }
  // 2. Oversized request -> 400. Every endpoint is GET-only and reads no body,
  //    so anything over 512 bytes is junk or a probe.
  const len = Number(req.headers['content-length']);
  if (Number.isFinite(len) && len > 512) {
    send(res, 400, { error: 'payload_too_large' });
    return false;
  }
  // 3. Wrong method -> 405.
  return validateMethod(req, res, method);
}

function applyRateLimit(req, res, { limit, windowMs }) {
  // Key on IP + path so each endpoint gets an independent bucket — bursting
  // /api/lookup can't exhaust the budget for, say, /api/kev.
  const { pathname } = new URL(req.url, 'http://localhost');
  const rl = rateLimit(`${clientIp(req)}:${pathname}`, limit, windowMs);
  res.setHeader('X-RateLimit-Limit', String(limit));
  res.setHeader('X-RateLimit-Remaining', String(rl.remaining));
  res.setHeader('X-RateLimit-Reset', String(rl.reset));
  if (!rl.ok) {
    res.setHeader('Retry-After', String(Math.max(1, rl.reset - Math.ceil(Date.now() / 1000))));
    send(res, 429, { error: 'rate_limited', message: 'Too many requests. Slow down.' });
    return false;
  }
  return true;
}

// fetch with a hard timeout so a slow upstream can't hang the function.
async function fetchWithTimeout(url, opts = {}, ms = 8000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...opts, signal: ctrl.signal });
  } finally {
    clearTimeout(t);
  }
}

module.exports = {
  validHost,
  validCve,
  rateLimit,
  clientIp,
  send,
  isBlockedUserAgent,
  validateMethod,
  guard,
  applyRateLimit,
  fetchWithTimeout,
};
