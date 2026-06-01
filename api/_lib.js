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

function applyRateLimit(req, res, { limit, windowMs }) {
  const rl = rateLimit(clientIp(req), limit, windowMs);
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
  applyRateLimit,
  fetchWithTimeout,
};
