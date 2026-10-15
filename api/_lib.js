// Shared helpers for the serverless functions.
// Kept dependency-free on purpose: no DB, no external packages, easy to audit.

// ---- Input validation -------------------------------------------------------
// Strict allowlist patterns. Anything that does not match is rejected outright.
const DOMAIN_RE =
  /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/i;
const IPV4_RE =
  /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
const CVE_RE = /^CVE-\d{4}-\d{4,7}$/i;

// Non-public space (RFC1918, loopback, link-local, CGNAT, benchmarking,
// IETF/test nets, multicast, reserved, broadcast) — reject so the tool isn't
// pointed at internal or meaningless address space.
function isPrivateIp(ip) {
  const o = ip.split('.').map(Number);
  if (o[0] === 0) return true;
  if (o[0] === 10) return true;
  if (o[0] === 100 && o[1] >= 64 && o[1] <= 127) return true; // CGNAT
  if (o[0] === 127) return true;
  if (o[0] === 169 && o[1] === 254) return true;
  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true;
  if (o[0] === 192 && o[1] === 0 && (o[2] === 0 || o[2] === 2)) return true;
  if (o[0] === 192 && o[1] === 168) return true;
  if (o[0] === 198 && (o[1] === 18 || o[1] === 19)) return true; // benchmarking
  if (o[0] === 198 && o[1] === 51 && o[2] === 100) return true; // TEST-NET-2
  if (o[0] === 203 && o[1] === 0 && o[2] === 113) return true; // TEST-NET-3
  if (o[0] >= 224) return true; // multicast, reserved, broadcast
  return false;
}

function validPublicIpv4(raw) {
  return typeof raw === 'string' && IPV4_RE.test(raw) && !isPrivateIp(raw);
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
const MAX_BUCKETS = 5000;

function rateLimit(key, limit, windowMs) {
  const now = Date.now();
  let b = buckets.get(key);
  if (!b || now > b.reset) {
    if (b) buckets.delete(key); // re-insert so Map order stays oldest-first
    b = { count: 0, reset: now + windowMs };
    buckets.set(key, b);
  }
  b.count += 1;

  // Keep the map bounded. Expired entries go first; if a flood of distinct
  // keys keeps it full of live entries, evict the oldest (Map iterates in
  // insertion order) so memory can't grow without limit.
  if (buckets.size > MAX_BUCKETS) {
    for (const [k, v] of buckets) if (now > v.reset) buckets.delete(k);
    for (const k of buckets.keys()) {
      if (buckets.size <= MAX_BUCKETS) break;
      buckets.delete(k);
    }
  }

  return {
    ok: b.count <= limit,
    remaining: Math.max(0, limit - b.count),
    reset: Math.ceil(b.reset / 1000),
  };
}

function clientIp(req) {
  // Prefer Vercel's `x-real-ip`: the platform sets it to the true connecting
  // client and a client-supplied value is overwritten, so it can't be spoofed.
  const real = req.headers['x-real-ip'];
  if (typeof real === 'string' && real.trim()) return real.trim();

  // Fallback: the RIGHTMOST entry of X-Forwarded-For is the address appended by
  // the closest trusted proxy. A client can prepend junk on the left to dodge
  // the rate limiter, but it can't forge what the proxy stamps on the right.
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length) {
    const parts = xff.split(',').map((s) => s.trim()).filter(Boolean);
    if (parts.length) return parts[parts.length - 1];
  }

  return req.socket?.remoteAddress || 'unknown';
}

// Rate-limit key for a client address. A single IPv6 subscriber is typically
// handed a whole /64, so keying on the full address would let one client
// rotate through 2^64 addresses and never hit the limit. Bucket IPv6 by /64.
function rateLimitKey(ip) {
  if (typeof ip !== 'string' || !ip.includes(':')) return ip;
  if (ip.startsWith('::ffff:') && ip.includes('.')) return ip.slice(7); // v4-mapped
  const [head, tail = ''] = ip.split('%')[0].split('::');
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  const groups = ip.includes('::')
    ? [...h, ...Array(Math.max(0, 8 - h.length - t.length)).fill('0'), ...t]
    : h;
  return groups
    .slice(0, 4)
    .map((g) => (parseInt(g, 16) || 0).toString(16))
    .join(':') + '::/64';
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
function guard(req, res, { method = 'GET', query = [] } = {}) {
  // 1. Scanner / missing UA -> 403, before any work or upstream call.
  if (isBlockedUserAgent(req.headers['user-agent'])) {
    send(res, 403, { error: 'forbidden' });
    return false;
  }
  // 2. Oversized request -> 400. Every endpoint is GET-only and reads no body,
  //    so anything over 512 bytes is junk or a probe. A chunked body carries no
  //    Content-Length, so reject Transfer-Encoding outright too.
  const len = Number(req.headers['content-length']);
  if ((Number.isFinite(len) && len > 512) || req.headers['transfer-encoding']) {
    send(res, 400, { error: 'payload_too_large' });
    return false;
  }
  // 3. Wrong method -> 405.
  if (!validateMethod(req, res, method)) return false;
  // 4. Unexpected query parameters -> 400. The CDN keys its cache on the full
  //    URL, so `/api/kev?x=<random>` would miss the cache every time and make
  //    this function re-fetch the upstream feed on every request — an easy way
  //    to hammer CISA/abuse.ch from our IP. Only allowlisted params pass.
  const { searchParams } = new URL(req.url, 'http://localhost');
  for (const k of searchParams.keys()) {
    if (!query.includes(k)) {
      send(res, 400, { error: 'unexpected_query' });
      return false;
    }
  }
  return true;
}

function applyRateLimit(req, res, { limit, windowMs }) {
  // Key on IP + path so each endpoint gets an independent bucket — bursting
  // /api/lookup can't exhaust the budget for, say, /api/kev.
  const { pathname } = new URL(req.url, 'http://localhost');
  const rl = rateLimit(`${rateLimitKey(clientIp(req))}:${pathname}`, limit, windowMs);
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

// fetch with a hard timeout AND a size cap, both covering the body as well as
// the headers. The body is buffered inside the timeout window, so an upstream
// that answers fast but then drips bytes (or streams forever) can't hang the
// function or exhaust its memory. Returns a fetch-like { ok, status, text(),
// json() } over the buffered body.
async function fetchWithTimeout(url, opts = {}, ms = 8000, maxBytes = 25 * 1024 * 1024) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    const r = await fetch(url, { ...opts, signal: ctrl.signal });
    const chunks = [];
    let size = 0;
    if (r.body) {
      const reader = r.body.getReader();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > maxBytes) {
          ctrl.abort();
          throw new Error('upstream response too large');
        }
        chunks.push(value);
      }
    }
    const body = Buffer.concat(chunks).toString('utf8');
    return {
      ok: r.ok,
      status: r.status,
      text: async () => body,
      json: async () => JSON.parse(body),
    };
  } finally {
    clearTimeout(t);
  }
}

// Coerce an untrusted feed field to a bounded string (or null). Keeps the
// browser from ever receiving objects/numbers where it expects text.
function str(v, max = 2000) {
  if (v == null) return null;
  return String(v).slice(0, max);
}

module.exports = {
  validHost,
  validCve,
  validPublicIpv4,
  str,
  rateLimit,
  clientIp,
  rateLimitKey,
  send,
  isBlockedUserAgent,
  validateMethod,
  guard,
  applyRateLimit,
  fetchWithTimeout,
};
