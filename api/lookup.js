// GET /api/lookup?source=quad9&host=<domain|ip>
// GET /api/lookup?source=cvss&cve=<CVE-id>
//
// Why this exists: these upstreams are relayed server-side so the browser never
// talks to them directly. NVD sends no CORS headers; Quad9 is proxied so the
// page's CSP can drop dns.quad9.net from connect-src and keep everything
// same-origin.
//
// Security posture:
//   - Upstream URLs are HARDCODED. User input only ever becomes a validated
//     query/body parameter to a known host, never a fetch target -> no SSRF.
//   - Inputs are validated against strict allowlists before any network call.
//   - Rate limited per IP (in-memory token bucket).
//   - No Access-Control-Allow-Origin -> same-origin only, can't be abused as a
//     public CORS proxy.

const {
  validHost,
  validCve,
  send,
  guard,
  applyRateLimit,
  fetchWithTimeout,
} = require('./_lib');

// 30 lookups per minute per IP. Tune to taste.
const RL = { limit: 30, windowMs: 60_000 };

function severityFromScore(score) {
  if (score == null) return null;
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  return 'low';
}

// Quad9 filtered DoH resolver. NXDOMAIN (Status 3) on a host that should exist
// means Quad9 is refusing to resolve it — i.e. it's on a threat blocklist.
async function quad9Lookup(host) {
  const r = await fetchWithTimeout(
    `https://dns.quad9.net/dns-query?name=${encodeURIComponent(host)}&type=A`,
    { headers: { accept: 'application/dns-json' } }
  );
  if (!r.ok) throw new Error('quad9 ' + r.status);
  const j = await r.json();
  const answers = Array.isArray(j.Answer) ? j.Answer : [];
  const aRecords = answers.filter((a) => a.type === 1).map((a) => a.data);
  return { host, blocked: j.Status === 3, aRecords };
}

async function cvssLookup(cve) {
  const r = await fetchWithTimeout(
    `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cve)}`,
    { headers: { 'User-Agent': 'passive-intel-console/1.0 (+defender tooling)' } }
  );
  if (!r.ok) throw new Error('nvd ' + r.status);
  const j = await r.json();
  const metrics = j.vulnerabilities?.[0]?.cve?.metrics;
  const m =
    metrics?.cvssMetricV31?.[0] ||
    metrics?.cvssMetricV30?.[0] ||
    metrics?.cvssMetricV2?.[0];
  const score = m?.cvssData?.baseScore ?? null;
  const vector = m?.cvssData?.vectorString ?? null;
  return { cve, score, severity: severityFromScore(score), vector };
}

module.exports = async function handler(req, res) {
  if (!guard(req, res)) return;
  if (!applyRateLimit(req, res, RL)) return;

  const url = new URL(req.url, 'http://localhost');
  const source = url.searchParams.get('source');

  try {
    if (source === 'quad9') {
      const host = validHost(url.searchParams.get('host'));
      if (!host) return send(res, 400, { error: 'invalid_host' });
      const data = await quad9Lookup(host);
      // DNS verdicts can shift; cache briefly.
      return send(res, 200, data, 'public, s-maxage=300, stale-while-revalidate=600');
    }

    if (source === 'cvss') {
      const cve = validCve(url.searchParams.get('cve'));
      if (!cve) return send(res, 400, { error: 'invalid_cve' });
      const data = await cvssLookup(cve);
      // CVSS base scores rarely change; cache hard to stay under NVD limits.
      return send(res, 200, data, 'public, s-maxage=86400, stale-while-revalidate=604800');
    }

    return send(res, 400, { error: 'unknown_source', allowed: ['quad9', 'cvss'] });
  } catch (err) {
    return send(res, 502, { error: 'upstream_error', message: 'lookup failed' });
  }
};
