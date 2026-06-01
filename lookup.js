// GET /api/lookup?source=urlhaus&host=<domain|ip>
// GET /api/lookup?source=cvss&cve=<CVE-id>
//
// Why this exists: URLhaus and NVD do not send CORS headers, so the browser
// can't call them directly. This relays the request server-side and returns
// JSON. Quad9 (DNS block status) is called client-side because it *does* send
// CORS — no need to proxy it.
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

async function urlhausLookup(host) {
  const r = await fetchWithTimeout('https://urlhaus-api.abuse.ch/v1/host/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `host=${encodeURIComponent(host)}`,
  });
  if (!r.ok) throw new Error('urlhaus ' + r.status);
  const j = await r.json();

  if (j.query_status === 'no_results') {
    return { host, status: 'clean', urls: 0, active: 0, tags: [] };
  }
  const urls = Array.isArray(j.urls) ? j.urls : [];
  const active = urls.filter((u) => u.url_status === 'online').length;
  const tags = [...new Set(urls.flatMap((u) => u.tags || []))].slice(0, 12);
  return {
    host,
    status: j.query_status === 'no_results' ? 'clean' : 'listed',
    urls: urls.length,
    active,
    tags,
  };
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
  if (req.method !== 'GET') return send(res, 405, { error: 'method_not_allowed' });
  if (!applyRateLimit(req, res, RL)) return;

  const url = new URL(req.url, 'http://localhost');
  const source = url.searchParams.get('source');

  try {
    if (source === 'urlhaus') {
      const host = validHost(url.searchParams.get('host'));
      if (!host) return send(res, 400, { error: 'invalid_host' });
      const data = await urlhausLookup(host);
      // URLhaus data shifts often; cache briefly.
      return send(res, 200, data, 'public, s-maxage=300, stale-while-revalidate=600');
    }

    if (source === 'cvss') {
      const cve = validCve(url.searchParams.get('cve'));
      if (!cve) return send(res, 400, { error: 'invalid_cve' });
      const data = await cvssLookup(cve);
      // CVSS base scores rarely change; cache hard to stay under NVD limits.
      return send(res, 200, data, 'public, s-maxage=86400, stale-while-revalidate=604800');
    }

    return send(res, 400, { error: 'unknown_source', allowed: ['urlhaus', 'cvss'] });
  } catch (err) {
    return send(res, 502, { error: 'upstream_error', message: 'lookup failed' });
  }
};
