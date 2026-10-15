// GET /api/kev
// Fetches the CISA Known Exploited Vulnerabilities catalog server-side,
// slims it to the fields the UI needs, and returns it with aggressive edge
// caching so CISA is hit at most a few times per day regardless of traffic.
//
// Bandwidth strategy:
//   - s-maxage=21600        -> Vercel's CDN serves a cached copy for 6 hours
//   - stale-while-revalidate=43200 -> serve stale up to 12h more while refreshing
//   The origin (this function + CISA) runs only on a cache miss, not per visit.
//   The payload is trimmed from ~1MB+ to the handful of fields actually rendered.
//
// To change the refresh cadence, edit S_MAXAGE below (in seconds).

const { send, guard, fetchWithTimeout, str } = require('./_lib');

const KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

const S_MAXAGE = 21600; // 6h
const SWR = 43200; // 12h

module.exports = async function handler(req, res) {
  if (!guard(req, res)) return;

  try {
    const upstream = await fetchWithTimeout(KEV_URL, {
      headers: { 'User-Agent': 'passive-intel-console/1.0 (+defender tooling)' },
    });

    if (!upstream.ok) {
      return send(res, 502, { error: 'upstream_error', status: upstream.status });
    }

    const data = await upstream.json();
    if (!data || !Array.isArray(data.vulnerabilities)) {
      return send(res, 502, { error: 'upstream_error', message: 'unexpected feed format' });
    }

    // Slim + sort newest first. Drop fields the UI never reads. Every field is
    // coerced to a bounded string so the client only ever gets plain text.
    const slim = data.vulnerabilities
      .filter((v) => v && typeof v === 'object')
      .map((v) => ({
        cveID: str(v.cveID, 32),
        vendorProject: str(v.vendorProject, 256),
        product: str(v.product, 256),
        name: str(v.vulnerabilityName, 512),
        dateAdded: str(v.dateAdded, 32),
        dueDate: str(v.dueDate, 32),
        desc: str(v.shortDescription, 4000),
        ransomware: v.knownRansomwareCampaignUse === 'Known',
      }))
      .sort((a, b) => String(b.dateAdded).localeCompare(String(a.dateAdded)));

    return send(
      res,
      200,
      {
        source: 'cisa-kev',
        count: slim.length,
        catalogVersion: str(data.catalogVersion, 64),
        dateReleased: str(data.dateReleased, 64),
        vulnerabilities: slim,
      },
      `public, s-maxage=${S_MAXAGE}, stale-while-revalidate=${SWR}`
    );
  } catch (err) {
    return send(res, 504, { error: 'fetch_failed', message: 'KEV feed unavailable' });
  }
};
