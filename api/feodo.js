// GET /api/feodo
// Proxies the Feodo Tracker IP blocklist (active botnet C2 servers) server-side
// and returns a slimmed JSON array. abuse.ch serves no CORS headers, so the
// browser can't read this feed directly; this relays it.
//
// Bandwidth strategy:
//   - s-maxage=3600              -> Vercel's CDN serves a cached copy for 1h
//   - stale-while-revalidate=7200 -> serve stale up to 2h more while refreshing

const { send, guard, fetchWithTimeout } = require('./_lib');

const FEODO_URL = 'https://feodotracker.abuse.ch/downloads/ipblocklist.json';

const S_MAXAGE = 3600; // 1h
const SWR = 7200; // 2h

module.exports = async function handler(req, res) {
  if (!guard(req, res)) return;

  try {
    const upstream = await fetchWithTimeout(FEODO_URL, {
      headers: { 'User-Agent': 'passive-intel-console/1.0 (+defender tooling)' },
    });

    if (!upstream.ok) {
      return send(res, 502, { error: 'upstream_error', status: upstream.status });
    }

    const data = await upstream.json();
    const list = Array.isArray(data) ? data : [];

    // Slim to the fields the UI renders, newest C2 first.
    const slim = list
      .map((c) => ({
        ip: c.ip_address,
        port: c.port,
        malware: c.malware,
        firstSeen: c.first_seen,
        lastSeen: c.last_online,
        country: c.country,
      }))
      .sort((a, b) => String(b.firstSeen).localeCompare(String(a.firstSeen)));

    return send(
      res,
      200,
      { source: 'feodo-tracker', count: slim.length, c2: slim },
      `public, s-maxage=${S_MAXAGE}, stale-while-revalidate=${SWR}`
    );
  } catch (err) {
    return send(res, 504, { error: 'fetch_failed', message: 'Feodo feed unavailable' });
  }
};
