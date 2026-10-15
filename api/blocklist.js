// GET /api/blocklist.txt
// Proxies the Feodo Tracker IP blocklist (active botnet C2 servers) server-side
// and returns a plain-text list of one IP per line, ready to paste into a
// firewall / blocklist ingest. abuse.ch serves no CORS headers, so the browser
// can't read this feed directly; this relays it.
//
// Bandwidth strategy:
//   - s-maxage=3600              -> Vercel's CDN serves a cached copy for 1h
//   - stale-while-revalidate=7200 -> serve stale up to 2h more while refreshing

const { guard, fetchWithTimeout, validPublicIpv4 } = require('./_lib');

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
      // Upstream failure -> 502 with an empty body.
      res.statusCode = 502;
      res.setHeader('X-Content-Type-Options', 'nosniff');
      return res.end();
    }

    const data = await upstream.json();
    if (!Array.isArray(data)) {
      // Unexpected shape: fail loudly rather than cache (and serve to firewall
      // ingest) an empty list that would silently drop every block.
      res.statusCode = 502;
      res.setHeader('X-Content-Type-Options', 'nosniff');
      return res.end();
    }

    // Only well-formed public IPv4 addresses make it out. This output is meant
    // to be piped straight into firewall rules, so a poisoned or malformed
    // upstream entry (embedded newline, CIDR like 0.0.0.0/0, a private range)
    // must never be passed through.
    const text = data
      .map((c) => (c && typeof c === 'object' ? c.ip_address : null))
      .filter(validPublicIpv4)
      .join('\n');

    res.statusCode = 200;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader(
      'Cache-Control',
      `public, s-maxage=${S_MAXAGE}, stale-while-revalidate=${SWR}`
    );
    return res.end(text);
  } catch (err) {
    // Timeout / network failure -> 504 with an empty body.
    res.statusCode = 504;
    res.setHeader('X-Content-Type-Options', 'nosniff');
    return res.end();
  }
};
