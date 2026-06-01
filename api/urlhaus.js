// GET /api/urlhaus
// Proxies the URLhaus "online" CSV feed server-side, parses it, and returns a
// slimmed JSON array of currently-active malware URLs. URLhaus serves no CORS
// headers, so the browser can't read this feed directly; this relays it.
//
// Bandwidth strategy:
//   - s-maxage=1800              -> Vercel's CDN serves a cached copy for 30 min
//   - stale-while-revalidate=3600 -> serve stale up to 1h more while refreshing
//   abuse.ch is hit at most a couple of times per hour regardless of traffic.

const { send, guard, fetchWithTimeout } = require('./_lib');

const URLHAUS_CSV = 'https://urlhaus.abuse.ch/downloads/csv_online/';

const S_MAXAGE = 1800; // 30m
const SWR = 3600; // 1h

// Parse one CSV line respecting double-quoted fields (URLhaus quotes every
// field and escapes embedded quotes by doubling them).
function parseCsvLine(line) {
  const out = [];
  let field = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (inQuotes) {
      if (c === '"') {
        if (line[i + 1] === '"') { field += '"'; i++; }
        else inQuotes = false;
      } else {
        field += c;
      }
    } else if (c === '"') {
      inQuotes = true;
    } else if (c === ',') {
      out.push(field);
      field = '';
    } else {
      field += c;
    }
  }
  out.push(field);
  return out;
}

// Extract the host from a URL string without throwing on malformed input.
function hostFromUrl(u) {
  try {
    return new URL(u).hostname;
  } catch (e) {
    return '';
  }
}

module.exports = async function handler(req, res) {
  if (!guard(req, res)) return;

  try {
    const upstream = await fetchWithTimeout(URLHAUS_CSV, {
      headers: { 'User-Agent': 'passive-intel-console/1.0 (+defender tooling)' },
    });

    if (!upstream.ok) {
      return send(res, 502, { error: 'upstream_error', status: upstream.status });
    }

    const text = await upstream.text();

    // CSV columns (abuse.ch order):
    // id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
    const rows = [];
    for (const raw of text.split('\n')) {
      const line = raw.trim();
      if (!line || line.startsWith('#')) continue; // skip comment/header block
      const f = parseCsvLine(line);
      if (f.length < 7) continue;
      const url = f[2];
      if (!url || !/^https?:\/\//i.test(url)) continue; // skip a stray header row
      rows.push({
        url,
        host: hostFromUrl(url),
        dateAdded: f[1],
        threat: f[5],
        tags: f[6] ? f[6].split(',').map((t) => t.trim()).filter(Boolean) : [],
      });
    }

    // Newest first.
    rows.sort((a, b) => String(b.dateAdded).localeCompare(String(a.dateAdded)));

    return send(
      res,
      200,
      { source: 'urlhaus-online', count: rows.length, urls: rows },
      `public, s-maxage=${S_MAXAGE}, stale-while-revalidate=${SWR}`
    );
  } catch (err) {
    return send(res, 504, { error: 'fetch_failed', message: 'URLhaus feed unavailable' });
  }
};
