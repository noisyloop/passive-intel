# passive intel console

A read-only threat-intelligence console for defenders, responders, and
researchers. It surfaces public, no-auth intel in one place: actively exploited
vulnerabilities and passive reputation lookups for domains/IPs.

**Passive by design.** Nothing here scans, probes, or contacts a target. Every
data source is cached public intelligence queried server-side or via a DNS
resolver. If you want offensive tooling, this isn't it — and that's the point.

## What it does

- **CISA KEV panel** — the Known Exploited Vulnerabilities catalog, newest
  first, filterable by vendor / product / CVE, severity-colored, ransomware-use
  flagged. Click any entry to expand its description and pull a CVSS base score.
- **URLhaus online feed** — live malware URLs actively serving right now, newest
  first, filterable by host / threat / tag. Loads on page open.
- **Feodo C2 feed** — active botnet command-and-control IPs with malware family
  and country. Loads on page open.

## Data sources

All public, all no-auth, no registration:

| Source        | Use                              | CORS | How it's called        |
|---------------|----------------------------------|------|------------------------|
| CISA KEV      | actively exploited CVEs          | yes  | proxied + edge-cached  |
| URLhaus       | live malware URLs (online feed)  | no   | server-side proxy      |
| Feodo Tracker | active botnet C2 IPs             | no   | server-side proxy      |
| Quad9         | DNS block status                 | yes  | server-side proxy      |
| NVD           | CVSS base scores                 | no   | server-side proxy      |

Everything is relayed server-side. URLhaus, Feodo, and NVD send no CORS headers;
Quad9 and CISA KEV are CORS-friendly but are still proxied so the payload can be
slimmed and cached — and so the browser CSP can keep `connect-src` to `'self'`
only.

## Architecture

```
index.html ── static page (no inline JS/CSS, strict CSP)
style.css
app.js     ── feed render/filter, CVSS enrichment, quad9 quick check
api/
  kev.js     ── GET /api/kev             slimmed + edge-cached KEV feed
  urlhaus.js ── GET /api/urlhaus         parsed online malware-URL feed
  feodo.js   ── GET /api/feodo           slimmed active botnet C2 list
  lookup.js  ── GET /api/lookup?source=  quad9 | cvss
  _lib.js    ── validation, rate limiting, timeouts, response helpers
vercel.json ── security headers + CSP
```

No database. No auth. The only server code is two stateless relay functions.

## Security

- **No SSRF.** Upstream URLs are hardcoded. User input only ever becomes a
  *validated* query/body parameter to a known host — never a fetch target.
- **Strict input validation.** Hosts must match a domain/IPv4 allowlist (private
  ranges rejected); CVE IDs must match `CVE-\d{4}-\d{4,7}`. Anything else → 400.
- **Rate limiting.** In-memory token bucket, 30 req/min per IP on `/api/lookup`,
  returning `429` + `Retry-After`. Best-effort on serverless (per-instance,
  resets on cold start) — fine for a portfolio deploy. See *Hardening* to make
  it distributed.
- **No DOM XSS from feed data.** The feeds display attacker-influenced content
  (malware URLs, tags, threat names, C2 IPs). The client never builds markup
  from it — every dynamic value is written via `textContent`/DOM APIs, so it's
  always inert text and can't be parsed as HTML. Malware URLs are shown as plain
  text, never as clickable `<a href>` links. With the strict CSP below, that's
  two independent layers against script injection.
- **Same-origin only.** No `Access-Control-Allow-Origin` is set, so the API
  can't be reused as an open CORS proxy by anyone else.
- **Strict CSP.** `default-src 'none'`; scripts/styles are `'self'` only (no
  inline), `connect-src 'self'` only (every upstream is proxied server-side, so
  the browser never talks to a third-party origin). Plus HSTS, `nosniff`,
  `frame-ancestors 'none'`, no-referrer.
- **Upstream timeouts** so a slow feed can't hang a function.

## Bandwidth / freshness

The KEV feed is ~1 MB+. Instead of every visitor pulling it from CISA:

- `/api/kev` fetches it server-side, trims it to the fields the UI renders, and
  returns `s-maxage=21600, stale-while-revalidate=43200`.
- Vercel's edge CDN then serves a cached copy for **6 hours**, and serves stale
  for up to **12 more** while revalidating. CISA is hit at most a few times a
  day per region, no matter how much traffic the site gets.

Change the cadence in `api/kev.js` (`S_MAXAGE` / `SWR`, in seconds). Longer =
less origin bandwidth, slightly staler data.

## Local dev

```bash
npm i -g vercel
vercel dev          # serves static files + /api functions locally
```

## Deploy

```bash
git init && git add . && git commit -m "passive intel console"
# push to your GitHub remote, then:
vercel              # or import the repo at vercel.com
```

No environment variables required. It works on the free tier.

## Hardening (for production / higher traffic)

- **Distributed rate limiting** — swap the in-memory `buckets` map in
  `api/_lib.js` for Upstash Redis or Vercel KV. The `rateLimit()` call site
  stays the same.
- **NVD API key** — registering a free key lifts NVD's strict anonymous rate
  limit; add it as an env var and pass it as a header in `cvssLookup()`.
- **Abuse signals** — log `429`s and repeat offenders; add a simple deny-list.

## Roadmap

- Cross-resolver consensus (Quad9 vs an unfiltered resolver) to separate
  "blocked" from "nonexistent".
- More passive feeds: ThreatFox IOCs, abuse.ch SSL blocklist, DNS passive.
- Per-CVE EPSS scores alongside CVSS for exploit-likelihood context.
- Saved watchlists for vendors/products you care about.

## Disclaimer

For defensive research and education. Use against infrastructure you own or are
authorized to investigate. The maintainers are not liable for misuse. Data is
provided as-is from third-party feeds and may be incomplete or delayed.

## License

MIT — see [LICENSE](./LICENSE).
