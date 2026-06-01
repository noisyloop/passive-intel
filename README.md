# passive intel console

A read-only threat-intelligence console for defenders, responders, and researchers. Surfaces public, no-auth intel in one place: actively exploited vulnerabilities, live malware URLs, and active botnet C2 servers.

**Passive by design.** Nothing here scans, probes, or contacts a target. Every data source is cached public intelligence. If you want offensive tooling, this isn't it — and that's the point.

## What it does

- **CISA KEV panel** — the Known Exploited Vulnerabilities catalog, newest first, filterable by vendor / product / CVE, severity-colored, ransomware-use flagged. Click any entry to expand its description and pull a CVSS base score.
- **URLhaus online feed** — live malware URLs actively serving right now, newest first, filterable by host / threat / tag.
- **Feodo C2 feed** — active botnet command-and-control IPs with malware family and country.

## Data sources

All public, all no-auth, no registration:

| Source | Use |
|---|---|
| CISA KEV | actively exploited CVEs |
| URLhaus | live malware URLs (online feed) |
| Feodo Tracker | active botnet C2 IPs |
| Quad9 | DNS block status |
| NVD | CVSS base scores |

All upstream calls are made server-side. The browser only ever talks to this app.

## Local dev

```bash
npm i -g vercel
vercel dev
```

## Deploy

```bash
git init && git add . && git commit -m "passive intel console"
vercel
```

No environment variables required.

## Roadmap

- Cross-resolver consensus to separate blocked from nonexistent.
- More passive feeds: ThreatFox IOCs, abuse.ch SSL blocklist.
- Per-CVE EPSS scores alongside CVSS for exploit-likelihood context.
- Saved watchlists for vendors/products you care about.

## Disclaimer

For defensive research and education. Use against infrastructure you own or are authorized to investigate. Data is provided as-is from third-party feeds and may be incomplete or delayed.

## License

MIT — see [LICENSE](./LICENSE).
