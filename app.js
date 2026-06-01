'use strict';

// Cached snapshot used as a fallback so the page is never empty if the live
// feed is briefly unreachable. The live /api/kev call overrides this on load.
const SEED = [
  { cveID: 'CVE-2026-0257', vendorProject: 'Palo Alto Networks', product: 'PAN-OS', dateAdded: '2026-05-29', sev: 'critical', ransomware: false, desc: 'Authentication bypass in PAN-OS allowing an unauthorized VPN connection, bypassing security restrictions.' },
  { cveID: 'CVE-2026-8398', vendorProject: 'Disc Soft', product: 'Daemon Tools Lite', dateAdded: '2026-05-27', sev: null, ransomware: false, desc: 'Embedded malicious code shipped within the installer — a supply-chain compromise of the distributed binary.' },
  { cveID: 'CVE-2026-34926', vendorProject: 'Trend Micro', product: 'Apex One (On-Premise)', dateAdded: '2026-05-21', sev: 'high', ransomware: false, desc: 'Directory traversal in the on-premise console permitting access to files outside the intended path.' },
  { cveID: 'CVE-2025-34291', vendorProject: 'Langflow', product: 'Langflow', dateAdded: '2026-05-21', sev: 'high', ransomware: false, desc: 'Origin validation error in Langflow, an open-source LLM app builder — relevant to AI/ML supply-chain exposure.' },
  { cveID: 'CVE-2026-41091', vendorProject: 'Microsoft', product: 'Defender', dateAdded: '2026-05-20', sev: 'high', ransomware: false, desc: 'Elevation of privilege in Microsoft Defender. A local attacker can abuse Defender to reach SYSTEM-level control.' },
  { cveID: 'CVE-2026-45498', vendorProject: 'Microsoft', product: 'Defender', dateAdded: '2026-05-20', sev: 'medium', ransomware: false, desc: 'Denial of service in Microsoft Defender, added alongside the EoP flaw in the same batch.' },
  { cveID: 'CVE-2026-31431', vendorProject: 'Linux', product: 'Kernel', dateAdded: '2026-05-09', sev: 'high', ransomware: false, desc: 'Local privilege escalation (Copy Fail) — incorrect resource transfer between spheres lets an unprivileged user gain root. PoC widely available. Fixed in 6.18.22 / 6.19.12 / 7.0.' },
  { cveID: 'CVE-2026-20182', vendorProject: 'Cisco', product: 'Catalyst SD-WAN Controller', dateAdded: '2026-05-14', sev: 'critical', ransomware: false, desc: 'Authentication bypass in the Catalyst SD-WAN Controller; covered under Emergency Directive 26-03.' },
  { cveID: 'CVE-2024-57726', vendorProject: 'SimpleHelp', product: 'SimpleHelp', dateAdded: '2026-04-24', sev: 'critical', ransomware: false, desc: 'Missing authorization lets low-privileged technicians mint API keys with excess permissions, escalating to admin. Linked to DragonForce ransomware precursor activity.' },
  { cveID: 'CVE-2024-7399', vendorProject: 'Samsung', product: 'MagicINFO 9 Server', dateAdded: '2026-04-24', sev: 'high', ransomware: false, desc: 'Path traversal allowing arbitrary file write. Exploitation tied to Mirai botnet deployment.' },
  { cveID: 'CVE-2025-29635', vendorProject: 'D-Link', product: 'DIR-823X (EOL)', dateAdded: '2026-04-24', sev: 'high', ransomware: false, desc: 'Command injection on end-of-life DIR-823X routers via a crafted POST to /goform/set_prohibiting.' },
];

const $ = (id) => document.getElementById(id);

// ---- Safe DOM construction --------------------------------------------------
// Everything the feeds display (malware URLs, tags, threat names, IPs, country
// codes) is attacker-influenced data from third-party blocklists. We NEVER build
// markup from it. Every dynamic value goes in through `textContent`, so it is
// always treated as inert text and can't be parsed as HTML — no XSS surface,
// regardless of what a poisoned feed contains. The strict CSP (script-src 'self',
// no inline) is the second layer; this is the first.
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
}

// Replace a status line with a single classed span of plain text.
function setNote(node, className, text) {
  node.replaceChildren(el('span', className, text));
}

// Severity tiers. Colors live in style.css as `.sev-<tier>` classes (not inline)
// so the strict CSP `style-src 'self'` keeps blocking inline styles.
const SEV_TIERS = ['critical', 'high', 'medium', 'low'];

function tierFromScore(score) {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

// Returns a badge element, or null when there's no score and no recognized
// severity word (render nothing).
function sevBadge(score, sev) {
  let tier, label;
  if (typeof score === 'number') {
    tier = tierFromScore(score);
    label = tier + ' ' + score.toFixed(1);
  } else if (SEV_TIERS.includes(sev)) {
    tier = sev;
    label = sev;
  } else {
    return null;
  }
  return el('span', 'sev sev-' + tier, label);
}

// ---- KEV feed ---------------------------------------------------------------
let kevData = SEED.slice();
let live = false;
const cvssCache = {};

function setStatus() {
  setNote($('kev-status'), 'muted', live
    ? `// ${kevData.length} entries · live cisa feed · newest first · click to expand`
    : `// ${kevData.length} entries · cached snapshot · live feed loads from /api/kev`);
}

function renderKev() {
  const q = $('k-filter').value.trim().toLowerCase();
  let items = kevData;
  if (q) {
    items = kevData.filter(
      (v) =>
        (v.cveID || '').toLowerCase().includes(q) ||
        (v.vendorProject || '').toLowerCase().includes(q) ||
        (v.product || '').toLowerCase().includes(q)
    );
  }
  items = items.slice(0, 80);

  const list = $('kev-list');
  if (!items.length) {
    list.replaceChildren(el('div', 'note list-empty', 'no matches'));
    return;
  }

  const frag = document.createDocumentFragment();
  for (const v of items) {
    const item = el('div', 'kev-item');
    item.tabIndex = 0;
    item.setAttribute('role', 'button');
    item.setAttribute('aria-expanded', 'false');

    const top = el('div', 'kev-top');
    top.appendChild(el('span', 'kev-cve', v.cveID));
    const badge = sevBadge(v.score, v.sev);
    if (badge) top.appendChild(badge);
    if (v.ransomware) top.appendChild(el('span', 'ransom', 'ransomware'));
    item.appendChild(top);

    item.appendChild(
      el('div', 'kev-meta', `${v.vendorProject} · ${v.product} · added ${v.dateAdded}`)
    );

    const detail = el('div', 'kev-detail');
    item.appendChild(detail);

    const toggle = () => expandKev(item, v, detail);
    item.addEventListener('click', toggle);
    item.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); }
    });
    frag.appendChild(item);
  }
  list.replaceChildren(frag);
}

async function expandKev(item, v, d) {
  if (d.classList.contains('open')) {
    d.classList.remove('open');
    item.setAttribute('aria-expanded', 'false');
    return;
  }
  d.classList.add('open');
  item.setAttribute('aria-expanded', 'true');

  d.replaceChildren(el('div', null, v.desc || v.name || 'no description'));
  if (v.dueDate) d.appendChild(el('div', 'lbl kev-line', 'due: ' + v.dueDate));

  // If the snapshot already carries a severity word, show it without hitting NVD.
  if (typeof v.score === 'number' || v.sev) return;

  const slot = el('div', 'muted kev-line', 'fetching cvss…');
  d.appendChild(slot);

  if (v.cveID in cvssCache) {
    showCvss(slot, cvssCache[v.cveID]);
    return;
  }
  try {
    const r = await fetch(`/api/lookup?source=cvss&cve=${encodeURIComponent(v.cveID)}`);
    if (!r.ok) throw new Error(String(r.status));
    const j = await r.json();
    cvssCache[v.cveID] = j.score;
    // The fetch may resolve after the user collapsed the row; don't write
    // stale content into a closed detail panel.
    if (!d.classList.contains('open')) return;
    showCvss(slot, j.score);
  } catch (e) {
    slot.className = 'err kev-line';
    slot.textContent = 'cvss unavailable';
  }
}

function showCvss(slot, score) {
  const wrap = el('div', 'kev-line');
  wrap.appendChild(el('span', 'lbl', 'cvss: '));
  wrap.appendChild(
    typeof score === 'number' ? sevBadge(score, null) : el('span', 'muted', 'n/a')
  );
  slot.replaceWith(wrap);
}

async function loadKev() {
  try {
    const r = await fetch('/api/kev');
    if (!r.ok) return;
    const j = await r.json();
    if (Array.isArray(j.vulnerabilities) && j.vulnerabilities.length) {
      kevData = j.vulnerabilities; // already slimmed + sorted server-side
      live = true;
      setStatus();
      renderKev();
    }
  } catch (e) {
    // keep the seed snapshot
  }
}

// ---- URLhaus online feed ----------------------------------------------------
// Live malware URLs actively serving, newest first, filterable by host/threat/tag.
let urlhausData = [];

function renderUrlhaus() {
  const status = $('urlhaus-status');
  const list = $('urlhaus-list');

  if (!urlhausData.length) {
    setNote(status, 'muted', '// loading live feed from /api/urlhaus…');
    list.replaceChildren();
    return;
  }

  const q = $('u-filter').value.trim().toLowerCase();
  let items = urlhausData;
  if (q) {
    items = urlhausData.filter(
      (u) =>
        (u.host || '').toLowerCase().includes(q) ||
        (u.threat || '').toLowerCase().includes(q) ||
        (u.tags || []).some((t) => t.toLowerCase().includes(q))
    );
  }

  setNote(status, 'muted', `// ${items.length} of ${urlhausData.length} online urls · newest first`);

  const shown = items.slice(0, 80);
  if (!shown.length) {
    list.replaceChildren(el('div', 'note list-empty', 'no matches'));
    return;
  }

  const frag = document.createDocumentFragment();
  for (const u of shown) {
    const item = el('div', 'feed-item');

    const top = el('div', 'feed-top');
    top.appendChild(el('span', 'feed-host', u.host || '—'));
    if (u.threat) top.appendChild(el('span', 'chip warn', u.threat));
    item.appendChild(top);

    // The live malware URL is rendered as inert TEXT, never as a clickable
    // <a href> — there is deliberately no way to navigate to it from here.
    item.appendChild(el('div', 'feed-url', u.url));

    let meta = `added ${u.dateAdded}`;
    if (u.tags && u.tags.length) meta += ' · ' + u.tags.slice(0, 8).join(', ');
    item.appendChild(el('div', 'feed-meta', meta));

    frag.appendChild(item);
  }
  list.replaceChildren(frag);
}

async function loadUrlhaus() {
  try {
    const r = await fetch('/api/urlhaus');
    if (!r.ok) throw new Error(String(r.status));
    const j = await r.json();
    urlhausData = Array.isArray(j.urls) ? j.urls : [];
    renderUrlhaus();
  } catch (e) {
    setNote($('urlhaus-status'), 'err', '// urlhaus feed unavailable');
  }
}

// ---- Feodo C2 feed ----------------------------------------------------------
// Active botnet command-and-control IPs with malware family and country.
let feodoData = [];

function renderFeodo() {
  const status = $('feodo-status');
  const list = $('feodo-list');

  if (!feodoData.length) {
    setNote(status, 'muted', '// loading live feed from /api/feodo…');
    list.replaceChildren();
    return;
  }

  setNote(status, 'muted', `// ${feodoData.length} active c2 servers · newest first`);

  const frag = document.createDocumentFragment();
  for (const c of feodoData.slice(0, 80)) {
    const item = el('div', 'feed-item');

    const top = el('div', 'feed-top');
    top.appendChild(el('span', 'feed-host', c.ip + (c.port != null ? ':' + c.port : '')));
    if (c.malware) top.appendChild(el('span', 'chip bad-chip', c.malware));
    if (c.country) top.appendChild(el('span', 'chip', c.country));
    item.appendChild(top);

    let meta = `first seen ${c.firstSeen || '—'}`;
    if (c.lastSeen) meta += ' · last online ' + c.lastSeen;
    item.appendChild(el('div', 'feed-meta', meta));

    frag.appendChild(item);
  }
  list.replaceChildren(frag);
}

async function loadFeodo() {
  try {
    const r = await fetch('/api/feodo');
    if (!r.ok) throw new Error(String(r.status));
    const j = await r.json();
    feodoData = Array.isArray(j.c2) ? j.c2 : [];
    renderFeodo();
  } catch (e) {
    setNote($('feodo-status'), 'err', '// feodo feed unavailable');
  }
}

// ---- Wire up ----------------------------------------------------------------
function init() {
  setStatus();
  renderKev();
  loadKev();
  $('k-filter').addEventListener('input', renderKev);

  renderUrlhaus();
  loadUrlhaus();
  $('u-filter').addEventListener('input', renderUrlhaus);

  renderFeodo();
  loadFeodo();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
