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
const esc = (s) =>
  String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

const SEV_COLOR = {
  critical: 'var(--bad)',
  high: 'var(--high)',
  medium: 'var(--warn)',
  low: 'var(--good)',
};

function sevBadge(score, sev) {
  let label, color;
  if (typeof score === 'number') {
    if (score >= 9) [label, color] = ['critical ' + score.toFixed(1), SEV_COLOR.critical];
    else if (score >= 7) [label, color] = ['high ' + score.toFixed(1), SEV_COLOR.high];
    else if (score >= 4) [label, color] = ['medium ' + score.toFixed(1), SEV_COLOR.medium];
    else [label, color] = ['low ' + score.toFixed(1), SEV_COLOR.good];
  } else if (sev && SEV_COLOR[sev]) {
    [label, color] = [sev, SEV_COLOR[sev]];
  } else {
    [label, color] = ['unscored', 'var(--fg-dim)'];
  }
  return `<span class="sev" style="color:${color};border-color:${color}">${label}</span>`;
}

// ---- KEV feed ---------------------------------------------------------------
let kevData = SEED.slice();
let live = false;
const cvssCache = {};

function setStatus() {
  $('kev-status').innerHTML = live
    ? `<span class="muted">// ${kevData.length} entries · live cisa feed · newest first · click to expand</span>`
    : `<span class="muted">// ${kevData.length} entries · cached snapshot · live feed loads from /api/kev</span>`;
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
    list.innerHTML = '<div class="note" style="padding:8px 0">no matches</div>';
    return;
  }

  list.innerHTML = items
    .map(
      (v, i) => `<div class="kev-item" data-idx="${i}" tabindex="0" role="button" aria-expanded="false">
        <div class="kev-top">
          <span class="kev-cve">${esc(v.cveID)}</span>
          ${sevBadge(v.score, v.sev)}
          ${v.ransomware ? '<span class="ransom">ransomware</span>' : ''}
        </div>
        <div class="kev-meta">${esc(v.vendorProject)} · ${esc(v.product)} · added ${esc(v.dateAdded)}</div>
        <div class="kev-detail" id="d-${i}"></div>
      </div>`
    )
    .join('');

  list.querySelectorAll('.kev-item').forEach((el) => {
    const idx = Number(el.dataset.idx);
    const toggle = () => expandKev(el, items[idx]);
    el.addEventListener('click', toggle);
    el.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); }
    });
  });
}

async function expandKev(el, v) {
  const d = el.querySelector('.kev-detail');
  if (d.classList.contains('open')) {
    d.classList.remove('open');
    el.setAttribute('aria-expanded', 'false');
    return;
  }
  d.classList.add('open');
  el.setAttribute('aria-expanded', 'true');

  let base = `<div>${esc(v.desc || v.name || 'no description')}</div>`;
  if (v.dueDate) base += `<div class="lbl" style="margin-top:3px">due: ${esc(v.dueDate)}</div>`;

  // If the snapshot already carries a severity word, show it without hitting NVD.
  if (typeof v.score === 'number' || v.sev) {
    d.innerHTML = base;
    return;
  }

  d.innerHTML = base + '<div class="muted" style="margin-top:3px">fetching cvss…</div>';

  if (v.cveID in cvssCache) {
    showCvss(d, base, cvssCache[v.cveID]);
    return;
  }
  try {
    const r = await fetch(`/api/lookup?source=cvss&cve=${encodeURIComponent(v.cveID)}`);
    if (!r.ok) throw new Error(String(r.status));
    const j = await r.json();
    cvssCache[v.cveID] = j.score;
    showCvss(d, base, j.score);
  } catch (e) {
    d.innerHTML = base + '<div class="err" style="margin-top:3px">cvss unavailable</div>';
  }
}

function showCvss(d, base, score) {
  d.innerHTML =
    base + `<div style="margin-top:4px"><span class="lbl">cvss: </span>${sevBadge(score, null)}</div>`;
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
    status.innerHTML = '<span class="muted">// loading live feed from /api/urlhaus…</span>';
    list.innerHTML = '';
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

  status.innerHTML = `<span class="muted">// ${items.length} of ${urlhausData.length} online urls · newest first</span>`;

  const shown = items.slice(0, 80);
  if (!shown.length) {
    list.innerHTML = '<div class="note" style="padding:8px 0">no matches</div>';
    return;
  }

  list.innerHTML = shown
    .map(
      (u) => `<div class="feed-item">
        <div class="feed-top">
          <span class="feed-host">${esc(u.host || '—')}</span>
          ${u.threat ? `<span class="chip warn">${esc(u.threat)}</span>` : ''}
        </div>
        <div class="feed-url">${esc(u.url)}</div>
        <div class="feed-meta">added ${esc(u.dateAdded)}${
          u.tags && u.tags.length
            ? ' · ' + u.tags.slice(0, 8).map((t) => esc(t)).join(', ')
            : ''
        }</div>
      </div>`
    )
    .join('');
}

async function loadUrlhaus() {
  try {
    const r = await fetch('/api/urlhaus');
    if (!r.ok) throw new Error(String(r.status));
    const j = await r.json();
    urlhausData = Array.isArray(j.urls) ? j.urls : [];
    renderUrlhaus();
  } catch (e) {
    $('urlhaus-status').innerHTML = '<span class="err">// urlhaus feed unavailable</span>';
  }
}

// ---- Feodo C2 feed ----------------------------------------------------------
// Active botnet command-and-control IPs with malware family and country.
let feodoData = [];

function renderFeodo() {
  const status = $('feodo-status');
  const list = $('feodo-list');

  if (!feodoData.length) {
    status.innerHTML = '<span class="muted">// loading live feed from /api/feodo…</span>';
    list.innerHTML = '';
    return;
  }

  status.innerHTML = `<span class="muted">// ${feodoData.length} active c2 servers · newest first</span>`;

  list.innerHTML = feodoData
    .slice(0, 80)
    .map(
      (c) => `<div class="feed-item">
        <div class="feed-top">
          <span class="feed-host">${esc(c.ip)}${c.port != null ? ':' + esc(c.port) : ''}</span>
          ${c.malware ? `<span class="chip bad-chip">${esc(c.malware)}</span>` : ''}
          ${c.country ? `<span class="chip">${esc(c.country)}</span>` : ''}
        </div>
        <div class="feed-meta">first seen ${esc(c.firstSeen || '—')}${
          c.lastSeen ? ' · last online ' + esc(c.lastSeen) : ''
        }</div>
      </div>`
    )
    .join('');
}

async function loadFeodo() {
  try {
    const r = await fetch('/api/feodo');
    if (!r.ok) throw new Error(String(r.status));
    const j = await r.json();
    feodoData = Array.isArray(j.c2) ? j.c2 : [];
    renderFeodo();
  } catch (e) {
    $('feodo-status').innerHTML = '<span class="err">// feodo feed unavailable</span>';
  }
}

// ---- Quad9 quick check ------------------------------------------------------
function normHost(v) {
  v = v.trim();
  try { if (/^https?:\/\//i.test(v)) return new URL(v).hostname; } catch (e) {}
  return v.replace(/^\/+|\/+$/g, '').split('/')[0];
}

async function quad9Check() {
  const raw = $('q-input').value.trim();
  if (!raw) return;
  const host = normHost(raw);
  const out = $('q-out');
  const btn = $('q-btn');
  out.innerHTML = '<span class="muted">[ querying quad9… ]</span>';
  btn.disabled = true;

  try {
    const r = await fetch(`/api/lookup?source=quad9&host=${encodeURIComponent(host)}`);
    if (r.status === 400) {
      out.innerHTML = '<div class="err">invalid target — domain or ip only</div>';
    } else if (r.status === 429) {
      out.innerHTML = '<div class="warn">rate limited — slow down</div>';
    } else if (!r.ok) {
      out.innerHTML = '<div class="err">error: lookup failed</div>';
    } else {
      const j = await r.json();
      let html = '';
      if (j.blocked) {
        html += `<div><span class="lbl">verdict     </span><span class="bad">BLOCKED / nxdomain</span></div>`;
        html += `<div class="note">// quad9 refuses to resolve — on threat blocklist or nonexistent</div>`;
      } else if (Array.isArray(j.aRecords) && j.aRecords.length) {
        html += `<div><span class="lbl">verdict     </span><span class="good">resolves (not blocked)</span></div>`;
        html += `<div><span class="lbl">a records   </span><span>${esc(j.aRecords.join(', '))}</span></div>`;
      } else {
        html += `<div><span class="lbl">verdict     </span><span class="warn">no a record</span></div>`;
      }
      out.innerHTML = html;
    }
  } catch (e) {
    out.innerHTML = '<div class="err">error: quad9 unreachable</div>';
  }
  btn.disabled = false;
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

  $('q-btn').addEventListener('click', quad9Check);
  $('q-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') quad9Check(); });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
