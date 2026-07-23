// ---------------------------------------------------------------- helpers

function escapeHtml(str) {
  const d = document.createElement('div');
  d.textContent = str || '';
  return d.innerHTML;
}
// escapeHtml (above) is safe for TEXT NODE content — e.g. ${escapeHtml(i.title)}
// as an element's inner text — because textContent->innerHTML round-tripping
// escapes &, <, > but deliberately leaves quote characters untouched (quotes
// have no special meaning inside text content). That makes it UNSAFE on its
// own for attribute-value contexts like href="${...}": a value containing a
// literal " can close the attribute early and inject new ones, e.g.
// `" onmouseover="alert(1)` becomes a live onmouseover handler on the tag.
// escapeAttr additionally escapes quotes for exactly that context.
function escapeAttr(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
// Every item.link in this app originates from external, only semi-trusted
// content — RSS/Atom feed XML (a compromised or malicious source can put
// anything in a <link> tag) or a restored database backup. Used directly as
// an href, a javascript: or data: URL there would execute on click even with
// perfect HTML-attribute escaping, since the injection isn't via HTML syntax
// at all — it's via the URL scheme itself. Only http(s) links are ever
// rendered as real hrefs; anything else (including a malformed/unparseable
// URL) safely falls back to a dead '#' link instead of silently doing
// nothing or, worse, executing.
function safeHref(url) {
  try {
    const parsed = new URL(url, window.location.href);
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      return escapeAttr(url);
    }
  } catch (e) { /* fall through */ }
  return '#';
}
function stripHtml(html) {
  const d = document.createElement('div');
  d.innerHTML = html || '';
  return d.textContent || '';
}
function timeAgo(ts) {
  const s = Math.floor(Date.now() / 1000 - ts);
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}

let sources = [];
const CATEGORY_COLORS = {
  general: '#5eead4', government: '#f87171', vulnerability: '#34d399',
  news: '#60a5fa', malware: '#e2586a', research: '#a78bfa'
};

// ------------------------------------------------------------------ router

const VIEWS = [
  'dashboard', 'live-feed', 'critical', 'vulnerabilities', 'malware',
  'ransomware', 'threat-actors', 'vendors', 'iocs', 'saved', 'sources', 'analytics', 'settings'
];
const VIEW_LOADERS = {
  'dashboard': loadDashboard,
  'live-feed': loadLiveFeed,
  'critical': () => loadSimpleFeed('feedCritical', { severity: 'high' }, 'No critical items right now.'),
  'vulnerabilities': () => loadMergedFeed('feedVulnerabilities',
    { category: 'vulnerability' }, { has_cve: true },
    'No vulnerability-tagged sources have posted, and no CVEs have been detected in any stored article yet.'),
  'malware': () => loadMergedFeed('feedMalware',
    { category: 'malware' }, { has_actor: true },
    'No malware-tagged sources have posted, and no threat actors have been detected in any stored article yet.'),
  'ransomware': () => loadSimpleFeed('feedRansomware', { keyword: 'ransomware' }, 'No ransomware-related items yet.'),
  'threat-actors': loadThreatActors,
  'vendors': loadVendors,
  'iocs': loadIOCsView,
  'saved': () => loadSimpleFeed('feedSaved', { bookmarked_only: true }, 'Nothing saved yet — click the star on any item to bookmark it.'),
  'sources': loadSourcesView,
  'analytics': loadAnalytics,
  'settings': loadSettingsView,
};

function navigateTo(view) {
  VIEWS.forEach(v => {
    document.getElementById('view-' + v).classList.toggle('active', v === view);
  });
  document.querySelectorAll('.nav-item').forEach(el => {
    el.classList.toggle('active', el.dataset.view === view);
  });
  location.hash = view;
  const loader = VIEW_LOADERS[view];
  if (loader) loader();
}

document.querySelectorAll('.nav-item').forEach(btn => {
  btn.onclick = () => navigateTo(btn.dataset.view);
});
document.querySelectorAll('[data-goto]').forEach(btn => {
  btn.onclick = () => navigateTo(btn.dataset.goto);
});

// -------------------------------------------------------------- dashboard

async function loadDashboard() {
  const stats = await (await fetch('/api/stats')).json();

  document.getElementById('dashStats').innerHTML = `
    <div class="stat-card"><div class="stat-label">Total articles</div><div class="stat-val">${stats.total_articles}</div></div>
    <div class="stat-card"><div class="stat-label">Critical alerts (24h)</div><div class="stat-val danger">${stats.critical_alerts}</div></div>
    <div class="stat-card"><div class="stat-label">New today</div><div class="stat-val ok">${stats.new_today}</div></div>
    <div class="stat-card"><div class="stat-label">Active sources</div><div class="stat-val">${stats.sources_active} <span style="font-size:14px;color:var(--text-faint);">/ ${stats.sources_total}</span></div></div>
  `;

  renderSparkline(document.getElementById('dashSparkline'), stats.articles_by_day);
  renderBarChart(document.getElementById('dashVendors'),
    stats.top_vendors.map(v => ({ label: v.name, count: v.count })));
  renderBarChart(document.getElementById('dashSeverity'),
    ['high', 'medium', 'low'].map(s => ({ label: s, count: stats.severity_distribution[s] || 0 })),
    { colorFn: (l) => SEVERITY_COLORS[l] || 'var(--signal)' });
  renderBarChart(document.getElementById('dashTopSources'),
    stats.top_sources.map(s => ({ label: s.name, count: s.count })));

  const latest = await fetchItems({ limit: 6 });
  renderFeedCards(document.getElementById('dashLatest'), latest, {
    emptyTitle: 'No intelligence yet', emptyHint: 'Add a source to start seeing signals here.',
    onBookmarkChange: loadDashboard,
  });
}

// -------------------------------------------------------------- live feed

let liveSearchTerm = '';
let liveSeverities = new Set(['high', 'medium', 'low']);
let liveDateFrom = '';
let liveDateTo = '';
let liveCurrentPage = 1;
const LIVE_PAGE_SIZE = 50;
let liveSearchDebounce = null;

function liveFilterParams() {
  const params = {};
  if (liveSeverities.size < 3) params.severity = [...liveSeverities].join(',');
  if (liveSearchTerm) params.keyword = liveSearchTerm;
  if (liveDateFrom) params.date_from = liveDateFrom;
  if (liveDateTo) params.date_to = liveDateTo;
  return params;
}

async function loadLiveFeed(page = liveCurrentPage) {
  liveCurrentPage = page;
  const filterParams = liveFilterParams();
  const offset = (page - 1) * LIVE_PAGE_SIZE;

  const [items, countResult] = await Promise.all([
    fetchItems({ ...filterParams, limit: LIVE_PAGE_SIZE, offset }),
    fetch('/api/items/count?' + new URLSearchParams(filterParams)).then(r => r.json()),
  ]);

  renderFeedCards(document.getElementById('liveFeed'), items, {
    emptyTitle: sources.length === 0 ? 'No sources configured' : 'No signals match current filters',
    emptyHint: sources.length === 0 ? 'Add a threat intel RSS feed to start seeing signals here.' : 'Adjust filters or the date range, or wait for the next poll cycle.',
    onBookmarkChange: () => loadLiveFeed(liveCurrentPage),
  });

  const totalPages = Math.max(1, Math.ceil(countResult.total / LIVE_PAGE_SIZE));
  renderPagination(document.getElementById('liveFeedPagination'), liveCurrentPage, totalPages, (p) => loadLiveFeed(p));

  await loadDateRangeHint();
}

async function loadDateRangeHint() {
  const range = await (await fetch('/api/items/range')).json();
  const hintEl = document.getElementById('dateRangeHint');
  const fromInput = document.getElementById('dateFrom');
  const toInput = document.getElementById('dateTo');
  if (range.earliest && range.latest) {
    const earliestStr = new Date(range.earliest * 1000).toISOString().slice(0, 10);
    const latestStr = new Date(range.latest * 1000).toISOString().slice(0, 10);
    fromInput.min = earliestStr; fromInput.max = latestStr;
    toInput.min = earliestStr; toInput.max = latestStr;
    hintEl.textContent = `${range.total} item(s) stored, ${earliestStr} — ${latestStr}`;
  } else {
    hintEl.textContent = 'No items stored yet';
  }
}

document.getElementById('searchInput').addEventListener('input', (e) => {
  liveSearchTerm = e.target.value;
  clearTimeout(liveSearchDebounce);
  liveSearchDebounce = setTimeout(() => loadLiveFeed(1), 350);
});
document.querySelectorAll('.sev-toggle').forEach(btn => {
  btn.onclick = () => {
    const sev = btn.dataset.sev;
    if (liveSeverities.has(sev)) { liveSeverities.delete(sev); btn.classList.remove('active'); }
    else { liveSeverities.add(sev); btn.classList.add('active'); }
    loadLiveFeed(1);
  };
});
document.getElementById('dateFrom').addEventListener('change', (e) => { liveDateFrom = e.target.value; loadLiveFeed(1); });
document.getElementById('dateTo').addEventListener('change', (e) => { liveDateTo = e.target.value; loadLiveFeed(1); });
document.getElementById('dateClearBtn').onclick = () => {
  liveDateFrom = ''; liveDateTo = '';
  document.getElementById('dateFrom').value = '';
  document.getElementById('dateTo').value = '';
  loadLiveFeed(1);
};

// ---------------------------------------------------- simple filtered feeds

async function loadSimpleFeed(containerId, params, emptyHint) {
  const items = await fetchItems({ limit: 100, ...params });
  renderFeedCards(document.getElementById(containerId), items, {
    emptyTitle: 'Nothing here yet', emptyHint, onBookmarkChange: () => VIEW_LOADERS[currentView()]?.(),
  });
}

/**
 * Fetches two filter conditions separately and merges the results
 * (dedup by id, re-sorted newest-first) — an OR across two dimensions
 * the backend's query builder only ANDs within a single request. Used
 * for "Vulnerabilities": a source manually tagged as a vulnerability
 * feed is one signal, but an article actually containing an extracted
 * CVE is a more reliable one regardless of how its source was
 * categorized — this shows either.
 */
async function loadMergedFeed(containerId, paramsA, paramsB, emptyHint) {
  const [itemsA, itemsB] = await Promise.all([
    fetchItems({ limit: 100, ...paramsA }),
    fetchItems({ limit: 100, ...paramsB }),
  ]);
  const merged = new Map();
  for (const item of [...itemsA, ...itemsB]) merged.set(item.id, item);
  const combined = [...merged.values()].sort((a, b) => b.fetched_at - a.fetched_at);
  renderFeedCards(document.getElementById(containerId), combined, {
    emptyTitle: 'Nothing here yet', emptyHint, onBookmarkChange: () => VIEW_LOADERS[currentView()]?.(),
  });
}
function currentView() {
  return VIEWS.find(v => document.getElementById('view-' + v).classList.contains('active'));
}

// -------------------------------------------------------------- vendors / actors

async function loadVendors() {
  const tags = await (await fetch('/api/tags?type=vendor&limit=30')).json();
  const chipsEl = document.getElementById('vendorChips');
  if (tags.length === 0) {
    chipsEl.innerHTML = `<div style="font-size:11.5px;color:var(--text-faint);">No vendors detected in stored items yet.</div>`;
  } else {
    chipsEl.innerHTML = tags.map(t => `<span class="tag-chip" data-vendor="${escapeHtml(t.name)}">${escapeHtml(t.name)} <span class="count">${t.count}</span></span>`).join('');
    chipsEl.querySelectorAll('.tag-chip').forEach(chip => {
      chip.onclick = async () => {
        chipsEl.querySelectorAll('.tag-chip').forEach(c => c.classList.remove('active'));
        chip.classList.add('active');
        const items = await fetchItems({ limit: 100, vendor: chip.dataset.vendor });
        renderFeedCards(document.getElementById('feedVendors'), items, { onBookmarkChange: loadVendors });
      };
    });
    chipsEl.querySelector('.tag-chip').click();
  }
  if (tags.length === 0) document.getElementById('feedVendors').innerHTML = '';
}

async function loadThreatActors() {
  const tags = await (await fetch('/api/tags?type=actor&limit=30')).json();
  const chipsEl = document.getElementById('actorChips');
  if (tags.length === 0) {
    chipsEl.innerHTML = `<div style="font-size:11.5px;color:var(--text-faint);">No threat actors detected in stored items yet.</div>`;
  } else {
    chipsEl.innerHTML = tags.map(t => `<span class="tag-chip" data-actor="${escapeHtml(t.name)}">${escapeHtml(t.name)} <span class="count">${t.count}</span></span>`).join('');
    chipsEl.querySelectorAll('.tag-chip').forEach(chip => {
      chip.onclick = async () => {
        chipsEl.querySelectorAll('.tag-chip').forEach(c => c.classList.remove('active'));
        chip.classList.add('active');
        const items = await fetchItems({ limit: 100, actor: chip.dataset.actor });
        renderFeedCards(document.getElementById('feedActors'), items, { onBookmarkChange: loadThreatActors });
      };
    });
    chipsEl.querySelector('.tag-chip').click();
  }
  if (tags.length === 0) document.getElementById('feedActors').innerHTML = '';
}

// -------------------------------------------------------------- IOCs

const IOC_TYPE_LABELS = { cve: 'CVEs', ip: 'IP Addresses', hash: 'Hashes', email: 'Emails' };
const IOC_TYPE_COLORS = { cve: '#5eead4', ip: '#60a5fa', hash: '#a78bfa', email: '#34d399' };
let currentIocType = 'cve';
let iocCurrentPage = 1;
const IOC_PAGE_SIZE = 10;
// The count of the single most-mentioned IOC of the current type (i.e.
// page 1's top row). Bars are scaled against this fixed value on every
// page rather than each page's own max, so a page of low-count IOCs
// doesn't render as visually "maxed out" as if it were as significant
// as the most-mentioned IOC overall.
let iocMaxCount = 1;
// The currently open "Articles containing…" drilldown, if any ({ type, value }).
// Tracked at module level (same pattern as currentIocType/liveCurrentPage/etc.)
// so an auto-refresh of this view — a WebSocket new_items broadcast or the
// 30s poll in init() — can restore it instead of always closing it.
let iocDrilldown = null;
// The calendar's currently displayed month, and the currently selected
// day (if any, 'YYYY-MM-DD'). A selected day scopes the top chart, the
// type-distribution donut, and the article list to just that date —
// independent of iocDrilldown above, so clicking a specific IOC value
// after selecting a day shows that value's occurrences on that day only.
const _today = new Date();
let iocCalYear = _today.getFullYear();
let iocCalMonth = _today.getMonth() + 1;
let iocSelectedDate = null;

async function loadIOCsView(page = iocCurrentPage) {
  iocCurrentPage = page;
  document.querySelectorAll('.ioc-type-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.iocType === currentIocType);
  });
  const dateSuffix = iocSelectedDate ? ` on ${new Date(iocSelectedDate + 'T00:00:00').toLocaleDateString(undefined, { month: 'long', day: 'numeric', year: 'numeric' })}` : '';
  document.getElementById('iocChartTitle').textContent = `Top ${IOC_TYPE_LABELS[currentIocType]} mentioned${dateSuffix}`;
  document.getElementById('iocClearDateBtn').style.display = iocSelectedDate ? '' : 'none';

  const dateParams = iocSelectedDate ? `&date_from=${iocSelectedDate}&date_to=${iocSelectedDate}` : '';
  const offset = (iocCurrentPage - 1) * IOC_PAGE_SIZE;
  const [top, summary] = await Promise.all([
    fetch(`/api/iocs?type=${currentIocType}&limit=${IOC_PAGE_SIZE}&offset=${offset}${dateParams}`).then(r => r.json()),
    fetch(`/api/iocs/summary?${iocSelectedDate ? `date_from=${iocSelectedDate}&date_to=${iocSelectedDate}` : ''}`).then(r => r.json()),
  ]);

  if (iocCurrentPage === 1) iocMaxCount = top.length ? top[0].count : 1;

  renderBarChart(document.getElementById('iocTopChart'),
    top.map(t => ({ label: t.name, count: t.count })),
    { colorFn: () => IOC_TYPE_COLORS[currentIocType], onClick: (value) => showIocArticles(currentIocType, value), max: iocMaxCount });

  const totalPages = Math.max(1, Math.ceil((summary[currentIocType] || 0) / IOC_PAGE_SIZE));
  renderPagination(document.getElementById('iocTopChartPagination'), iocCurrentPage, totalPages, (p) => loadIOCsView(p));

  renderDonutChart(document.getElementById('iocDonutWrap'),
    Object.entries(IOC_TYPE_LABELS).map(([type, label]) => ({
      label, count: summary[type] || 0, color: IOC_TYPE_COLORS[type],
    })),
    { centerLabel: iocSelectedDate ? 'IOCs that day' : 'distinct IOCs' });

  await loadIocCalendar();

  // Restore an open drilldown across auto-refreshes rather than always
  // closing it — but only for the IOC type currently being viewed; switching
  // type (below) is a genuine context change and should close it.
  if (iocDrilldown && iocDrilldown.type === currentIocType) {
    await showIocArticles(iocDrilldown.type, iocDrilldown.value, { scrollIntoView: false });
  } else if (iocSelectedDate) {
    await showIocDateArticles(iocSelectedDate, { scrollIntoView: false });
  } else {
    iocDrilldown = null;
    document.getElementById('iocArticlesPanel').style.display = 'none';
  }
}

// Guards loadIocCalendar against out-of-order responses: if navigation
// fires two overlapping requests (e.g. someone double-clicks "next
// month", or a slow network reorders responses), only the response that
// matches the *current* token actually renders — an older, slower
// response arriving after a newer one is simply discarded rather than
// overwriting the screen with stale data.
let _iocCalendarRequestToken = 0;

async function loadIocCalendar() {
  const myToken = ++_iocCalendarRequestToken;
  const monthStr = String(iocCalMonth).padStart(2, '0');
  const daysInMonth = new Date(iocCalYear, iocCalMonth, 0).getDate();
  const from = `${iocCalYear}-${monthStr}-01`;
  const to = `${iocCalYear}-${monthStr}-${String(daysInMonth).padStart(2, '0')}`;

  const [rows, range] = await Promise.all([
    fetch(`/api/iocs/calendar?type=${currentIocType}&date_from=${from}&date_to=${to}`).then(r => r.json()),
    fetch('/api/items/range').then(r => r.json()),
  ]);

  if (myToken !== _iocCalendarRequestToken) return; // superseded by a newer request — discard

  const counts = {};
  rows.forEach(r => { counts[r.date] = r.count; });

  // Bounds navigation to years the database could plausibly have data
  // for, so "jump to year" can't wander off into meaningless empty years.
  // Always includes the current year even if there's no data yet (a
  // brand-new install with zero items shouldn't have a calendar that
  // can't even reach today), and always includes the latest item's year
  // even if that's in the future relative to "now" on this machine.
  const nowYear = new Date().getFullYear();
  const minYear = range.earliest ? Math.min(new Date(range.earliest * 1000).getFullYear(), nowYear) : nowYear;
  const maxYear = range.latest ? Math.max(new Date(range.latest * 1000).getFullYear(), nowYear) : nowYear;

  renderCalendarHeatmap(document.getElementById('iocCalendar'), {
    year: iocCalYear, month: iocCalMonth, counts,
    color: IOC_TYPE_COLORS[currentIocType],
    selected: iocSelectedDate,
    itemLabel: IOC_TYPE_LABELS[currentIocType].toLowerCase(),
    minYear, maxYear,
    onSelectDay: (dateStr) => {
      // Clicking the already-selected day again clears the filter, same
      // toggle pattern as re-clicking an active filter chip elsewhere in
      // the app.
      iocSelectedDate = iocSelectedDate === dateStr ? null : dateStr;
      iocDrilldown = null;
      iocCurrentPage = 1;
      loadIOCsView();
    },
    onNavigate: (year, month) => {
      // Re-validated here too, not just trusted from the widget — this
      // function is the actual boundary that builds an API query string
      // from year/month, so it's the one place that must never accept a
      // bad value regardless of what UI layer called it.
      year = parseInt(year, 10);
      month = parseInt(month, 10);
      if (!Number.isInteger(year) || !Number.isInteger(month)) return;
      iocCalYear = Math.min(maxYear, Math.max(minYear, year));
      iocCalMonth = Math.min(12, Math.max(1, month));
      loadIocCalendar();
    },
  });
}

document.querySelectorAll('.ioc-type-btn').forEach(btn => {
  btn.onclick = () => { currentIocType = btn.dataset.iocType; iocDrilldown = null; iocSelectedDate = null; iocCurrentPage = 1; loadIOCsView(); };
});

document.getElementById('iocClearDateBtn').onclick = () => {
  iocSelectedDate = null;
  iocDrilldown = null;
  iocCurrentPage = 1;
  loadIOCsView();
};

async function showIocArticles(iocType, value, { scrollIntoView = true } = {}) {
  iocDrilldown = { type: iocType, value };
  const dateFilter = iocSelectedDate ? { date_from: iocSelectedDate, date_to: iocSelectedDate } : {};
  const items = await fetchItems({ ioc_type: iocType, ioc_value: value, limit: 50, ...dateFilter });
  const dateSuffix = iocSelectedDate ? ` on ${iocSelectedDate}` : '';
  renderIocArticles(
    `Articles containing ${IOC_TYPE_LABELS[iocType].replace(/s$/, '')}: ${value}${dateSuffix} (${items.length} occurrence${items.length === 1 ? '' : 's'})`,
    items, scrollIntoView,
  );
}

async function showIocDateArticles(dateStr, { scrollIntoView = true } = {}) {
  iocDrilldown = null;
  const items = await fetchItems({ ioc_type: currentIocType, date_from: dateStr, date_to: dateStr, limit: 100 });
  const label = new Date(dateStr + 'T00:00:00').toLocaleDateString(undefined, { month: 'long', day: 'numeric', year: 'numeric' });
  renderIocArticles(
    `Articles with ${IOC_TYPE_LABELS[currentIocType]} on ${label} (${items.length})`,
    items, scrollIntoView,
  );
}

function renderIocArticles(title, items, scrollIntoView) {
  const panel = document.getElementById('iocArticlesPanel');
  const tbody = document.getElementById('iocArticlesBody');
  document.getElementById('iocArticlesTitle').textContent = title;

  tbody.innerHTML = items.length === 0
    ? `<tr><td colspan="4" style="text-align:center; color:var(--text-faint); padding:24px;">No articles found.</td></tr>`
    : items.map(i => `
        <tr>
          <td><span class="src-tag" style="background:${i.source_color}22; color:${i.source_color}">${escapeHtml(i.source_name)}</span></td>
          <td>${escapeHtml(i.title)}</td>
          <td style="color:var(--text-faint); white-space:nowrap;">${new Date(i.fetched_at * 1000).toLocaleString()}</td>
          <td style="text-align:right;"><a class="icon-btn" href="${safeHref(i.link)}" target="_blank" rel="noopener" title="Open original">&#8599;</a></td>
        </tr>
      `).join('');

  panel.style.display = '';
  if (scrollIntoView) panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// -------------------------------------------------------------- analytics

async function loadAnalytics() {
  const stats = await (await fetch('/api/stats')).json();
  renderSparkline(document.getElementById('anSparkline'), stats.articles_by_day);
  renderBarChart(document.getElementById('anSeverity'),
    ['high', 'medium', 'low'].map(s => ({ label: s, count: stats.severity_distribution[s] || 0 })),
    { colorFn: (l) => SEVERITY_COLORS[l] || 'var(--signal)' });
  renderBarChart(document.getElementById('anCategory'),
    Object.entries(stats.category_distribution).map(([k, v]) => ({ label: k, count: v })),
    { colorFn: (l) => CATEGORY_COLORS[l] || 'var(--signal)' });
  renderBarChart(document.getElementById('anTopSources'), stats.top_sources.map(s => ({ label: s.name, count: s.count })));
  renderBarChart(document.getElementById('anVendors'), stats.top_vendors.map(v => ({ label: v.name, count: v.count })));
}

// -------------------------------------------------------------- settings

async function loadSettingsView() {
  const settings = await (await fetch('/api/settings')).json();
  document.getElementById('retentionSelect').value = String(settings.retention_days);
  document.getElementById('deepExtractionToggle').classList.toggle('on', settings.deep_extraction);

  const range = await (await fetch('/api/items/range')).json();
  const label = document.getElementById('storedRangeLabel');
  if (range.earliest && range.latest) {
    const earliestStr = new Date(range.earliest * 1000).toLocaleDateString();
    const latestStr = new Date(range.latest * 1000).toLocaleDateString();
    label.textContent = `Currently stored: ${range.total} items, ${earliestStr} → ${latestStr}`;
  } else {
    label.textContent = 'Currently stored: nothing yet';
  }

  await loadWebhooksTable();
}

async function loadWebhooksTable() {
  const webhooks = await (await fetch('/api/webhooks')).json();
  const tbody = document.getElementById('webhooksTableBody');
  if (webhooks.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" style="text-align:center; color:var(--text-faint); padding:20px;">No webhooks configured.</td></tr>`;
    return;
  }
  tbody.innerHTML = webhooks.map(w => {
    const parts = [];
    if (w.keyword) parts.push(`keyword: ${w.keyword}`);
    if (w.source_id) {
      const src = sources.find(s => s.id === w.source_id);
      parts.push(`source: ${src ? src.name : 'unknown'}`);
    }
    if (w.min_severity) parts.push(`severity ≥ ${w.min_severity}`);
    const trigger = parts.length ? parts.join(', ') : 'any new item';
    const statusOk = w.last_status && w.last_status.startsWith('ok');
    return `
      <tr>
        <td>${w.protected ? '🔒 ' : ''}${escapeHtml(w.name)}${w.allow_insecure_tls ? ' <span title="TLS certificate verification disabled for this webhook" style="color:var(--text-faint); font-size:10.5px;">(insecure TLS)</span>' : ''}</td>
        <td style="color:var(--text-dim); font-size:11.5px;">${escapeHtml(trigger)}</td>
        <td>
          <span class="status-badge status-${w.last_status === 'pending' ? 'pending' : (statusOk ? 'ok' : 'error')}"></span>
          ${w.enabled ? '' : '(paused) '}${escapeHtml(w.last_status || 'pending')}
        </td>
        <td style="text-align:right; white-space:nowrap;">
          <button class="btn" data-action="test-webhook" data-id="${w.id}" style="padding:4px 10px; font-size:11px;">Test</button>
          <button class="icon-btn" data-action="edit-webhook" data-id="${w.id}" title="Edit">&#9998;</button>
          <button class="icon-btn toggle" data-action="toggle-webhook" data-id="${w.id}" data-enabled="${w.enabled}" title="${w.enabled ? 'Pause' : 'Resume'}">${w.enabled ? '⏸' : '▶'}</button>
          <button class="icon-btn" data-action="delete-webhook" data-id="${w.id}" title="Remove">✕</button>
        </td>
      </tr>`;
  }).join('');

  tbody.querySelectorAll('[data-action="test-webhook"]').forEach(btn => {
    btn.onclick = async () => {
      btn.textContent = 'Sending...';
      btn.disabled = true;
      try {
        const res = await fetch(`/api/webhooks/${btn.dataset.id}/test`, { method: 'POST' });
        const result = await res.json();
        alert(res.ok ? `Test delivered: ${result.status}` : `Delivery failed: ${result.detail}`);
      } catch (e) {
        alert('Request failed: ' + e.message);
      }
      btn.textContent = 'Test';
      btn.disabled = false;
      await loadWebhooksTable();
    };
  });
  tbody.querySelectorAll('[data-action="edit-webhook"]').forEach(btn => {
    btn.onclick = async () => {
      const webhook = webhooks.find(w => w.id === btn.dataset.id);
      if (!webhook) return;
      const unlock = await unlockProtectedWebhook(webhook);
      if (!unlock.ok) return;
      openWebhookModal({ ...webhook, url: unlock.url }, unlock.key);
    };
  });
  tbody.querySelectorAll('[data-action="toggle-webhook"]').forEach(btn => {
    btn.onclick = async () => {
      const webhook = webhooks.find(w => w.id === btn.dataset.id);
      if (!webhook) return;
      const unlock = await unlockProtectedWebhook(webhook);
      if (!unlock.ok) return;
      const body = { enabled: btn.dataset.enabled !== 'true' };
      if (unlock.key) body.key = unlock.key;
      await fetch(`/api/webhooks/${btn.dataset.id}`, {
        method: 'PATCH', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      await loadWebhooksTable();
    };
  });
  tbody.querySelectorAll('[data-action="delete-webhook"]').forEach(btn => {
    btn.onclick = async () => {
      // Deletion is intentionally never key-gated — for a protected webhook,
      // it's the documented fallback when the key is lost.
      if (confirm('Remove this webhook?')) {
        await fetch(`/api/webhooks/${btn.dataset.id}`, { method: 'DELETE' });
        await loadWebhooksTable();
      }
    };
  });
}

// Prompts for a protected webhook's key and verifies it via /reveal in one
// round trip (which also hands back the real URL) — reused by both "Edit"
// and the pause/resume toggle, since a protected webhook requires its key
// for any change, not only for viewing the URL. Unprotected webhooks skip
// the prompt entirely.
async function unlockProtectedWebhook(webhook) {
  if (!webhook.protected) return { ok: true, key: null, url: webhook.url };
  const key = prompt(`Enter the key for "${webhook.name}" to continue:`);
  if (key === null) return { ok: false };
  const res = await fetch(`/api/webhooks/${webhook.id}/reveal`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ key }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    alert('Failed: ' + (err.detail || 'Incorrect key'));
    return { ok: false };
  }
  const { url } = await res.json();
  return { ok: true, key, url };
}

document.getElementById('retentionSelect').addEventListener('change', async (e) => {
  await fetch('/api/settings', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ retention_days: e.target.value }),
  });
});

document.getElementById('deepExtractionToggle').onclick = async function () {
  const enabling = !this.classList.contains('on');
  this.classList.toggle('on', enabling);
  await fetch('/api/settings', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ deep_extraction: enabling ? '1' : '0' }),
  });
};

// -------------------------------------------------------------- sources view

async function loadSources() {
  const res = await fetch('/api/sources');
  sources = await res.json();
  document.getElementById('statSources').textContent = sources.filter(s => s.enabled).length;
}

async function loadSourcesView() {
  await loadSources();
  const tbody = document.getElementById('sourcesTableBody');
  if (sources.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--text-faint); padding:30px;">No sources yet. Click <b>+ Add Source</b> to get started.</td></tr>`;
    return;
  }
  tbody.innerHTML = sources.map(s => `
    <tr>
      <td class="name-cell">${sourceIconHtml(s.id, s.color)} <span>${escapeHtml(s.name)}</span></td>
      <td><span class="tag-chip" style="cursor:default; margin:0;">${escapeHtml(s.category)}</span></td>
      <td><span class="status-badge status-${s.last_status === 'ok' ? 'ok' : (s.last_status && s.last_status.startsWith('error') ? 'error' : 'pending')}"></span> ${escapeHtml(s.last_status || 'pending')}</td>
      <td>${s.interval_seconds}s</td>
      <td>${s.last_fetched ? timeAgo(s.last_fetched) : 'never'}</td>
      <td style="text-align:right;">
        <button class="icon-btn" data-id="${s.id}" data-action="edit" title="Edit">&#9998;</button>
        <button class="icon-btn toggle" data-id="${s.id}" data-action="toggle" title="${s.enabled ? 'Pause' : 'Resume'}">${s.enabled ? '&#9208;' : '&#9654;'}</button>
        <button class="icon-btn" data-id="${s.id}" data-action="delete" title="Remove">&#10005;</button>
      </td>
    </tr>
  `).join('');

  tbody.querySelectorAll('[data-action="edit"]').forEach(btn => {
    btn.onclick = () => {
      const src = sources.find(s => s.id === btn.dataset.id);
      if (src) openModal(src);
    };
  });
  tbody.querySelectorAll('[data-action="delete"]').forEach(btn => {
    btn.onclick = async () => {
      if (confirm('Remove this source and its cached items?')) {
        await fetch('/api/sources/' + btn.dataset.id, { method: 'DELETE' });
        await loadSourcesView();
      }
    };
  });
  tbody.querySelectorAll('[data-action="toggle"]').forEach(btn => {
    btn.onclick = async () => {
      const src = sources.find(s => s.id === btn.dataset.id);
      await fetch('/api/sources/' + btn.dataset.id, {
        method: 'PATCH', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !src.enabled }),
      });
      await loadSourcesView();
    };
  });
}

document.getElementById('exportSourcesBtn').onclick = downloadSourcesExport;
document.getElementById('settingsExportBtn').onclick = downloadSourcesExport;
async function downloadSourcesExport() {
  const data = await (await fetch('/api/sources/export')).json();
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'pantomath-sources.json';
  a.click();
}
document.getElementById('importSourcesBtn').onclick = () => document.getElementById('importSourcesFile').click();
document.getElementById('importSourcesFile').addEventListener('change', async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const text = await file.text();
  try {
    const payload = JSON.parse(text);
    const res = await fetch('/api/sources/import', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload)
    });
    const result = await res.json();
    alert(`Imported ${result.added} source(s), skipped ${result.skipped} (duplicates).`);
    await loadSourcesView();
  } catch (err) {
    alert('Could not import: invalid JSON file.');
  }
  e.target.value = '';
});

document.getElementById('refreshAllBtn').onclick = async () => {
  const btn = document.getElementById('refreshAllBtn');
  btn.disabled = true;
  const original = btn.textContent;
  btn.textContent = 'Refreshing...';
  try {
    const res = await fetch('/api/sources/poll-all', { method: 'POST' });
    const result = await res.json();
    await loadSourcesView();
    if (res.ok) {
      alert(`Refreshed ${result.sources_polled} source(s). New items (if any) will appear shortly.`);
    } else {
      alert('Refresh failed: ' + (result.detail || 'unknown error'));
    }
  } catch (e) {
    alert('Request failed: ' + e.message);
  }
  btn.disabled = false;
  btn.textContent = original;
};

document.getElementById('backupBtn').onclick = () => { window.location.href = '/api/backup'; };

document.getElementById('restoreBtn').onclick = () => { document.getElementById('restoreFileInput').click(); };

document.getElementById('restoreFileInput').onchange = async (e) => {
  const file = e.target.files[0];
  e.target.value = ''; // reset so picking the exact same file again still fires 'change'
  if (!file) return;

  const resultEl = document.getElementById('restoreResult');
  // This is one of the few genuinely destructive actions in the app —
  // the confirmation names the actual file so a misclick on the wrong
  // backup is caught before anything happens, not after.
  if (!confirm(
    `Restore the database from "${file.name}"?\n\nThis REPLACES all current items, sources, settings, and webhooks. ` +
    `A safety copy of what's currently live will be made automatically first, but this still isn't reversible from ` +
    `inside the app — you'd need that safety-backup file to undo it.`
  )) {
    return;
  }

  resultEl.textContent = 'Uploading and validating…';
  resultEl.style.color = 'var(--text-faint)';

  try {
    const formData = new FormData();
    formData.append('file', file);
    const res = await fetch('/api/restore', { method: 'POST', body: formData });
    const body = await res.json();
    if (!res.ok) {
      resultEl.textContent = `Restore failed: ${body.detail || 'unknown error'}`;
      resultEl.style.color = 'var(--red)';
      return;
    }
    resultEl.textContent = `Restored successfully. Previous data was saved to: ${body.safety_backup || '(no prior database existed)'}. Reloading…`;
    resultEl.style.color = 'var(--signal)';
    setTimeout(() => window.location.reload(), 2500);
  } catch (err) {
    resultEl.textContent = `Restore failed: ${err.message}`;
    resultEl.style.color = 'var(--red)';
  }
};

document.getElementById('reprocessBtn').onclick = async () => {
  const btn = document.getElementById('reprocessBtn');
  const resultEl = document.getElementById('reprocessResult');
  if (!confirm('Re-run severity/vendor/threat-actor/IOC detection against every stored item? This can take a while and does not re-fetch RSS feeds.')) return;
  btn.disabled = true;
  btn.textContent = 'Reprocessing...';
  resultEl.textContent = 'Working — this can take a few minutes with deep extraction on a large history.';
  try {
    const res = await fetch('/api/reprocess', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}),
    });
    const result = await res.json();
    if (res.ok) {
      resultEl.textContent = `Done — reprocessed ${result.processed} item(s) across ${result.sources} source(s).`;
      loadDashboard?.();
    } else {
      resultEl.textContent = `Failed: ${result.detail || 'unknown error'}`;
    }
  } catch (e) {
    resultEl.textContent = 'Request failed: ' + e.message;
  }
  btn.disabled = false;
  btn.textContent = 'Reprocess all';
};

// -------------------------------------------------------------- add/edit-source modal

const modal = document.getElementById('modalOverlay');
let editingSourceId = null;

function openModal(source) {
  editingSourceId = source ? source.id : null;
  document.getElementById('modalTitle').textContent = source ? 'Edit feed source' : 'Add feed source';
  document.getElementById('confirmAdd').textContent = source ? 'Save changes' : 'Add source';
  document.getElementById('srcName').value = source ? source.name : '';
  document.getElementById('srcUrl').value = source ? source.url : '';
  document.getElementById('srcCategory').value = source ? source.category : 'general';
  document.getElementById('srcIcon').value = (source && source.icon_url) ? source.icon_url : '';
  document.getElementById('srcInterval').value = source ? source.interval_seconds : (document.getElementById('defaultInterval').value || 300);
  modal.classList.add('open');
}
function closeModal() { modal.classList.remove('open'); editingSourceId = null; }
document.getElementById('addSourceBtnHeader').onclick = () => openModal(null);
document.getElementById('addSourceBtnSources').onclick = () => openModal(null);
document.getElementById('cancelAdd').onclick = closeModal;
modal.onclick = (e) => { if (e.target === modal) closeModal(); };

document.getElementById('confirmAdd').onclick = async () => {
  const name = document.getElementById('srcName').value.trim();
  const url = document.getElementById('srcUrl').value.trim();
  const category = document.getElementById('srcCategory').value;
  const iconUrlInput = document.getElementById('srcIcon').value.trim();
  const interval_seconds = parseInt(document.getElementById('srcInterval').value) || 300;
  if (!name || !url) { alert('Name and URL are required'); return; }
  const color = CATEGORY_COLORS[category] || '#5eead4';

  const isEditing = !!editingSourceId;
  const res = await fetch(isEditing ? `/api/sources/${editingSourceId}` : '/api/sources', {
    method: isEditing ? 'PATCH' : 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, url, category, color, icon_url: iconUrlInput || null, interval_seconds })
  });
  if (res.ok) {
    document.getElementById('srcName').value = '';
    document.getElementById('srcUrl').value = '';
    document.getElementById('srcIcon').value = '';
    closeModal();
    await loadSources();
    VIEW_LOADERS[currentView()]?.();
  } else {
    const err = await res.json();
    alert('Failed: ' + (err.detail || 'unknown error'));
  }
};
document.getElementById('srcInterval').addEventListener('focus', function () {
  const d = document.getElementById('defaultInterval');
  if (d && d.value) this.value = d.value;
}, { once: false });

// -------------------------------------------------------------- add/edit-webhook modal

const webhookModal = document.getElementById('webhookModalOverlay');
const whProtectCheckbox = document.getElementById('whProtect');
const whKeyField = document.getElementById('whKeyField');
const whKeyInput = document.getElementById('whKey');
let editingWebhookId = null;
// The key just verified (via unlockProtectedWebhook) for the webhook currently
// open in the modal, if any — reused to authorize the PATCH on Save so the
// person isn't asked to type it twice in one edit.
let editingWebhookKey = null;

whProtectCheckbox.onchange = () => {
  whKeyField.style.display = whProtectCheckbox.checked ? 'block' : 'none';
};

function openWebhookModal(webhook, verifiedKey = null) {
  editingWebhookId = webhook ? webhook.id : null;
  editingWebhookKey = verifiedKey;
  document.getElementById('webhookModalTitle').textContent = webhook ? 'Edit webhook' : 'Add webhook';
  document.getElementById('confirmAddWebhook').textContent = webhook ? 'Save changes' : 'Add webhook';

  const select = document.getElementById('whSource');
  select.innerHTML = '<option value="">Any source</option>' +
    sources.map(s => `<option value="${s.id}">${escapeHtml(s.name)}</option>`).join('');

  document.getElementById('whName').value = webhook ? webhook.name : '';
  document.getElementById('whUrl').value = webhook ? webhook.url : '';
  document.getElementById('whKeyword').value = webhook ? webhook.keyword : '';
  document.getElementById('whSource').value = webhook ? webhook.source_id : '';
  document.getElementById('whMinSeverity').value = webhook ? webhook.min_severity : '';
  document.getElementById('whInsecureTls').checked = webhook ? !!webhook.allow_insecure_tls : false;
  whProtectCheckbox.checked = webhook ? !!webhook.protected : false;
  whKeyInput.value = '';
  whKeyInput.placeholder = (webhook && webhook.protected) ? 'Leave blank to keep the current key' : 'Enter a key';
  whKeyField.style.display = whProtectCheckbox.checked ? 'block' : 'none';
  webhookModal.classList.add('open');
}
function closeWebhookModal() {
  webhookModal.classList.remove('open');
  editingWebhookId = null;
  editingWebhookKey = null;
}
document.getElementById('addWebhookBtn').onclick = () => openWebhookModal(null);
document.getElementById('cancelAddWebhook').onclick = closeWebhookModal;
webhookModal.onclick = (e) => { if (e.target === webhookModal) closeWebhookModal(); };

document.getElementById('confirmAddWebhook').onclick = async () => {
  const name = document.getElementById('whName').value.trim();
  const url = document.getElementById('whUrl').value.trim();
  const keyword = document.getElementById('whKeyword').value.trim();
  const source_id = document.getElementById('whSource').value;
  const min_severity = document.getElementById('whMinSeverity').value;
  const allow_insecure_tls = document.getElementById('whInsecureTls').checked;
  const wantsProtection = whProtectCheckbox.checked;
  const keyInput = whKeyInput.value;
  if (!name || !url) { alert('Name and webhook URL are required'); return; }

  const isEditing = !!editingWebhookId;
  const body = { name, url, keyword, source_id, min_severity, allow_insecure_tls };
  if (!isEditing) body.enabled = true;

  if (wantsProtection) {
    if (keyInput) {
      body[isEditing ? 'set_key' : 'key'] = keyInput;
    } else if (!isEditing) {
      alert('Enter a key to protect this webhook, or leave the checkbox unchecked.');
      return;
    }
    // else: editing an already-protected webhook, key left blank => keep the existing key
  } else if (isEditing) {
    body.remove_protection = true;
  }
  if (isEditing && editingWebhookKey) body.key = editingWebhookKey;

  const res = await fetch(isEditing ? `/api/webhooks/${editingWebhookId}` : '/api/webhooks', {
    method: isEditing ? 'PATCH' : 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (res.ok) {
    document.getElementById('whName').value = '';
    document.getElementById('whUrl').value = '';
    document.getElementById('whKeyword').value = '';
    document.getElementById('whSource').value = '';
    document.getElementById('whMinSeverity').value = '';
    document.getElementById('whInsecureTls').checked = false;
    whProtectCheckbox.checked = false;
    whKeyInput.value = '';
    whKeyField.style.display = 'none';
    closeWebhookModal();
    await loadWebhooksTable();
  } else {
    const err = await res.json();
    alert('Failed: ' + (err.detail || 'unknown error'));
  }
};

// -------------------------------------------------------------- websocket

function connectWs() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(proto + '//' + location.host + '/ws');
  ws.onopen = () => {
    document.getElementById('connLabel').textContent = 'Live';
    document.getElementById('connDot').style.background = 'var(--signal)';
  };
  ws.onclose = () => {
    document.getElementById('connLabel').textContent = 'Reconnecting';
    document.getElementById('connDot').style.background = 'var(--red)';
    setTimeout(connectWs, 2000);
  };
  ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    if (msg.type === 'new_items') {
      // Whatever view is open just re-fetches — simplest correct behavior,
      // and item volume is low enough that this stays fast.
      VIEW_LOADERS[currentView()]?.();
      loadSources();
      notifyForNewItems(msg.items);
    } else if (msg.type === 'sources_changed') {
      loadSources();
      if (currentView() === 'sources') loadSourcesView();
    }
  };
}

// -------------------------------------------------------------- boot

(async function init() {
  initThemeControls();
  await initNotificationControls();
  await loadSources();
  const initial = VIEWS.includes(location.hash.slice(1)) ? location.hash.slice(1) : 'dashboard';
  navigateTo(initial);
  connectWs();
  setInterval(() => { VIEW_LOADERS[currentView()]?.(); }, 30000);
})();
