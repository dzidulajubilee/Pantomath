// ---------------------------------------------------------------- helpers

function escapeHtml(str) {
  const d = document.createElement('div');
  d.textContent = str || '';
  return d.innerHTML;
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
  'ransomware', 'threat-actors', 'vendors', 'saved', 'sources', 'analytics', 'settings'
];
const VIEW_LOADERS = {
  'dashboard': loadDashboard,
  'live-feed': loadLiveFeed,
  'critical': () => loadSimpleFeed('feedCritical', { severity: 'high' }, 'No critical items right now.'),
  'vulnerabilities': () => loadSimpleFeed('feedVulnerabilities', { category: 'vulnerability' }, 'No vulnerability-tagged sources have posted yet.'),
  'malware': () => loadSimpleFeed('feedMalware', { category: 'malware' }, 'No malware-tagged sources have posted yet.'),
  'ransomware': () => loadSimpleFeed('feedRansomware', { keyword: 'ransomware' }, 'No ransomware-related items yet.'),
  'threat-actors': loadThreatActors,
  'vendors': loadVendors,
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
let liveOffset = 0;
let liveHasMore = true;
const LIVE_PAGE_SIZE = 100;

async function loadLiveFeed(reset = true) {
  if (reset) {
    liveOffset = 0;
    liveHasMore = true;
    window._liveItems = [];
  }
  const params = { limit: LIVE_PAGE_SIZE, offset: liveOffset };
  if (liveDateFrom) params.date_from = liveDateFrom;
  if (liveDateTo) params.date_to = liveDateTo;

  const batch = await fetchItems(params);
  window._liveItems = reset ? batch : [...window._liveItems, ...batch];
  liveHasMore = batch.length === LIVE_PAGE_SIZE;
  liveOffset += batch.length;

  renderLiveFeed(window._liveItems);
  document.getElementById('loadMoreBtn').style.display = liveHasMore ? '' : 'none';
  document.getElementById('feedEndHint').style.display = (!liveHasMore && window._liveItems.length > 0) ? '' : 'none';

  if (reset) await loadDateRangeHint();
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

function renderLiveFeed(items) {
  let filtered = items.filter(i => liveSeverities.has(i.severity));
  if (liveSearchTerm) {
    filtered = filtered.filter(i => (i.title + ' ' + i.summary).toLowerCase().includes(liveSearchTerm.toLowerCase()));
  }
  renderFeedCards(document.getElementById('liveFeed'), filtered, {
    emptyTitle: sources.length === 0 ? 'No sources configured' : 'No signals match current filters',
    emptyHint: sources.length === 0 ? 'Add a threat intel RSS feed to start seeing signals here.' : 'Adjust filters or the date range, or wait for the next poll cycle.',
    onBookmarkChange: () => {},
  });
}
document.getElementById('searchInput').addEventListener('input', (e) => {
  liveSearchTerm = e.target.value;
  if (window._liveItems) renderLiveFeed(window._liveItems);
});
document.querySelectorAll('.sev-toggle').forEach(btn => {
  btn.onclick = () => {
    const sev = btn.dataset.sev;
    if (liveSeverities.has(sev)) { liveSeverities.delete(sev); btn.classList.remove('active'); }
    else { liveSeverities.add(sev); btn.classList.add('active'); }
    if (window._liveItems) renderLiveFeed(window._liveItems);
  };
});
document.getElementById('dateFrom').addEventListener('change', (e) => { liveDateFrom = e.target.value; loadLiveFeed(true); });
document.getElementById('dateTo').addEventListener('change', (e) => { liveDateTo = e.target.value; loadLiveFeed(true); });
document.getElementById('dateClearBtn').onclick = () => {
  liveDateFrom = ''; liveDateTo = '';
  document.getElementById('dateFrom').value = '';
  document.getElementById('dateTo').value = '';
  loadLiveFeed(true);
};
document.getElementById('loadMoreBtn').onclick = () => loadLiveFeed(false);

// ---------------------------------------------------- simple filtered feeds

async function loadSimpleFeed(containerId, params, emptyHint) {
  const items = await fetchItems({ limit: 100, ...params });
  renderFeedCards(document.getElementById(containerId), items, {
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

  const range = await (await fetch('/api/items/range')).json();
  const label = document.getElementById('storedRangeLabel');
  if (range.earliest && range.latest) {
    const earliestStr = new Date(range.earliest * 1000).toLocaleDateString();
    const latestStr = new Date(range.latest * 1000).toLocaleDateString();
    label.textContent = `Currently stored: ${range.total} items, ${earliestStr} → ${latestStr}`;
  } else {
    label.textContent = 'Currently stored: nothing yet';
  }
}

document.getElementById('retentionSelect').addEventListener('change', async (e) => {
  await fetch('/api/settings', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ retention_days: e.target.value }),
  });
});

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
        <button class="icon-btn toggle" data-id="${s.id}" data-action="toggle" title="${s.enabled ? 'Pause' : 'Resume'}">${s.enabled ? '&#9208;' : '&#9654;'}</button>
        <button class="icon-btn" data-id="${s.id}" data-action="delete" title="Remove">&#10005;</button>
      </td>
    </tr>
  `).join('');

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
      await fetch('/api/sources/' + btn.dataset.id + '?enabled=' + (!src.enabled), { method: 'PATCH' });
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

document.getElementById('backupBtn').onclick = () => { window.location.href = '/api/backup'; };

// -------------------------------------------------------------- add-source modal

const modal = document.getElementById('modalOverlay');
function openModal() { modal.classList.add('open'); }
function closeModal() { modal.classList.remove('open'); }
document.getElementById('addSourceBtnHeader').onclick = openModal;
document.getElementById('addSourceBtnSources').onclick = openModal;
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
  const res = await fetch('/api/sources', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
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
