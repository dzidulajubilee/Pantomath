// ---------------------------------------------------------------- helpers

// ---------------------------------------------------------------- helpers

// ------------------------------------------------------- settings auth

// Only Settings and Sources are password-gated (server-side, via
// pantomath/api/routes.py's protected_router) — the rest of the app
// (Dashboard, Live Feed, IOCs, etc.) is intentionally left open, since
// this is designed as an always-visible SOC/NOC display. See
// pantomath/auth/settings_auth.py for the full reasoning.
let settingsToken = sessionStorage.getItem('pantomath_settings_token') || null;
let _authUnlockedCallback = null;

function setSettingsToken(token) {
  settingsToken = token;
  if (token) sessionStorage.setItem('pantomath_settings_token', token);
  else sessionStorage.removeItem('pantomath_settings_token');
}

// Every fetch() call in the app is routed through this wrapper (it
// replaces the global function once, here, rather than editing each of
// the dozens of individual call sites across the app — safer, since a
// hand-edited call site is easy to miss and this project has already
// hit that exact mistake once, with the href-escaping fix). The header
// is harmless on unprotected routes — nothing there reads it — so
// sending it unconditionally is simpler and safer than trying to
// enumerate which URLs need it.
(function installSettingsAuthFetchWrapper() {
  const nativeFetch = window.fetch.bind(window);
  window.fetch = function (url, opts = {}) {
    if (settingsToken) {
      opts = { ...opts, headers: { ...(opts.headers || {}), 'X-Settings-Token': settingsToken } };
    }
    return nativeFetch(url, opts);
  };
})();

function _resetAuthGateForm() {
  ['authSetupPassword', 'authSetupPasswordConfirm', 'authLoginPassword', 'authRecoveryCode', 'authRecoveryNewPassword'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  ['authSetupError', 'authLoginError', 'authRecoveryError'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = '';
  });
}

// Shows the lock modal. `mode` is 'setup' (no password configured yet)
// or 'login' (returning visit). `onUnlocked` is called once
// authentication actually succeeds — the caller's view loader passes
// itself in, so e.g. loadSettingsView() re-runs automatically right
// after a successful login instead of the operator having to navigate
// away and back.
function showAuthGate(mode, onUnlocked) {
  _authUnlockedCallback = onUnlocked;
  _resetAuthGateForm();
  document.getElementById('authStateSetup').style.display = mode === 'setup' ? '' : 'none';
  document.getElementById('authStateLogin').style.display = mode === 'login' ? '' : 'none';
  document.getElementById('authStateRecovery').style.display = 'none';
  document.getElementById('authStateShowRecovery').style.display = 'none';
  document.getElementById('settingsAuthOverlay').classList.add('open');
}

function hideAuthGate() {
  document.getElementById('settingsAuthOverlay').classList.remove('open');
}

function showRecoveryCodeScreen(code) {
  ['authStateSetup', 'authStateLogin', 'authStateRecovery'].forEach(id => { document.getElementById(id).style.display = 'none'; });
  document.getElementById('authStateShowRecovery').style.display = '';
  document.getElementById('authRecoveryCodeDisplay').textContent = code;
  document.getElementById('settingsAuthOverlay').classList.add('open');
}

// Called at the top of loadSettingsView()/loadSourcesView(). Returns
// true if already unlocked (a stale/expired token is still handled —
// each loader checks the status of its own first protected fetch and
// falls back to showAuthGate('login', ...) if it comes back 401,
// exactly like an expired session should). Returns false if it just
// rendered the lock screen, in which case the caller should stop
// without trying to load real content yet.
async function ensureSettingsUnlocked(onUnlocked) {
  if (settingsToken) return true;
  if (document.getElementById('settingsAuthOverlay').classList.contains('open')) {
    // Already showing the lock screen — possibly mid-recovery-flow, or
    // the user is actively typing a password. A redundant/overlapping
    // call here (e.g. two loadSettingsView() calls in flight at once,
    // or the 30s periodic refresh firing while still locked) must not
    // reset the visible state back to the login screen and blow away
    // whatever progress the user has made. Still worth updating which
    // callback fires on eventual success, in case they navigated to a
    // different gated page while locked.
    _authUnlockedCallback = onUnlocked;
    return false;
  }
  const status = await (await fetch('/api/settings/auth/status')).json();
  showAuthGate(status.configured ? 'login' : 'setup', onUnlocked);
  return false;
}

document.getElementById('authSetupSubmit').onclick = async () => {
  const pw = document.getElementById('authSetupPassword').value;
  const pw2 = document.getElementById('authSetupPasswordConfirm').value;
  const errEl = document.getElementById('authSetupError');
  if (pw.length < 8) { errEl.textContent = 'Password must be at least 8 characters.'; return; }
  if (pw !== pw2) { errEl.textContent = 'Passwords do not match.'; return; }
  const res = await fetch('/api/settings/auth/setup', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: pw }),
  });
  const body = await res.json();
  if (!res.ok) { errEl.textContent = body.detail || 'Setup failed.'; return; }
  setSettingsToken(body.token);
  showRecoveryCodeScreen(body.recovery_code);
};

document.getElementById('authLoginSubmit').onclick = async () => {
  const pw = document.getElementById('authLoginPassword').value;
  const errEl = document.getElementById('authLoginError');
  const res = await fetch('/api/settings/auth/login', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: pw }),
  });
  const body = await res.json();
  if (!res.ok) { errEl.textContent = body.detail || 'Login failed.'; return; }
  setSettingsToken(body.token);
  hideAuthGate();
  _authUnlockedCallback?.();
};
document.getElementById('authLoginPassword').addEventListener('keydown', (e) => { if (e.key === 'Enter') document.getElementById('authLoginSubmit').click(); });

document.getElementById('authForgotLink').onclick = () => {
  document.getElementById('authStateLogin').style.display = 'none';
  document.getElementById('authStateRecovery').style.display = '';
};
document.getElementById('authRecoveryBack').onclick = () => {
  document.getElementById('authStateRecovery').style.display = 'none';
  document.getElementById('authStateLogin').style.display = '';
};

document.getElementById('authRecoverySubmit').onclick = async () => {
  const code = document.getElementById('authRecoveryCode').value;
  const newPw = document.getElementById('authRecoveryNewPassword').value;
  const errEl = document.getElementById('authRecoveryError');
  if (newPw.length < 8) { errEl.textContent = 'Password must be at least 8 characters.'; return; }
  const res = await fetch('/api/settings/auth/recover', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ recovery_code: code, new_password: newPw }),
  });
  const body = await res.json();
  if (!res.ok) { errEl.textContent = body.detail || 'Recovery failed.'; return; }
  setSettingsToken(body.token);
  showRecoveryCodeScreen(body.recovery_code);
};

document.getElementById('authRecoveryCodeContinue').onclick = () => {
  hideAuthGate();
  _authUnlockedCallback?.();
};

async function lockSettings() {
  await fetch('/api/settings/auth/logout', { method: 'POST' });
  setSettingsToken(null);
  if (currentView() === 'settings' || currentView() === 'sources') {
    VIEW_LOADERS[currentView()]();
  }
}
document.getElementById('lockSettingsBtn').onclick = lockSettings;
document.getElementById('lockSourcesBtn').onclick = lockSettings;

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
  'critical': () => loadFeedPage('critical'),
  'vulnerabilities': () => loadFeedPage('vulnerabilities'),
  'malware': () => loadFeedPage('malware'),
  'ransomware': () => loadFeedPage('ransomware'),
  'threat-actors': loadThreatActors,
  'vendors': loadVendors,
  'iocs': loadIOCsView,
  'saved': () => loadFeedPage('saved'),
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

const RANGE_WORDS = { 24: '24 hours', 168: '7 days', 720: '30 days', 2160: '90 days' };

async function loadDashboard() {
  let ov;
  try {
    ov = await fetchOverview();
  } catch (e) {
    renderConnStatus();
    document.getElementById('dashKpis').innerHTML =
      `<div class="dash-error">Couldn't load the dashboard (${escapeHtml(e.message)}). Pantomath will try again in 30 seconds.</div>`;
    return;
  }
  const range = RANGE_WORDS[ov.hours] || `${ov.hours} hours`;
  const generated = new Date(ov.generated_at * 1000);
  document.getElementById('dashSubtitle').textContent =
    `${generated.toLocaleDateString([], { weekday: 'long', day: 'numeric', month: 'long' })}, ` +
    `${fmtClock(ov.generated_at)}. Counts use each item's published date.`;
  document.getElementById('attentionSub').textContent = `High severity, published in the last ${range}`;

  const src = ov.sources, ind = ov.indicators_week;
  const count = (n, one, many) => `${n} ${n === 1 ? one : many}`;
  let sourcesNote = 'add one to get started', sourcesTone = '';
  if (src.failing) { sourcesNote = `${src.failing} failing, see why`; sourcesTone = 'bad'; }
  else if (src.pending) sourcesNote = `${src.pending} waiting for a first poll`;
  else if (src.paused) sourcesNote = `${src.paused} paused`;
  else if (src.total) sourcesNote = 'all working';

  const kpis = [
    { label: 'High severity', value: ov.high_in_window, note: `published in the last ${range}`,
      goto: 'critical', tone: ov.high_in_window ? 'high' : '' },
    { label: 'New since you last looked', value: ov.new_since, note: `since ${fmtClock(ov.since)}`, goto: 'live-feed' },
    { label: 'Indicators this week', value: ind.cve + ind.ip + ind.hash + ind.email,
      note: `${count(ind.cve, 'CVE', 'CVEs')}, ${count(ind.ip, 'IP', 'IPs')}, ${count(ind.hash, 'hash', 'hashes')}, ${count(ind.email, 'email', 'emails')}`,
      goto: 'iocs' },
    { label: 'Published this week', value: ov.published_week, note: `${ov.published_today} of them today`, goto: 'live-feed' },
    { label: 'Sources', value: src.total ? `${src.healthy} of ${src.total}` : '0', note: sourcesNote,
      noteTone: sourcesTone, goto: 'sources' },
  ];
  const kpiEl = document.getElementById('dashKpis');
  kpiEl.innerHTML = kpis.map(k => `
    <button type="button" class="kpi" data-goto="${k.goto}">
      <span class="kpi-label">${escapeHtml(k.label)}</span>
      <span class="kpi-value${k.tone ? ' tone-' + k.tone : ''}">${escapeHtml(String(k.value))}</span>
      <span class="kpi-note${k.noteTone ? ' tone-' + k.noteTone : ''}">${escapeHtml(k.note)}</span>
    </button>`).join('');
  kpiEl.querySelectorAll('[data-goto]').forEach(b => b.addEventListener('click', () => navigateTo(b.dataset.goto)));

  renderAttention(ov, range);
  renderSourceHealth(src);
  renderDayChart(ov.by_day);
}

function indicatorSummary(i) {
  const parts = [];
  if (i.cves.length > 1) parts.push(`+${i.cves.length - 1} more CVE${i.cves.length > 2 ? 's' : ''}`);
  if (i.ips.length) parts.push(`${i.ips.length} IP${i.ips.length > 1 ? 's' : ''}`);
  if (i.hashes.length) parts.push(`${i.hashes.length} hash${i.hashes.length > 1 ? 'es' : ''}`);
  if (i.emails.length) parts.push(`${i.emails.length} email${i.emails.length > 1 ? 's' : ''}`);
  return parts.join(', ');
}

function renderAttention(ov, range) {
  const el = document.getElementById('dashAttention');
  if (!ov.sources.total) {
    el.innerHTML = `<li class="card-empty"><strong>No sources yet</strong>Add an RSS or Atom feed and Pantomath starts collecting straight away.<br>
      <button type="button" class="btn btn-primary" id="dashAddFirst">+ Add your first source</button></li>`;
    document.getElementById('dashAddFirst').addEventListener('click', () => document.getElementById('addSourceBtnHeader').click());
    return;
  }
  if (!ov.attention.length) {
    el.innerHTML = `<li class="card-empty"><strong>Nothing high severity</strong>No high-severity items were published in the last ${escapeHtml(range)}.</li>`;
    return;
  }
  el.innerHTML = ov.attention.map(i => {
    const tag = i.actors[0] || i.vendors[0] || '';
    const extra = indicatorSummary(i);
    const ts = effectiveTs(i);
    return `
    <li class="attention-row">
      <span class="sev-pill sev-${escapeAttr(i.severity)}">${escapeHtml(i.severity)}</span>
      <div class="attention-main">
        <a class="attention-title" href="${safeHref(i.link)}" target="_blank" rel="noopener">${escapeHtml(i.title)}</a>
        <div class="attention-meta">
          <span>${escapeHtml(i.source_name)}</span>
          ${i.cves[0] ? `<span class="chip chip-ioc">${escapeHtml(i.cves[0])}</span>` : ''}
          ${tag ? `<span class="chip chip-tag">${escapeHtml(tag)}</span>` : ''}
          ${extra ? `<span>${escapeHtml(extra)}</span>` : ''}
        </div>
      </div>
      <time class="attention-time" datetime="${new Date(ts * 1000).toISOString()}" title="${escapeAttr(timeTitle(i))}">${escapeHtml(fmtClock(ts))}</time>
    </li>`;
  }).join('');
}

const HEALTH_LIST_LIMIT = 8;

function renderSourceHealth(src) {
  const sub = document.getElementById('healthSub');
  const el = document.getElementById('dashHealth');
  if (!src.total) { sub.textContent = 'No sources yet'; el.innerHTML = ''; return; }
  sub.textContent = `${src.healthy} of ${src.total} working`;
  const label = { healthy: 'Healthy', failing: 'Failing', pending: 'Waiting', paused: 'Paused' };
  const rows = src.list.slice(0, HEALTH_LIST_LIMIT).map(s => {
    let detail = 'Not being polled';
    if (s.state === 'failing') detail = s.error || 'The last poll failed';
    else if (s.state === 'healthy') detail = s.last_fetched ? `Last checked ${timeAgo(s.last_fetched)}` : '';
    else if (s.state === 'pending') detail = 'Waiting for its first poll';
    return `<li class="health-row state-${escapeAttr(s.state)}">
      <span class="health-dot" aria-hidden="true"></span>
      <span class="health-name">${escapeHtml(s.name)}</span>
      <span class="health-state">${label[s.state] || escapeHtml(s.state)}</span>
      <span class="health-detail">${escapeHtml(detail)}</span>
    </li>`;
  });
  const hidden = src.list.length - HEALTH_LIST_LIMIT;
  if (hidden > 0) rows.push(`<li class="health-more">${hidden} more on the Sources page</li>`);
  el.innerHTML = rows.join('');
}

function renderDayChart(days) {
  const el = document.getElementById('dashDays');
  const max = Math.max(1, ...days.map(d => d.high + d.medium + d.low));
  const px = n => Math.max(3, Math.round((n / max) * 96));
  const todayKey = days[days.length - 1].date;
  el.innerHTML = days.map(d => {
    const total = d.high + d.medium + d.low;
    const isToday = d.date === todayKey;
    const label = isToday ? 'Today' : new Date(d.date + 'T12:00:00').toLocaleDateString([], { weekday: 'short' });
    const summary = `${label}: ${total} published, ${d.high} high, ${d.medium} medium, ${d.low} low`;
    return `<div class="day-col" role="img" aria-label="${escapeAttr(summary)}">
      <span class="day-total">${total}</span>
      <div class="day-bars">
        ${d.high ? `<i class="bar-high" style="height:${px(d.high)}px"></i>` : ''}
        ${d.medium ? `<i class="bar-medium" style="height:${px(d.medium)}px"></i>` : ''}
        ${d.low ? `<i class="bar-low" style="height:${px(d.low)}px"></i>` : ''}
      </div>
      <span class="day-label${isToday ? ' today' : ''}">${escapeHtml(label)}</span>
    </div>`;
  }).join('');
}

// -------------------------------------------------------------- live feed

let liveSearchTerm = '';
let liveSeverities = new Set(['high', 'medium', 'low']);
let liveDateFrom = '';
let liveDateTo = '';
let liveCurrentPage = 1;
const LIVE_PAGE_SIZE = 50;
let liveSearchDebounce = null;
let liveSourceId = '';
let liveCategory = '';

function liveFilterParams() {
  const params = {};
  if (liveSeverities.size < 3) params.severity = [...liveSeverities].join(',');
  if (liveSearchTerm) params.keyword = liveSearchTerm;
  if (liveDateFrom) params.date_from = liveDateFrom;
  if (liveDateTo) params.date_to = liveDateTo;
  if (liveSourceId) params.source_id = liveSourceId;
  if (liveCategory) params.category = liveCategory;
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
  livePanel.items = items;
  liveTotal = countResult.total;
  renderFeedRows(livePanel);
  const selected = livePanel.items.find(i => i.id === livePanel.selectedId);
  if (selected) renderFeedDetail(livePanel, selected);

  const totalPages = Math.max(1, Math.ceil(countResult.total / LIVE_PAGE_SIZE));
  renderPagination(document.getElementById('liveFeedPagination'), liveCurrentPage, totalPages, (p) => loadLiveFeed(p));
  updateLiveSubtitle();
  populateLiveSourceFilter();
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

function currentView() {
  return VIEWS.find(v => document.getElementById('view-' + v).classList.contains('active'));
}

// -------------------------------------------------------------- vendors / actors

// The currently selected vendor/actor chip, if any — tracked at module
// level (same pattern as iocDrilldown/currentIocType/liveCurrentPage) so
// an auto-refresh of this view (a WebSocket `new_items` broadcast, or the
// 30s poll in init(), both of which call VIEW_LOADERS[currentView()]?.())
// can restore the user's selection instead of always re-selecting the
// first chip and silently discarding whatever they had filtered to.
let selectedVendor = null;
let selectedActor = null;

async function loadVendors() {
  const tags = await (await fetch('/api/tags?type=vendor&limit=60')).json();
  const chipsEl = document.getElementById('vendorChips');
  document.getElementById('vendorCount').textContent = tags.length ? `${tags.length} most mentioned` : '';
  if (tags.length === 0) {
    chipsEl.innerHTML = '<p class="muted">No vendors found in stored items yet.</p>';
    selectedVendor = null;
  } else {
    chipsEl.innerHTML = tags.map(t => `<button type="button" class="tag-chip" data-vendor="${escapeAttr(t.name)}" data-count="${t.count}" aria-pressed="false"><span>${escapeHtml(t.name)}</span><span class="count">${t.count}</span></button>`).join('');
    chipsEl.querySelectorAll('.tag-chip').forEach(chip => {
      chip.onclick = async () => {
        selectedVendor = chip.dataset.vendor;
        chipsEl.querySelectorAll('.tag-chip').forEach(c => { c.classList.remove('active'); c.setAttribute('aria-pressed', 'false'); });
        chip.classList.add('active');
        chip.setAttribute('aria-pressed', 'true');
        const items = await fetchItems({ limit: FEED_PAGE_LIMIT, vendor: chip.dataset.vendor });
        showTagItems('vendors', chip.dataset.vendor, Number(chip.dataset.count), items);
      };
    });
    // Restore the previously selected chip if it still exists in this
    // refreshed list; only fall back to the first chip if there was no
    // prior selection, or the previously selected vendor has disappeared.
    const toSelect = (selectedVendor && chipsEl.querySelector(`.tag-chip[data-vendor="${CSS.escape(selectedVendor)}"]`))
      || chipsEl.querySelector('.tag-chip');
    toSelect.click();
    document.getElementById('vendorFilter').dispatchEvent(new Event('input'));
  }
  if (tags.length === 0) showTagItems('vendors', null, 0, []);
}

async function loadThreatActors() {
  const tags = await (await fetch('/api/tags?type=actor&limit=60')).json();
  const chipsEl = document.getElementById('actorChips');
  document.getElementById('actorCount').textContent = tags.length ? `${tags.length} most mentioned` : '';
  if (tags.length === 0) {
    chipsEl.innerHTML = '<p class="muted">No threat actors found in stored items yet.</p>';
    selectedActor = null;
  } else {
    chipsEl.innerHTML = tags.map(t => `<button type="button" class="tag-chip" data-actor="${escapeAttr(t.name)}" data-count="${t.count}" aria-pressed="false"><span>${escapeHtml(t.name)}</span><span class="count">${t.count}</span></button>`).join('');
    chipsEl.querySelectorAll('.tag-chip').forEach(chip => {
      chip.onclick = async () => {
        selectedActor = chip.dataset.actor;
        chipsEl.querySelectorAll('.tag-chip').forEach(c => { c.classList.remove('active'); c.setAttribute('aria-pressed', 'false'); });
        chip.classList.add('active');
        chip.setAttribute('aria-pressed', 'true');
        const items = await fetchItems({ limit: FEED_PAGE_LIMIT, actor: chip.dataset.actor });
        showTagItems('threat-actors', chip.dataset.actor, Number(chip.dataset.count), items);
      };
    });
    // Same restore-over-reset behavior as loadVendors() above.
    const toSelect = (selectedActor && chipsEl.querySelector(`.tag-chip[data-actor="${CSS.escape(selectedActor)}"]`))
      || chipsEl.querySelector('.tag-chip');
    toSelect.click();
    document.getElementById('actorFilter').dispatchEvent(new Event('input'));
  }
  if (tags.length === 0) showTagItems('threat-actors', null, 0, []);
}

// -------------------------------------------------------------- IOCs

const IOC_TYPE_LABELS = { cve: 'CVEs', ip: 'IP addresses', hash: 'Hashes', email: 'Emails' };
const IOC_SINGULAR = { cve: 'CVE', ip: 'IP address', hash: 'hash', email: 'email' };
const IOC_TYPE_LOWER = { cve: 'CVEs', ip: 'IP addresses', hash: 'hashes', email: 'emails' };
const IOC_TYPE_COLORS = { cve: '#5eead4', ip: '#60a5fa', hash: '#a78bfa', email: '#34d399' };
let currentIocType = 'cve';
let iocCurrentPage = 1;
const IOC_PAGE_SIZE = 25;
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
  if (iocSelectionType !== currentIocType) {
    // A different indicator type: selection and text filter don't carry over.
    iocSelection.clear();
    iocSelectionType = currentIocType;
    iocFilterText = '';
    document.getElementById('iocFilter').value = '';
  }
  document.querySelectorAll('.ioc-type-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.iocType === currentIocType);
    btn.setAttribute('aria-pressed', String(btn.dataset.iocType === currentIocType));
  });
  const dateSuffix = iocSelectedDate ? ` on ${new Date(iocSelectedDate + 'T00:00:00').toLocaleDateString(undefined, { month: 'long', day: 'numeric', year: 'numeric' })}` : '';
  document.getElementById('iocChartTitle').textContent = `${IOC_TYPE_LABELS[currentIocType]}${dateSuffix}`;
  document.getElementById('iocClearDateBtn').style.display = iocSelectedDate ? '' : 'none';
  document.getElementById('iocCalSub').textContent = `Distinct ${IOC_TYPE_LOWER[currentIocType]} seen each day`;
  document.getElementById('iocFilter').placeholder = `Filter ${IOC_TYPE_LOWER[currentIocType]}`;

  const dateParams = iocSelectedDate ? `&date_from=${iocSelectedDate}&date_to=${iocSelectedDate}` : '';
  const filterParams = iocFilterText ? `&q=${encodeURIComponent(iocFilterText)}` : '';
  const pageSize = iocFilterText ? IOC_FILTER_LIMIT : IOC_PAGE_SIZE;
  const offset = iocFilterText ? 0 : (iocCurrentPage - 1) * IOC_PAGE_SIZE;
  const [top, summary] = await Promise.all([
    fetch(`/api/iocs?type=${currentIocType}&detail=1&limit=${pageSize}&offset=${offset}${dateParams}${filterParams}`).then(r => r.json()),
    fetch(`/api/iocs/summary?${iocSelectedDate ? `date_from=${iocSelectedDate}&date_to=${iocSelectedDate}` : ''}`).then(r => r.json()),
  ]);

  Object.keys(IOC_TYPE_LABELS).forEach(type => {
    const el = document.getElementById('iocCount-' + type);
    if (el) el.textContent = summary[type] || 0;
  });
  top.forEach(row => iocRowCache.set(row.name, row));
  renderIocTable(top);
  const total = summary[currentIocType] || 0;
  document.getElementById('iocTableSub').textContent = iocFilterText
    ? `${top.length}${top.length === IOC_FILTER_LIMIT ? '+' : ''} matching "${iocFilterText}"`
    : `${total} distinct${iocSelectedDate ? ' seen that day' : ''}, most mentioned first`;
  const totalPages = iocFilterText ? 1 : Math.max(1, Math.ceil(total / IOC_PAGE_SIZE));
  renderPagination(document.getElementById('iocTopChartPagination'), iocCurrentPage, totalPages, (p) => loadIOCsView(p));
  updateIocActionBar();

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
  const articles = {};
  rows.forEach(r => { counts[r.date] = r.count; articles[r.date] = r.articles; });

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
    titleFn: (date, n) => {
      const day = new Date(date + 'T00:00:00').toLocaleDateString(undefined, { weekday: 'short', day: 'numeric', month: 'short' });
      if (!n) return `${day}: no ${IOC_TYPE_LOWER[currentIocType]}`;
      const inArticles = articles[date] || 0;
      return `${day}: ${n} ${n === 1 ? IOC_SINGULAR[currentIocType] : IOC_TYPE_LOWER[currentIocType]} in ${inArticles} article${inArticles === 1 ? '' : 's'}`;
    },
    color: IOC_TYPE_COLORS[currentIocType],
    selected: iocSelectedDate,
    itemLabel: IOC_TYPE_LOWER[currentIocType],
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
  const dateSuffix = iocSelectedDate
    ? ` on ${new Date(iocSelectedDate + 'T00:00:00').toLocaleDateString(undefined, { month: 'long', day: 'numeric', year: 'numeric' })}` : '';
  renderIocArticles(
    `Articles mentioning ${iocType === 'cve' ? '' : IOC_SINGULAR[iocType] + ' '}${value}${dateSuffix} (${items.length})`,
    items, scrollIntoView, value,
  );
  document.querySelectorAll('#iocTopChart .ioc-row[data-value]').forEach(row => {
    row.classList.toggle('selected', iocType === currentIocType && row.dataset.value === value);
  });
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

function renderIocArticles(title, items, scrollIntoView, focusValue = null) {
  const panel = document.getElementById('iocArticlesPanel');
  const tbody = document.getElementById('iocArticlesBody');
  document.getElementById('iocArticlesTitle').textContent = title;

  tbody.innerHTML = items.length === 0
    ? `<tr><td colspan="4" style="text-align:center; color:var(--text-faint); padding:24px;">No articles found.</td></tr>`
    : items.map(i => `
        <tr>
          <td><span class="sev-pill sev-${escapeAttr(i.severity)}">${escapeHtml(i.severity)}</span></td>
          <td><a href="${safeHref(i.link)}" target="_blank" rel="noopener">${escapeHtml(i.title)}</a></td>
          <td style="color:var(--text-dim);">${escapeHtml(i.source_name)}</td>
          <td style="color:var(--text-dim); white-space:nowrap;" title="${escapeAttr(timeTitle(i))}">${escapeHtml(fmtClock(i.fetched_at))}</td>
        </tr>
      `).join('');

  // "Seen alongside": the other indicators and names that appear in the
  // same articles — the quickest pivot from one IOC to the campaign.
  const alongside = document.getElementById('iocAlongside');
  if (focusValue && items.length) {
    const counts = new Map();
    items.forEach(i => [...i.cves, ...i.ips, ...i.hashes, ...i.vendors, ...i.actors].forEach(v => {
      if (v !== focusValue) counts.set(v, (counts.get(v) || 0) + 1);
    }));
    const top = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([v]) => v);
    alongside.innerHTML = top.length
      ? 'Seen alongside: ' + top.map(v => `<span class="chip ${/^CVE-|^\d|^[a-f0-9]{32,}$/i.test(v) ? 'chip-ioc' : 'chip-tag'}">${escapeHtml(v.length > 24 ? v.slice(0, 22) + '…' : v)}</span>`).join(' ')
      : 'Not seen alongside any other indicator.';
  } else {
    alongside.textContent = '';
  }

  panel.style.display = '';
  if (scrollIntoView) panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// -------------------------------------------------------------- analytics

let anDays = 30;
const AN_PREVIOUS = { 7: 'the previous 7 days', 30: 'the previous 30 days', 90: 'the previous 90 days', 365: 'the previous 12 months' };
const DAY_NAMES = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

async function loadAnalytics() {
  const a = await (await fetch(`/api/analytics?days=${anDays}`)).json();
  const previous = AN_PREVIOUS[a.days] || `the previous ${a.days} days`;
  const t = a.totals, p = a.previous, ind = a.indicators;
  const startLabel = new Date(a.start * 1000).toLocaleDateString([], { day: 'numeric', month: 'short', year: 'numeric' });
  document.getElementById('anSubtitle').textContent = `${startLabel} to today, by published date.`;
  document.getElementById('anMixSub').textContent = `Compared with ${previous}`;

  const change = (cur, prev) => {
    if (!prev) return cur ? `none in ${previous}` : `same as ${previous}`;
    const pct = Math.round(((cur - prev) / prev) * 100);
    return pct === 0 ? `no change vs ${previous}` : `${pct > 0 ? '+' : '−'}${Math.abs(pct)}% vs ${previous}`;
  };
  const kpis = [
    { label: 'Items published', value: t.items, note: change(t.items, p.items) },
    { label: 'High severity', value: t.high, tone: t.high ? 'high' : '', note: `${t.items ? Math.round((t.high / t.items) * 100) : 0}% of items, ${change(t.high, p.high)}` },
    { label: 'Indicators found', value: ind.cve + ind.ip + ind.hash + ind.email, note: `${ind.cve} CVEs, ${ind.ip} IPs, ${ind.hash} hashes, ${ind.email} emails` },
    { label: 'Sources publishing', value: a.active_sources, note: 'with at least one item in this period' },
  ];
  document.getElementById('anKpis').innerHTML = kpis.map(k => `
    <div class="kpi static">
      <span class="kpi-label">${escapeHtml(k.label)}</span>
      <span class="kpi-value${k.tone ? ' tone-' + k.tone : ''}">${escapeHtml(String(k.value))}</span>
      <span class="kpi-note">${escapeHtml(k.note)}</span>
    </div>`).join('');

  renderVolumeChart(document.getElementById('anVolume'), a.by_day);
  renderSeverityMix(document.getElementById('anSeverity'), t, p, previous);
  renderTopSources(document.getElementById('anTopSources'), a.top_sources, t.items);
  renderHeatmap(document.getElementById('anHeatmap'), a.heatmap);
  renderRankList(document.getElementById('anVendors'), a.top_vendors, 'No vendors mentioned in this period.');
  renderRankList(document.getElementById('anActors'), a.top_actors, 'No threat actors mentioned in this period.');
  renderRankList(document.getElementById('anCategory'),
    a.by_category.map(c => ({ ...c, label: c.name.charAt(0).toUpperCase() + c.name.slice(1), color: CATEGORY_COLORS[c.name] })),
    'Nothing published in this period.');
  renderRankList(document.getElementById('anIndicators'),
    Object.keys(IOC_TYPE_LABELS).map(type => ({ name: type, label: IOC_TYPE_LABELS[type], count: ind[type], color: IOC_TYPE_COLORS[type] }))
      .filter(r => r.count), 'No indicators found in this period.');
}

// -------------------------------------------------------------- settings

async function loadSettingsView() {
  if (!(await ensureSettingsUnlocked(loadSettingsView))) return;

  const settingsRes = await fetch('/api/settings');
  if (settingsRes.status === 401) { setSettingsToken(null); showAuthGate('login', loadSettingsView); return; }
  const settings = await settingsRes.json();
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
  const res = await fetch('/api/webhooks');
  if (res.status === 401) {
    // Session expired while already on the Settings page (e.g. the
    // 1-hour session ran out, or another tab logged out). Falling back
    // to the lock screen here — rather than leaving the page half-
    // rendered with a broken webhooks section — matches how
    // loadSettingsView() itself already handles this for /api/settings.
    setSettingsToken(null);
    showAuthGate('login', loadSettingsView);
    return;
  }
  const webhooks = await res.json();
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
  const res = await fetch('/api/settings', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ retention_days: e.target.value }),
  });
  if (res.status === 401) { setSettingsToken(null); showAuthGate('login', loadSettingsView); }
});

document.getElementById('deepExtractionToggle').onclick = async function () {
  const enabling = !this.classList.contains('on');
  this.classList.toggle('on', enabling);
  const res = await fetch('/api/settings', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ deep_extraction: enabling ? '1' : '0' }),
  });
  if (res.status === 401) {
    this.classList.toggle('on', !enabling); // revert the optimistic UI change — it didn't actually save
    setSettingsToken(null);
    showAuthGate('login', loadSettingsView);
  }
};

// -------------------------------------------------------------- sources view

async function loadSources() {
  const res = await fetch('/api/sources');
  if (!res.ok) {
    // Expected whenever Settings/Sources is locked (including on every
    // fresh page load before authenticating) — must not throw here.
    // sources must stay a real array, since other code throughout the
    // app calls .filter()/.find() on it; leaving it as a parsed error
    // object ({detail: "..."}) would crash the FIRST such call, and
    // this function runs unconditionally during boot (see init()),
    // before the WebSocket connects — an uncaught exception here was
    // silently killing the rest of the boot sequence, including
    // connectWs(), which is why notifications appeared broken (they
    // fire from the WS message handler, which never got reached).
    sources = [];
    return;
  }
  sources = await res.json();
}

async function loadSourcesView() {
  if (!(await ensureSettingsUnlocked(loadSourcesView))) return;

  const sourcesRes = await fetch('/api/sources');
  if (sourcesRes.status === 401) { setSettingsToken(null); showAuthGate('login', loadSourcesView); return; }
  sources = await sourcesRes.json();

  const table = document.getElementById('sourcesTableBody');
  renderSourcesSummary(sources);
  if (sources.length === 0) {
    table.innerHTML = `<div class="card-empty"><strong>No sources yet</strong>Add an RSS or Atom feed to start collecting.<br>
      <button type="button" class="btn btn-primary" id="srcAddFirst">+ Add your first source</button></div>`;
    document.getElementById('srcAddFirst').onclick = () => openModal(null);
    return;
  }
  const order = { failing: 0, pending: 1, healthy: 2, paused: 3 };
  const rows = sources.map(s => ({ s, state: sourceState(s) }))
    .sort((a, b) => order[a.state] - order[b.state] || a.s.name.localeCompare(b.s.name));
  table.innerHTML = `<div class="src-row src-head" role="row">
      <span role="columnheader">Status</span><span role="columnheader">Source</span><span role="columnheader">Last success</span>
      <span role="columnheader" class="src-cell num">Today</span><span role="columnheader" class="src-cell num">Response</span>
      <span role="columnheader" style="text-align:right;">Actions</span>
    </div>` + rows.map(({ s, state }) => sourceRowHtml(s, state)).join('');

  table.querySelectorAll('[data-action="edit"]').forEach(btn => {
    btn.onclick = () => {
      const src = sources.find(s => s.id === btn.dataset.id);
      if (src) openModal(src);
    };
  });
  table.querySelectorAll('[data-action="delete"]').forEach(btn => {
    btn.onclick = async () => {
      const src = sources.find(s => s.id === btn.dataset.id);
      if (confirm(`Remove "${src ? src.name : 'this source'}" and its stored items?`)) {
        await fetch('/api/sources/' + btn.dataset.id, { method: 'DELETE' });
        await loadSourcesView();
      }
    };
  });
  table.querySelectorAll('[data-action="toggle"]').forEach(btn => {
    btn.onclick = async () => {
      const src = sources.find(s => s.id === btn.dataset.id);
      await fetch('/api/sources/' + btn.dataset.id, {
        method: 'PATCH', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !src.enabled }),
      });
      await loadSourcesView();
    };
  });
  table.querySelectorAll('[data-action="test"]').forEach(btn => {
    btn.onclick = async () => {
      const src = sources.find(s => s.id === btn.dataset.id);
      const out = document.getElementById('srcTest-' + src.id);
      out.hidden = false;
      out.className = 'src-test';
      out.textContent = 'Testing…';
      btn.disabled = true;
      const result = await testFeedUrl(src.url);
      btn.disabled = false;
      const d = describeFeedTest(result);
      out.className = 'src-test ' + (result.ok ? 'ok' : 'bad');
      out.textContent = `${d.title}. ${d.text}`;
    };
  });
}

document.getElementById('exportSourcesBtn').onclick = downloadSourcesExport;
document.getElementById('settingsExportBtn').onclick = downloadSourcesExport;
async function downloadSourcesExport() {
  const res = await fetch('/api/sources/export');
  if (res.status === 401) { setSettingsToken(null); showAuthGate('login', () => {}); return; }
  const data = await res.json();
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

document.getElementById('backupBtn').onclick = async () => {
  // A raw `window.location.href = url` navigation does NOT go through
  // the fetch() wrapper that attaches X-Settings-Token (it only
  // intercepts calls made via fetch(), not full page navigations) — so
  // this endpoint, being protected, would 401 even for a properly
  // logged-in user, and the browser would navigate away from the app
  // entirely to display the raw error JSON. Fetching as a blob and
  // triggering the download via an anchor element keeps everything
  // properly authenticated and keeps the user on the actual app page.
  const res = await fetch('/api/backup');
  if (res.status === 401) { setSettingsToken(null); showAuthGate('login', () => {}); return; }
  if (!res.ok) { alert('Backup download failed: ' + res.status); return; }
  const blob = await res.blob();
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'pantomath-backup.db';
  a.click();
  URL.revokeObjectURL(a.href);
};

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
    // Read as text first and parse manually — a raw fetch failure this app
    // doesn't control (e.g. a reverse proxy like nginx rejecting the
    // upload before it ever reaches the app, returning its own HTML error
    // page for a 413/502/etc.) is not JSON, and calling res.json()
    // directly throws an opaque "Unexpected token '<'..." SyntaxError that
    // buries the actual problem. Handle that case with an explicit,
    // legible message instead.
    const raw = await res.text();
    let body;
    try {
      body = JSON.parse(raw);
    } catch {
      const hint = res.status === 413
        ? ' — the upload was likely rejected by a reverse proxy (e.g. nginx) before reaching Pantomath. ' +
          'If you set up HTTPS via `pantomath-admin setup-https`, re-run it with -y to pick up the raised ' +
          'upload-size limit, then try again.'
        : '';
      resultEl.textContent = `Restore failed: server returned an unexpected non-JSON response (HTTP ${res.status})${hint}`;
      resultEl.style.color = 'var(--red)';
      return;
    }
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

// -------------------------------------------------------------- shell (0.5.0)

// "New since you last looked" = since this browser last left Pantomath.
// Read once at load, so the number stays stable while you're looking, and
// re-recorded whenever the tab is hidden or closed.
const LAST_SEEN_KEY = 'pantomath-last-seen';
const previousVisitEnded = (() => {
  try { return parseFloat(localStorage.getItem(LAST_SEEN_KEY)) || null; } catch (e) { return null; }
})();
function recordLastSeen() {
  try { localStorage.setItem(LAST_SEEN_KEY, String(Date.now() / 1000)); } catch (e) { /* storage disabled */ }
}
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'hidden') recordLastSeen(); });
window.addEventListener('pagehide', recordLastSeen);

let dashHours = 24;
let lastOverviewData = null;
let lastDataAt = 0;          // ms timestamp of the last successful /api/overview
let wsOpen = false;
let wsEverOpened = false;
// The page refreshes every 30 s. If nothing has arrived for 2 minutes the
// screen says so loudly — on an unattended wall display a frozen page
// otherwise looks exactly like a quiet day.
const STALE_AFTER_S = 120;

async function fetchOverview() {
  const params = new URLSearchParams({ hours: String(dashHours) });
  params.set('since', String(unreadSince()));
  const res = await fetch('/api/overview?' + params);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const ov = await res.json();
  lastOverviewData = ov;
  lastDataAt = Date.now();
  populateLiveSourceFilter();
  updateShellIndicators(ov);
  renderConnStatus();
  return ov;
}

function refreshShell() {
  fetchOverview().catch(() => renderConnStatus());
}

function setNavCount(id, n) {
  const el = document.getElementById(id);
  if (!el) return;
  el.hidden = !n;
  el.textContent = n > 99 ? '99+' : String(n);
}

function updateShellIndicators(ov) {
  const src = ov.sources;
  const pill = document.getElementById('healthPill');
  if (src.total === 0) {
    pill.hidden = false;
    pill.className = 'health-pill';
    pill.textContent = 'No sources yet';
    pill.removeAttribute('aria-label');
  } else if (src.failing > 0) {
    pill.hidden = false;
    pill.className = 'health-pill bad';
    pill.innerHTML = `<span>${src.failing}</span><span class="pill-text">source${src.failing === 1 ? '' : 's'} failing</span>`;
    pill.setAttribute('aria-label', `${src.failing} source${src.failing === 1 ? '' : 's'} failing, open Sources`);
  } else {
    pill.hidden = true;
  }
  setNavCount('navSourcesCount', src.failing);
  document.getElementById('navSourcesCount').dataset.kind = 'bad';
  setNavCount('navNewCount', ov.new_since);
}

function formatAge(seconds) {
  if (seconds < 60) return `${seconds} s`;
  const minutes = Math.round(seconds / 60);
  return minutes < 60 ? `${minutes} min` : `${Math.round(minutes / 60)} h`;
}

function renderConnStatus() {
  const ageS = lastDataAt ? Math.max(0, Math.round((Date.now() - lastDataAt) / 1000)) : null;
  let state = 'connecting';
  if (ageS !== null && ageS > STALE_AFTER_S) state = 'stale';
  else if (wsOpen) state = 'live';
  else if (wsEverOpened) state = 'reconnecting';
  const labels = { connecting: 'Connecting', live: 'Live', reconnecting: 'Reconnecting', stale: 'Not updating' };
  const status = document.getElementById('connStatus');
  if (status.dataset.state !== state) {
    status.dataset.state = state;
    document.getElementById('connLabel').textContent = labels[state];
  }
  document.getElementById('connAge').textContent = ageS === null ? '' : `updated ${formatAge(ageS)} ago`;
}
setInterval(renderConnStatus, 5000);

// Global search: an exact CVE, IP, hash or email opens its indicator
// drill-down; anything else becomes a Live feed keyword filter.
const INDICATOR_PATTERNS = [
  ['cve', /^CVE-\d{4}-\d{4,}$/i, v => v.toUpperCase()],
  ['ip', /^(?:\d{1,3}\.){3}\d{1,3}$/, v => v],
  ['hash', /^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i, v => v.toLowerCase()],
  ['email', /^[^\s@]+@[^\s@]+\.[^\s@]+$/, v => v.toLowerCase()],
];
document.getElementById('globalSearchForm').addEventListener('submit', (e) => {
  e.preventDefault();
  const query = document.getElementById('globalSearch').value.trim();
  if (!query) return;
  const match = INDICATOR_PATTERNS.find(([, pattern]) => pattern.test(query));
  if (match) {
    const [type, , normalize] = match;
    currentIocType = type;
    iocCurrentPage = 1;
    navigateTo('iocs');
    showIocArticles(type, normalize(query));
    return;
  }
  navigateTo('live-feed');
  const input = document.getElementById('searchInput');
  input.value = query;
  input.dispatchEvent(new Event('input'));
});
document.addEventListener('keydown', (e) => {
  if (e.key !== '/' || e.ctrlKey || e.metaKey || e.altKey) return;
  if (e.target.closest && e.target.closest('input, textarea, select, [contenteditable="true"]')) return;
  e.preventDefault();
  document.getElementById('globalSearch').focus();
});

// Small screens: the sidebar becomes a drawer.
const navRail = document.getElementById('navRail');
const navToggle = document.getElementById('navToggle');
const navScrim = document.getElementById('navScrim');
function setNavOpen(open) {
  navRail.classList.toggle('open', open);
  navScrim.hidden = !open;
  navToggle.setAttribute('aria-expanded', String(open));
  navToggle.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
}
navToggle.addEventListener('click', () => setNavOpen(!navRail.classList.contains('open')));
navScrim.addEventListener('click', () => setNavOpen(false));
navRail.addEventListener('click', (e) => { if (e.target.closest('.nav-item')) setNavOpen(false); });
document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && navRail.classList.contains('open')) setNavOpen(false); });

document.querySelectorAll('#dashRange button').forEach(btn => {
  btn.addEventListener('click', () => {
    dashHours = Number(btn.dataset.hours);
    document.querySelectorAll('#dashRange button').forEach(b => b.setAttribute('aria-pressed', String(b === btn)));
    loadDashboard();
  });
});

// -------------------------------------------------------------- 0.6.0 shared helpers

const COPY_ICON = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 9h11v11H9zM5 15H4V4h11v1"/></svg>';
const EDIT_ICON = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 20h4L19 9l-4-4L4 16v4z"/></svg>';
const PAUSE_ICON = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" aria-hidden="true"><path d="M9 5v14M15 5v14"/></svg>';
const PLAY_ICON = '<svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M8 5v14l11-7z"/></svg>';
const TRASH_ICON = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/></svg>';
const CLOSE_ICON = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18"/></svg>';

function showToast(message) {
  document.querySelectorAll('.toast').forEach(t => t.remove());
  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.setAttribute('role', 'status');
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 2200);
}

// navigator.clipboard only exists on https:// or localhost, and Pantomath
// is often opened over plain http on the LAN — so fall back to the older
// execCommand route rather than silently doing nothing.
async function copyText(text, what) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
    } else {
      const area = document.createElement('textarea');
      area.value = text;
      area.setAttribute('readonly', '');
      area.style.position = 'fixed';
      area.style.opacity = '0';
      document.body.appendChild(area);
      area.select();
      const ok = document.execCommand('copy');
      area.remove();
      if (!ok) throw new Error('copy refused');
    }
    showToast(`Copied ${what}`);
  } catch (e) {
    showToast("Couldn't copy. Select the text and copy it manually.");
  }
}

function downloadText(filename, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type: type || 'text/plain' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// Read state lives in this browser: an item is new if Pantomath stored it
// after you last left or last pressed "Mark all as read", whichever is later.
const READ_MARK_KEY = 'pantomath-read-mark';
const pageLoadedAt = Date.now() / 1000;
function unreadSince() {
  let mark = 0;
  try { mark = parseFloat(localStorage.getItem(READ_MARK_KEY)) || 0; } catch (e) { /* storage disabled */ }
  return Math.max(previousVisitEnded || (pageLoadedAt - 86400), mark);
}

// -------------------------------------------------------------- feed lists (0.6.0; shared since 0.6.1)
//
// One list + detail panel, used by the Live feed and every other feed page
// (High severity, Vulnerabilities, Malware, Ransomware, Saved, Vendors,
// Threat actors). Each page keeps its own items and selection; the keyboard
// shortcuts act on whichever page is showing.

const FEED_PANELS = {};
function createFeedPanel(view, listId, detailId, emptyState) {
  FEED_PANELS[view] = { view, listId, detailId, emptyState, items: [], selectedId: null, shownId: null };
  return FEED_PANELS[view];
}

const livePanel = createFeedPanel('live-feed', 'liveFeed', 'liveDetail', () => (
  lastOverviewData && lastOverviewData.sources.total === 0
    ? { title: 'No sources yet', hint: 'Add an RSS or Atom feed to start collecting.' }
    : { title: 'Nothing matches these filters', hint: 'Try clearing the search, severity, source or date filters.' }
));
let liveTotal = 0;
let liveDensity = 'compact';
try { liveDensity = localStorage.getItem('pantomath-density') || 'compact'; } catch (e) { /* default */ }

function setLiveDensity(density) {
  liveDensity = density;
  try { localStorage.setItem('pantomath-density', density); } catch (e) { /* not remembered */ }
  document.querySelectorAll('.feed-table').forEach(t => { t.dataset.density = density; });
  document.querySelectorAll('.density-seg button').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.density === density)));
}
setLiveDensity(liveDensity);
document.querySelectorAll('.density-seg button').forEach(btn => btn.addEventListener('click', () => setLiveDensity(btn.dataset.density)));

(function fillCategoryFilter() {
  const select = document.getElementById('liveCategory');
  Object.keys(CATEGORY_COLORS).forEach(c => {
    const option = document.createElement('option');
    option.value = c;
    option.textContent = c.charAt(0).toUpperCase() + c.slice(1);
    select.appendChild(option);
  });
})();
document.getElementById('liveSource').addEventListener('change', (e) => { liveSourceId = e.target.value; loadLiveFeed(1); });
document.getElementById('liveCategory').addEventListener('change', (e) => { liveCategory = e.target.value; loadLiveFeed(1); });
document.getElementById('liveMarkAllRead').addEventListener('click', () => {
  try { localStorage.setItem(READ_MARK_KEY, String(Date.now() / 1000)); } catch (e) { /* storage disabled */ }
  Object.values(FEED_PANELS).forEach(renderFeedRows);
  updateLiveSubtitle();
  refreshShell();
  showToast('Marked everything as read');
});

function populateLiveSourceFilter() {
  const list = lastOverviewData ? lastOverviewData.sources.list : [];
  const select = document.getElementById('liveSource');
  const key = list.map(s => s.id + s.name).join('|');
  if (select.dataset.key === key) return;
  select.dataset.key = key;
  select.innerHTML = '<option value="">All sources</option>' + list.slice()
    .sort((a, b) => a.name.localeCompare(b.name))
    .map(s => `<option value="${escapeAttr(s.id)}">${escapeHtml(s.name)}</option>`).join('');
  select.value = liveSourceId;
}

function updateLiveSubtitle() {
  const filtered = liveSearchTerm || liveSeverities.size < 3 || liveDateFrom || liveDateTo || liveSourceId || liveCategory;
  const newCount = livePanel.items.filter(i => i.fetched_at > unreadSince()).length;
  document.getElementById('liveSubtitle').textContent =
    `${liveTotal} item${liveTotal === 1 ? '' : 's'}${filtered ? ' match these filters' : ''}, newest arrivals first. ` +
    (newCount ? `${newCount} new on this page since ${fmtClock(unreadSince())}.` : 'Nothing new on this page.');
}

function feedRowHtml(panel, i, unread) {
  const chip = i.cves[0] || i.ips[0] || (i.hashes[0] ? i.hashes[0].slice(0, 12) + '…' : '') || i.emails[0] || '';
  const total = i.cves.length + i.ips.length + i.hashes.length + i.emails.length;
  const saved = !!i.bookmarked;
  return `<div class="feed-row${unread ? ' unread' : ''}${i.id === panel.selectedId ? ' selected' : ''}" data-id="${escapeAttr(i.id)}" role="listitem">
    <span class="unread-dot" aria-label="${unread ? 'New' : ''}"></span>
    <span class="sev-pill sev-${escapeAttr(i.severity)}">${escapeHtml(i.severity)}</span>
    <div class="feed-row-main">
      <button type="button" class="feed-row-title">${escapeHtml(i.title)}</button>
      <div class="feed-row-summary">${escapeHtml(truncateAtSentence(stripHtml(i.summary)))}</div>
    </div>
    <span class="feed-row-source">${sourceIconHtml(i.source_id, i.source_color)}<span>${escapeHtml(i.source_name)}</span></span>
    <span class="feed-row-iocs">${chip ? `<span class="chip chip-ioc">${escapeHtml(chip)}</span>` : ''}${total > 1 ? `<span>+${total - 1}</span>` : ''}</span>
    <span class="feed-row-time" title="${escapeAttr(timeTitle(i))}">${escapeHtml(fmtClock(effectiveTs(i)))}</span>
    <button type="button" class="row-icon${saved ? ' saved' : ''}" data-action="bookmark" aria-label="${saved ? 'Remove from saved' : 'Save'}" title="${saved ? 'Saved' : 'Save'}">${saved ? '&#9733;' : '&#9734;'}</button>
  </div>`;
}

function renderFeedRows(panel) {
  const el = document.getElementById(panel.listId);
  el.dataset.density = liveDensity;
  if (!panel.items.length) {
    const empty = panel.emptyState();
    el.innerHTML = `<div class="card-empty"><strong>${escapeHtml(empty.title)}</strong>${escapeHtml(empty.hint)}</div>`;
    return;
  }
  const since = unreadSince();
  const anyUnread = panel.items.some(i => i.fetched_at > since);
  const parts = anyUnread ? ['<div class="feed-divider new">New since you last looked</div>'] : [];
  let earlierShown = false;
  for (const i of panel.items) {
    const unread = i.fetched_at > since;
    if (anyUnread && !unread && !earlierShown) { parts.push('<div class="feed-divider">Earlier</div>'); earlierShown = true; }
    parts.push(feedRowHtml(panel, i, unread));
  }
  el.innerHTML = parts.join('');
  el.querySelectorAll('.feed-row').forEach(row => {
    row.addEventListener('click', (e) => {
      const item = panel.items.find(i => i.id === row.dataset.id);
      if (!item) return;
      if (e.target.closest('[data-action="bookmark"]')) toggleFeedBookmark(panel, item);
      else selectFeedItem(panel, item.id);
    });
  });
}

async function toggleFeedBookmark(panel, item) {
  const next = !item.bookmarked;
  await toggleBookmark(item.id, next);
  panel.items.forEach(x => { if (x.id === item.id) x.bookmarked = next; });
  item.bookmarked = next;
  renderFeedRows(panel);
  if (panel.shownId === item.id) renderFeedDetail(panel, item, { force: true });
  showToast(next ? 'Saved' : 'Removed from saved');
  if (panel.view === 'saved' && !next) loadFeedPage('saved');
}

function selectFeedItem(panel, id, { scroll = false } = {}) {
  const item = panel.items.find(i => i.id === id);
  if (!item) return;
  panel.selectedId = id;
  document.querySelectorAll(`#${panel.listId} .feed-row`).forEach(r => r.classList.toggle('selected', r.dataset.id === id));
  renderFeedDetail(panel, item);
  if (scroll) document.querySelector(`#${panel.listId} .feed-row[data-id="${CSS.escape(id)}"]`)?.scrollIntoView({ block: 'nearest' });
}

function closeFeedDetail(panel) {
  panel.selectedId = null;
  panel.shownId = null;
  document.getElementById(panel.detailId).hidden = true;
  document.getElementById('view-' + panel.view).classList.remove('has-detail');
  document.querySelectorAll(`#${panel.listId} .feed-row.selected`).forEach(r => r.classList.remove('selected'));
}

function renderFeedDetail(panel, i, { force = false } = {}) {
  if (!force && panel.shownId === i.id) return;
  panel.shownId = i.id;
  const el = document.getElementById(panel.detailId);
  document.getElementById('view-' + panel.view).classList.add('has-detail');
  el.hidden = false;
  const indicators = [
    ...i.cves.map(v => ['cve', 'CVE', v]), ...i.ips.map(v => ['ip', 'IP', v]),
    ...i.hashes.map(v => ['hash', 'Hash', v]), ...i.emails.map(v => ['email', 'Email', v]),
  ];
  const summary = stripHtml(i.summary || '');
  el.innerHTML = `
    <div class="detail-top">
      <span class="sev-pill sev-${escapeAttr(i.severity)}">${escapeHtml(i.severity)}</span>
      ${i.category ? `<span class="chip">${escapeHtml(i.category.charAt(0).toUpperCase() + i.category.slice(1))}</span>` : ''}
      <button type="button" class="icon-btn-sq" data-role="close" aria-label="Close details">${CLOSE_ICON}</button>
    </div>
    <h3 class="detail-title">${escapeHtml(i.title)}</h3>
    <dl class="detail-meta">
      <dt>Source</dt><dd>${escapeHtml(i.source_name)}</dd>
      <dt>Published</dt><dd>${escapeHtml(fmtFull(effectiveTs(i)))}</dd>
      <dt>Seen by Pantomath</dt><dd>${escapeHtml(fmtFull(i.fetched_at))}</dd>
      ${i.vendors.length ? `<dt>Vendors</dt><dd>${i.vendors.map(escapeHtml).join(', ')}</dd>` : ''}
      ${i.actors.length ? `<dt>Threat actors</dt><dd>${i.actors.map(escapeHtml).join(', ')}</dd>` : ''}
    </dl>
    ${summary ? `<p class="detail-summary">${escapeHtml(summary.length > 1200 ? summary.slice(0, 1200) + '…' : summary)}</p>` : ''}
    <section class="detail-section">
      <div class="detail-section-head">
        <h4>Indicators (${indicators.length})</h4>
        ${indicators.length ? '<button type="button" class="btn btn-sm" data-role="copy-all">Copy all</button>' : ''}
      </div>
      ${indicators.length ? indicators.map(([type, label, v]) => `
        <div class="ioc-line">
          <span class="ioc-type">${label}</span>
          <button type="button" class="ioc-value" data-ioc-type="${type}" data-ioc-value="${escapeAttr(v)}" title="Show every item mentioning this">${escapeHtml(v)}</button>
          <button type="button" class="row-icon" data-copy="${escapeAttr(v)}" aria-label="Copy ${escapeAttr(v)}">${COPY_ICON}</button>
        </div>`).join('') : '<p class="muted">No CVEs, IP addresses, hashes or emails were found in this item.</p>'}
    </section>
    <section class="detail-section" data-role="related"></section>
    <div class="detail-actions">
      <a class="btn btn-primary" href="${safeHref(i.link)}" target="_blank" rel="noopener">Open original &#8599;</a>
      <button type="button" class="btn" data-role="save">${i.bookmarked ? '&#9733; Saved' : '&#9734; Save'}</button>
    </div>`;
  el.querySelector('[data-role="close"]').onclick = () => closeFeedDetail(panel);
  el.querySelector('[data-role="save"]').onclick = () => toggleFeedBookmark(panel, i);
  const copyAll = el.querySelector('[data-role="copy-all"]');
  if (copyAll) copyAll.onclick = () => copyText(indicators.map(x => x[2]).join('\n'), `${indicators.length} indicator${indicators.length === 1 ? '' : 's'}`);
  el.querySelectorAll('[data-copy]').forEach(btn => { btn.onclick = () => copyText(btn.dataset.copy, btn.dataset.copy); });
  el.querySelectorAll('.ioc-value').forEach(btn => {
    btn.onclick = () => openMention({ cve: 'cves', ip: 'ips', hash: 'hashes', email: 'emails' }[btn.dataset.iocType], btn.dataset.iocValue);
  });
  loadRelated(panel, i);
}

async function loadRelated(panel, i) {
  const el = document.getElementById(panel.detailId).querySelector('[data-role="related"]');
  const pick = i.cves[0] ? ['cve', i.cves[0]] : i.ips[0] ? ['ip', i.ips[0]] : i.hashes[0] ? ['hash', i.hashes[0]] : null;
  if (!pick) { el.hidden = true; return; }
  const [type, value] = pick;
  const short = value.length > 24 ? value.slice(0, 22) + '…' : value;
  const related = (await fetchItems({ ioc_type: type, ioc_value: value, limit: 6 })).filter(r => r.id !== i.id).slice(0, 3);
  if (panel.shownId !== i.id) return;  // the selection moved on while this loaded
  el.hidden = false;
  el.innerHTML = '<h4>Related</h4>' + (related.length
    ? related.map(r => `<a class="related-link" href="${safeHref(r.link)}" target="_blank" rel="noopener">
        <span class="related-title">${escapeHtml(r.title)}</span>
        <span class="related-why">Also mentions ${escapeHtml(short)}. ${escapeHtml(r.source_name)}, ${escapeHtml(fmtClock(effectiveTs(r)))}</span>
      </a>`).join('')
    : `<p class="muted">No other items mention ${escapeHtml(short)}.</p>`);
}

// A CVE, IP, hash or email opens its drill-down on Indicators; a vendor or
// threat actor opens that page with it selected.
function openMention(field, value) {
  if (field === 'vendors') { selectedVendor = value; navigateTo('vendors'); return; }
  if (field === 'actors') { selectedActor = value; navigateTo('threat-actors'); return; }
  const type = { cves: 'cve', ips: 'ip', hashes: 'hash', emails: 'email' }[field];
  currentIocType = type;
  iocCurrentPage = 1;
  navigateTo('iocs');
  showIocArticles(type, value);
}

document.addEventListener('keydown', (e) => {
  const panel = FEED_PANELS[currentView()];
  if (!panel || e.ctrlKey || e.metaKey || e.altKey) return;
  if (e.target.closest && e.target.closest('input, textarea, select, [contenteditable="true"]')) return;
  if (document.querySelector('.modal-overlay.open')) return;
  const index = panel.items.findIndex(i => i.id === panel.selectedId);
  if (e.key === 'j' || e.key === 'k') {
    e.preventDefault();
    const next = e.key === 'j' ? Math.min(panel.items.length - 1, index + 1) : Math.max(0, index - 1);
    if (panel.items[next]) selectFeedItem(panel, panel.items[next].id, { scroll: true });
  } else if (e.key === 'o' && index >= 0) {
    window.open(safeHref(panel.items[index].link), '_blank', 'noopener');
  } else if (e.key === 's' && index >= 0) {
    toggleFeedBookmark(panel, panel.items[index]);
  } else if (e.key === 'Escape' && panel.selectedId) {
    closeFeedDetail(panel);
  }
});

// -------------------------------------------------------------- feed pages (0.6.1)

const FEED_PAGE_LIMIT = 200;

// Same order as /api/items: arrival minute, then published date.
function feedOrder(a, b) {
  return Math.floor(b.fetched_at / 60) - Math.floor(a.fetched_at / 60) || effectiveTs(b) - effectiveTs(a);
}

// Two filters OR'd together (the API ANDs filters within one request),
// e.g. Vulnerabilities = "from a Vulnerability source" OR "mentions a CVE".
async function fetchEither(paramsA, paramsB) {
  const [a, b] = await Promise.all([
    fetchItems({ limit: FEED_PAGE_LIMIT, ...paramsA }),
    fetchItems({ limit: FEED_PAGE_LIMIT, ...paramsB }),
  ]);
  const merged = new Map();
  [...a, ...b].forEach(i => merged.set(i.id, i));
  return [...merged.values()].sort(feedOrder).slice(0, FEED_PAGE_LIMIT);
}

const FEED_PAGES = {
  critical: {
    key: 'critical', list: 'feedCritical', mentions: ['cves', 'vendors', 'actors'], fourth: 'cve',
    fetch: () => fetchItems({ limit: FEED_PAGE_LIMIT, severity: 'high' }),
    empty: { title: 'No high-severity items', hint: 'Items scored high severity will appear here.' },
  },
  vulnerabilities: {
    key: 'vulns', list: 'feedVulnerabilities', mentions: ['cves', 'vendors'], fourth: 'high',
    fetch: () => fetchEither({ category: 'vulnerability' }, { has_cve: true }),
    empty: { title: 'No vulnerability items yet', hint: 'Items that mention a CVE, or come from a Vulnerability source, will appear here.' },
  },
  malware: {
    key: 'malware', list: 'feedMalware', mentions: ['actors', 'vendors', 'hashes'], fourth: 'high',
    fetch: () => fetchEither({ category: 'malware' }, { has_actor: true }),
    empty: { title: 'No malware items yet', hint: 'Items that name a threat actor, or come from a Malware source, will appear here.' },
  },
  ransomware: {
    key: 'ransomware', list: 'feedRansomware', mentions: ['actors', 'vendors', 'cves'], fourth: 'high',
    fetch: () => fetchItems({ limit: FEED_PAGE_LIMIT, keyword: 'ransomware' }),
    empty: { title: 'No ransomware items yet', hint: 'Items that mention ransomware will appear here.' },
  },
  saved: {
    key: 'saved', list: 'feedSaved', mentions: ['cves', 'vendors', 'actors'], fourth: 'high',
    fetch: () => fetchItems({ limit: FEED_PAGE_LIMIT, bookmarked_only: true }),
    empty: { title: 'Nothing saved yet', hint: 'Select an item and press Save, or use the star on any row.' },
  },
};

Object.entries(FEED_PAGES).forEach(([view, cfg]) => {
  cfg.allItems = [];
  cfg.filterText = '';
  cfg.panel = createFeedPanel(view, cfg.list, cfg.key + 'Detail', () => (
    cfg.filterText ? { title: 'Nothing matches the filter', hint: 'Clear the filter to see every item.' } : cfg.empty
  ));
  let debounce = null;
  document.getElementById(cfg.key + 'Filter').addEventListener('input', (e) => {
    clearTimeout(debounce);
    debounce = setTimeout(() => { cfg.filterText = e.target.value.trim().toLowerCase(); applyFeedPageFilter(cfg); }, 150);
  });
});

async function loadFeedPage(view) {
  const cfg = FEED_PAGES[view];
  const items = await cfg.fetch();
  cfg.allItems = items;
  renderFeedStats(cfg.key + 'Stats', items, cfg.fourth);
  renderMentions(document.getElementById(cfg.key + 'Mentions'), items, cfg.mentions);
  document.getElementById(cfg.key + 'Note').textContent = items.length >= FEED_PAGE_LIMIT
    ? `Showing the newest ${FEED_PAGE_LIMIT}. The Live feed's filters reach everything stored.` : '';
  applyFeedPageFilter(cfg);
}

function itemMatches(i, text) {
  if (!text) return true;
  return [i.title, i.source_name, stripHtml(i.summary || ''), ...i.cves, ...i.ips, ...i.hashes, ...i.vendors, ...i.actors]
    .some(v => (v || '').toLowerCase().includes(text));
}

function applyFeedPageFilter(cfg) {
  cfg.panel.items = cfg.allItems.filter(i => itemMatches(i, cfg.filterText));
  renderFeedRows(cfg.panel);
  const selected = cfg.panel.items.find(i => i.id === cfg.panel.selectedId);
  if (selected) renderFeedDetail(cfg.panel, selected);
}

function renderFeedStats(elId, items, fourth, first = null) {
  const since = unreadSince();
  const dayAgo = Date.now() / 1000 - 86400;
  const unread = items.filter(i => i.fetched_at > since).length;
  const capped = items.length >= FEED_PAGE_LIMIT;
  const cells = [
    first || { label: 'Items', value: capped ? `${FEED_PAGE_LIMIT}+` : items.length, note: capped ? `showing the newest ${FEED_PAGE_LIMIT}` : 'newest arrivals first' },
    { label: 'New since you last looked', value: unread, tone: unread ? 'signal' : '', note: unread ? `since ${fmtClock(since)}` : 'nothing new' },
    { label: 'Published in the last 24 hours', value: items.filter(i => effectiveTs(i) >= dayAgo).length, note: 'by published date' },
    fourth === 'cve'
      ? { label: 'Mention a CVE', value: items.filter(i => i.cves.length).length, note: `${new Set(items.flatMap(i => i.cves)).size} distinct CVEs` }
      : { label: 'High severity', value: items.filter(i => i.severity === 'high').length, tone: 'high', note: `of ${items.length} shown` },
  ];
  document.getElementById(elId).innerHTML = cells.map(c => `
    <div class="kpi static">
      <span class="kpi-label">${escapeHtml(c.label)}</span>
      <span class="kpi-value${c.tone ? ' tone-' + c.tone : ''}">${escapeHtml(String(c.value))}</span>
      <span class="kpi-note">${escapeHtml(c.note)}</span>
    </div>`).join('');
}

const MENTION_HINTS = {
  cves: 'Open this CVE on Indicators', ips: 'Open this IP address on Indicators', hashes: 'Open this hash on Indicators',
  vendors: 'Open this vendor', actors: 'Open this threat actor',
};
function renderMentions(el, items, fields) {
  const counts = new Map();
  items.forEach(i => fields.forEach(f => new Set(i[f]).forEach(v => {
    const k = f + '\u0000' + v;
    counts.set(k, (counts.get(k) || 0) + 1);
  })));
  const top = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
  if (!top.length) { el.innerHTML = ''; return; }
  el.innerHTML = '<span>Most mentioned here:</span>' + top.map(([k, n]) => {
    const [f, v] = k.split('\u0000');
    const mono = f === 'cves' || f === 'ips' || f === 'hashes';
    const label = f === 'hashes' ? v.slice(0, 12) + '…' : v;
    return `<button type="button" class="mention-chip${mono ? ' mono' : ''}" data-field="${f}" data-value="${escapeAttr(v)}" title="${MENTION_HINTS[f]}">${escapeHtml(label)}<span class="count">${n}</span></button>`;
  }).join('');
  el.querySelectorAll('.mention-chip').forEach(chip => { chip.onclick = () => openMention(chip.dataset.field, chip.dataset.value); });
}

// Vendors and Threat actors: a chip per name, then the same list and panel.
const TAG_PAGES = {
  vendors: { key: 'vendors', list: 'feedVendors', filter: 'vendorFilter', chips: 'vendorChips', noun: 'vendor' },
  'threat-actors': { key: 'actors', list: 'feedActors', filter: 'actorFilter', chips: 'actorChips', noun: 'threat actor' },
};
Object.entries(TAG_PAGES).forEach(([view, cfg]) => {
  cfg.name = null;
  cfg.panel = createFeedPanel(view, cfg.list, cfg.key + 'Detail', () => (
    cfg.name ? { title: `No stored items name ${cfg.name}`, hint: '' }
      : { title: `No ${cfg.noun}s yet`, hint: `They appear here once stored items name them.` }
  ));
  document.getElementById(cfg.filter).addEventListener('input', (e) => {
    const text = e.target.value.trim().toLowerCase();
    document.querySelectorAll(`#${cfg.chips} .tag-chip`).forEach(chip => {
      chip.hidden = !!text && !chip.dataset[cfg.noun === 'vendor' ? 'vendor' : 'actor'].toLowerCase().includes(text);
    });
  });
});

function showTagItems(view, name, total, items) {
  const cfg = TAG_PAGES[view];
  const changed = cfg.name !== name;
  cfg.name = name;
  cfg.panel.items = items;
  if (changed && cfg.panel.selectedId) closeFeedDetail(cfg.panel);
  renderFeedRows(cfg.panel);
  const selected = items.find(i => i.id === cfg.panel.selectedId);
  if (selected) renderFeedDetail(cfg.panel, selected);
  if (!name) { document.getElementById(cfg.key + 'Stats').innerHTML = ''; return; }
  renderFeedStats(cfg.key + 'Stats', items, 'high', {
    label: `Items naming ${name}`, value: total,
    note: total > items.length ? `showing the newest ${items.length}` : 'all shown below',
  });
}

// -------------------------------------------------------------- settings (0.6.1)

document.querySelectorAll('.settings-nav button').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.settings-nav button').forEach(b => b.classList.toggle('active', b === btn));
    document.getElementById(btn.dataset.target).scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
});
// The switches are toggled by their own handlers through the "on" class;
// keep aria-checked in step so screen readers hear the real state.
document.querySelectorAll('.toggle-switch').forEach(sw => {
  const sync = () => sw.setAttribute('aria-checked', String(sw.classList.contains('on')));
  sync();
  new MutationObserver(sync).observe(sw, { attributes: true, attributeFilter: ['class'] });
});

// -------------------------------------------------------------- indicators (0.6.0)

const IOC_FILTER_LIMIT = 200;
const iocSelection = new Set();
const iocRowCache = new Map();
let iocSelectionType = currentIocType;
let iocFilterText = '';
let iocFilterDebounce = null;
document.getElementById('iocFilter').addEventListener('input', (e) => {
  clearTimeout(iocFilterDebounce);
  iocFilterDebounce = setTimeout(() => { iocFilterText = e.target.value.trim(); loadIOCsView(1); }, 250);
});

function renderIocTable(rows) {
  const el = document.getElementById('iocTopChart');
  if (!rows.length) {
    const what = IOC_TYPE_LOWER[currentIocType];
    el.innerHTML = `<div class="card-empty"><strong>No ${what}</strong>${iocFilterText ? 'Nothing matches the filter.' : iocSelectedDate ? 'None appeared on this day.' : 'They show up here once articles mention them.'}</div>`;
    return;
  }
  const allSelected = rows.every(r => iocSelection.has(r.name));
  el.innerHTML = `<div class="ioc-row ioc-head" role="row">
      <span role="columnheader"><input type="checkbox" id="iocSelectAll" aria-label="Select every indicator on this page"${allSelected ? ' checked' : ''}></span>
      <span role="columnheader">${escapeHtml(IOC_SINGULAR[currentIocType].charAt(0).toUpperCase() + IOC_SINGULAR[currentIocType].slice(1))}</span>
      <span role="columnheader" class="num">Mentions</span><span role="columnheader" class="num">Sources</span>
      <span role="columnheader">Highest severity</span><span role="columnheader">First seen</span><span role="columnheader">Last seen</span><span></span>
    </div>` + rows.map(r => `
    <div class="ioc-row${iocDrilldown && iocDrilldown.type === currentIocType && iocDrilldown.value === r.name ? ' selected' : ''}" role="row" data-value="${escapeAttr(r.name)}">
      <span role="cell"><input type="checkbox" class="ioc-check" data-value="${escapeAttr(r.name)}" aria-label="Select ${escapeAttr(r.name)}"${iocSelection.has(r.name) ? ' checked' : ''}></span>
      <span role="cell" style="min-width:0; display:flex;"><button type="button" class="ioc-value" data-value="${escapeAttr(r.name)}" title="Show the articles that mention this">${escapeHtml(r.name)}</button></span>
      <span role="cell" class="num">${r.count}</span>
      <span role="cell" class="num">${r.sources}</span>
      <span role="cell"><span class="sev-pill sev-${escapeAttr(r.severity)}">${escapeHtml(r.severity)}</span></span>
      <span role="cell" class="when">${escapeHtml(fmtClock(r.first_seen))}</span>
      <span role="cell" class="when">${escapeHtml(fmtClock(r.last_seen))}</span>
      <button type="button" class="row-icon" data-copy="${escapeAttr(r.name)}" aria-label="Copy ${escapeAttr(r.name)}">${COPY_ICON}</button>
    </div>`).join('');

  const syncSelectAll = () => {
    const all = document.getElementById('iocSelectAll');
    const picked = rows.filter(r => iocSelection.has(r.name)).length;
    all.checked = picked === rows.length;
    all.indeterminate = picked > 0 && picked < rows.length;
  };
  syncSelectAll();
  el.querySelectorAll('.ioc-check').forEach(box => {
    box.onchange = () => {
      if (box.checked) iocSelection.add(box.dataset.value); else iocSelection.delete(box.dataset.value);
      syncSelectAll();
      updateIocActionBar();
    };
  });
  document.getElementById('iocSelectAll').onchange = (e) => {
    rows.forEach(r => (e.target.checked ? iocSelection.add(r.name) : iocSelection.delete(r.name)));
    el.querySelectorAll('.ioc-check').forEach(box => { box.checked = e.target.checked; });
    updateIocActionBar();
  };
  el.querySelectorAll('.ioc-value').forEach(btn => { btn.onclick = () => showIocArticles(currentIocType, btn.dataset.value); });
  el.querySelectorAll('[data-copy]').forEach(btn => { btn.onclick = () => copyText(btn.dataset.copy, btn.dataset.copy); });
}

function updateIocActionBar() {
  const n = iocSelection.size;
  document.getElementById('iocSelectedCount').textContent = n
    ? `${n} selected`
    : `Nothing selected. Actions apply to all ${IOC_TYPE_LOWER[currentIocType]} in the list.`;
  document.getElementById('iocCopyBtn').textContent = n ? 'Copy selected' : 'Copy all';
  document.getElementById('iocCsvBtn').textContent = n ? 'Export selected (CSV)' : 'Export CSV';
  document.getElementById('iocListBtn').textContent = currentIocType === 'cve' ? 'Download list (.txt)' : 'Download blocklist (.txt)';
}

async function iocRowsForExport() {
  if (iocSelection.size) return [...iocSelection].map(v => iocRowCache.get(v) || { name: v });
  const dateParams = iocSelectedDate ? `&date_from=${iocSelectedDate}&date_to=${iocSelectedDate}` : '';
  const filterParams = iocFilterText ? `&q=${encodeURIComponent(iocFilterText)}` : '';
  return fetch(`/api/iocs?type=${currentIocType}&detail=1&limit=100000&offset=0${dateParams}${filterParams}`).then(r => r.json());
}

function iocExportName(ext) {
  return `pantomath-${currentIocType}-${new Date().toISOString().slice(0, 10)}.${ext}`;
}

// Spreadsheet apps execute cells that start with = + - @ as formulas.
function csvCell(value) {
  let text = value === undefined || value === null ? '' : String(value);
  if (/^[=+\-@]/.test(text)) text = "'" + text;
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

document.getElementById('iocCopyBtn').onclick = async () => {
  const rows = await iocRowsForExport();
  if (!rows.length) { showToast('Nothing to copy'); return; }
  copyText(rows.map(r => r.name).join('\n'), `${rows.length} indicator${rows.length === 1 ? '' : 's'}`);
};
document.getElementById('iocCsvBtn').onclick = async () => {
  const rows = await iocRowsForExport();
  const iso = ts => (ts ? new Date(ts * 1000).toISOString() : '');
  const lines = [['indicator', 'type', 'mentions', 'sources', 'highest_severity', 'first_seen_utc', 'last_seen_utc'].join(',')]
    .concat(rows.map(r => [r.name, currentIocType, r.count, r.sources, r.severity, iso(r.first_seen), iso(r.last_seen)].map(csvCell).join(',')));
  downloadText(iocExportName('csv'), lines.join('\n') + '\n', 'text/csv');
};
document.getElementById('iocListBtn').onclick = async () => {
  const rows = await iocRowsForExport();
  const header = `# Pantomath ${IOC_TYPE_LOWER[currentIocType]}, ${rows.length} entries, exported ${new Date().toISOString()}`;
  downloadText(iocExportName('txt'), [header, ...rows.map(r => r.name)].join('\n') + '\n');
};

// -------------------------------------------------------------- sources (0.6.0)

function sourceState(s) {
  if (!s.enabled) return 'paused';
  if (s.last_status === 'ok') return 'healthy';
  if ((s.last_status || '').startsWith('error')) return 'failing';
  return 'pending';
}

function formatInterval(seconds) {
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min`;
  const hours = Math.round((minutes / 60) * 10) / 10;
  return `${hours} h`;
}

function sourceRowHtml(s, state) {
  const label = { healthy: 'Healthy', failing: 'Failing', pending: 'Waiting', paused: 'Paused' }[state];
  const error = state === 'failing' ? (s.last_status.split(':').slice(1).join(':').trim() || 'The last poll failed') : '';
  const lastSuccess = s.last_success ? timeAgo(s.last_success)
    : (state === 'healthy' && s.last_fetched ? timeAgo(s.last_fetched) : 'never');
  const response = s.last_duration_ms
    ? (s.last_duration_ms < 1000 ? `${s.last_duration_ms} ms` : `${(s.last_duration_ms / 1000).toFixed(1)} s`) : '—';
  const name = escapeAttr(s.name);
  return `<div class="src-row state-${state}" role="row">
    <span class="src-status" role="cell"><span class="health-dot" aria-hidden="true"></span>${label}</span>
    <div class="src-main" role="cell">
      <div class="src-name">${sourceIconHtml(s.id, s.color)}<span>${escapeHtml(s.name)}</span></div>
      <div class="src-sub">${escapeHtml(s.category.charAt(0).toUpperCase() + s.category.slice(1))}, checked every ${escapeHtml(formatInterval(s.interval_seconds))}${s.items_total ? `, ${s.items_total} items stored` : ''}</div>
      ${error ? `<div class="src-error">${escapeHtml(error)}${s.failing_since ? `. Failing since ${escapeHtml(fmtClock(s.failing_since))}` : ''}</div>` : ''}
      <div class="src-test" id="srcTest-${escapeAttr(s.id)}" role="status" hidden></div>
    </div>
    <span class="src-cell src-last" role="cell">${escapeHtml(lastSuccess)}</span>
    <span class="src-cell num" role="cell">${s.items_today || 0}</span>
    <span class="src-cell num" role="cell">${escapeHtml(response)}</span>
    <div class="src-actions" role="cell">
      <button type="button" class="btn btn-sm" data-action="test" data-id="${escapeAttr(s.id)}" aria-label="Test ${name}">Test</button>
      <button type="button" class="row-icon" data-action="edit" data-id="${escapeAttr(s.id)}" aria-label="Edit ${name}" title="Edit">${EDIT_ICON}</button>
      <button type="button" class="row-icon" data-action="toggle" data-id="${escapeAttr(s.id)}" aria-label="${s.enabled ? 'Pause' : 'Resume'} ${name}" title="${s.enabled ? 'Pause' : 'Resume'}">${s.enabled ? PAUSE_ICON : PLAY_ICON}</button>
      <button type="button" class="row-icon danger" data-action="delete" data-id="${escapeAttr(s.id)}" aria-label="Remove ${name}" title="Remove">${TRASH_ICON}</button>
    </div>
  </div>`;
}

function renderSourcesSummary(list) {
  const count = { healthy: 0, failing: 0, pending: 0, paused: 0 };
  let today = 0, oldestFailure = 0;
  list.forEach(s => {
    const state = sourceState(s);
    count[state] += 1;
    today += s.items_today || 0;
    if (state === 'failing' && s.failing_since && (!oldestFailure || s.failing_since < oldestFailure)) oldestFailure = s.failing_since;
  });
  const cells = [
    { label: 'Healthy', value: count.healthy, tone: count.healthy ? 'good' : '', note: `of ${list.length} source${list.length === 1 ? '' : 's'}` },
    { label: 'Failing', value: count.failing, tone: count.failing ? 'bad' : '',
      note: count.failing ? (oldestFailure ? `oldest failing since ${fmtClock(oldestFailure)}` : 'see the reasons below') : 'nothing failing' },
    { label: 'Waiting or paused', value: count.pending + count.paused, note: `${count.pending} waiting for a first poll, ${count.paused} paused` },
    { label: 'Items today', value: today, note: 'stored since midnight' },
  ];
  document.getElementById('sourcesSummary').innerHTML = cells.map(c => `
    <div class="kpi static">
      <span class="kpi-label">${escapeHtml(c.label)}</span>
      <span class="kpi-value${c.tone ? ' tone-' + c.tone : ''}">${c.value}</span>
      <span class="kpi-note">${escapeHtml(c.note)}</span>
    </div>`).join('');
}

async function testFeedUrl(url) {
  try {
    const res = await fetch('/api/sources/test', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url }),
    });
    if (res.status === 401) return { ok: false, error: 'Settings are locked. Unlock Sources and try again.' };
    return await res.json();
  } catch (e) {
    return { ok: false, error: 'Pantomath itself could not be reached' };
  }
}

function describeFeedTest(r) {
  if (!r.ok) return { title: "This URL doesn't work as a feed", text: r.error || 'Unknown error' };
  const newest = r.newest_published ? `, newest published ${timeAgo(r.newest_published)}` : '';
  const cves = r.items_with_cve ? ` ${r.items_with_cve} of them mention a CVE.` : '';
  return {
    title: `Valid ${r.format} feed${r.title ? `: ${r.title}` : ''}`,
    text: `${r.items} item${r.items === 1 ? '' : 's'}${newest}.${cves}`,
  };
}

// Add/Edit source: "Test feed" checks the URL without saving. Saving runs
// the same test first; if it fails, the button becomes "Save anyway" so a
// broken source is never added by accident — but can still be on purpose
// (a feed that is only temporarily down).
let feedTestState = { url: null, ok: null };
function resetFeedTest() {
  feedTestState = { url: null, ok: null };
  const box = document.getElementById('feedTestResult');
  box.hidden = true;
  box.innerHTML = '';
  const confirmBtn = document.getElementById('confirmAdd');
  if (confirmBtn.dataset.saveAnyway === '1') {
    confirmBtn.textContent = confirmBtn.dataset.label || 'Add source';
    confirmBtn.dataset.saveAnyway = '';
  }
}
async function runModalFeedTest() {
  const url = document.getElementById('srcUrl').value.trim();
  const box = document.getElementById('feedTestResult');
  const btn = document.getElementById('testFeedBtn');
  box.hidden = false;
  if (!url) {
    box.className = 'feed-test bad';
    box.innerHTML = '<strong>Enter a feed URL first</strong>';
    return { ok: false };
  }
  btn.disabled = true;
  btn.textContent = 'Testing…';
  box.className = 'feed-test';
  box.textContent = 'Fetching the feed…';
  const result = await testFeedUrl(url);
  btn.disabled = false;
  btn.textContent = 'Test feed';
  const d = describeFeedTest(result);
  box.className = 'feed-test ' + (result.ok ? 'ok' : 'bad');
  box.innerHTML = `<strong>${escapeHtml(d.title)}</strong>${escapeHtml(d.text)}`;
  feedTestState = { url, ok: !!result.ok };
  return result;
}
document.getElementById('testFeedBtn').addEventListener('click', runModalFeedTest);
document.getElementById('srcUrl').addEventListener('input', () => { if (feedTestState.url !== null) resetFeedTest(); });
const saveSourceFromModal = document.getElementById('confirmAdd').onclick;
document.getElementById('confirmAdd').onclick = async (e) => {
  const btn = document.getElementById('confirmAdd');
  const url = document.getElementById('srcUrl').value.trim();
  if (url && btn.dataset.saveAnyway !== '1') {
    const result = feedTestState.url === url ? { ok: feedTestState.ok } : await runModalFeedTest();
    if (!result.ok) {
      btn.dataset.label = btn.textContent;
      btn.dataset.saveAnyway = '1';
      btn.textContent = 'Save anyway';
      return;
    }
  }
  resetFeedTest();
  return saveSourceFromModal(e);
};
// openModal() is a plain function declaration used from several places;
// wrapping it once here means every way of opening the form starts clean.
const openSourceModal = openModal;
openModal = function (source) {
  resetFeedTest();
  openSourceModal(source);
};

// -------------------------------------------------------------- analytics (0.6.0)

document.querySelectorAll('#anRange button').forEach(btn => {
  btn.addEventListener('click', () => {
    anDays = Number(btn.dataset.days);
    document.querySelectorAll('#anRange button').forEach(b => b.setAttribute('aria-pressed', String(b === btn)));
    loadAnalytics();
  });
});

function renderVolumeChart(el, days) {
  const max = Math.max(1, ...days.map(d => d.high + d.medium + d.low));
  const width = days.length * 10;
  const barWidth = days.length > 120 ? 9 : 7;
  const inset = (10 - barWidth) / 2;
  const label = d => new Date(d.date + 'T12:00:00').toLocaleDateString([], { day: 'numeric', month: 'short' });
  const bars = days.map((d, idx) => {
    let y = 100;
    const segments = [['low', d.low], ['medium', d.medium], ['high', d.high]].map(([sev, n]) => {
      if (!n) return '';
      const h = (n / max) * 98;
      y -= h;
      return `<rect class="bar-${sev}" x="${idx * 10 + inset}" y="${y.toFixed(2)}" width="${barWidth}" height="${h.toFixed(2)}"></rect>`;
    }).join('');
    const total = d.high + d.medium + d.low;
    return `<g><title>${escapeHtml(label(d))}: ${total} published (${d.high} high, ${d.medium} medium, ${d.low} low)</title>` +
      `<rect x="${idx * 10}" y="0" width="10" height="100" fill="transparent"></rect>${segments}</g>`;
  }).join('');
  const total = days.reduce((sum, d) => sum + d.high + d.medium + d.low, 0);
  el.innerHTML = `<div class="an-ymax">Busiest day: ${max} item${max === 1 ? '' : 's'}</div>
    <svg viewBox="0 0 ${width} 100" preserveAspectRatio="none" role="img" aria-label="${total} items published over ${days.length} days">${bars}</svg>
    <div class="an-axis"><span>${escapeHtml(label(days[0]))}</span><span>${escapeHtml(label(days[Math.floor(days.length / 2)]))}</span><span>Today</span></div>`;
}

function renderSeverityMix(el, t, p, previous) {
  if (!t.items) { el.innerHTML = '<p class="muted">Nothing was published in this period.</p>'; return; }
  const share = n => Math.round((n / t.items) * 100);
  el.innerHTML = `<div class="mix-bar" role="img" aria-label="${share(t.high)}% high, ${share(t.medium)}% medium, ${share(t.low)}% low">` +
    ['high', 'medium', 'low'].map(s => (t[s] ? `<i class="bar-${s}" style="width:${((t[s] / t.items) * 100).toFixed(2)}%"></i>` : '')).join('') +
    '</div><div class="mix-rows">' + ['high', 'medium', 'low'].map(s => {
      const diff = t[s] - p[s];
      const tone = s === 'high' && diff > 0 ? ' worse' : s === 'high' && diff < 0 ? ' better' : '';
      return `<div class="mix-row">
        <span><span class="sev-pill sev-${s}">${s}</span></span>
        <span class="num">${t[s]}<span class="share">${share(t[s])}%</span></span>
        <span class="delta${tone}">${diff === 0 ? 'no change' : `${diff > 0 ? '+' : '−'}${Math.abs(diff)}`} vs ${escapeHtml(previous)}</span>
      </div>`;
    }).join('') + '</div>';
}

function renderTopSources(el, rows, totalItems) {
  if (!rows.length) { el.innerHTML = '<p class="muted">Nothing was published in this period.</p>'; return; }
  el.innerHTML = '<div class="src-rank head"><span>Source</span><span class="num">Items</span><span class="num">High</span><span>Share of all items</span></div>' +
    rows.map(r => `<div class="src-rank">
      <span class="name" title="${escapeAttr(r.name)}">${escapeHtml(r.name)}</span>
      <span class="num">${r.count}</span>
      <span class="num high">${r.high}</span>
      <span class="rank-track" title="${Math.round((r.count / Math.max(1, totalItems)) * 100)}%"><i style="width:${((r.count / Math.max(1, totalItems)) * 100).toFixed(1)}%"></i></span>
    </div>`).join('');
}

function heatColor(n, max) {
  if (!n) return 'var(--bg-sunken)';
  return `color-mix(in srgb, var(--signal) ${Math.round(18 + (n / max) * 82)}%, var(--bg-sunken))`;
}

function renderHeatmap(el, heat) {
  const max = Math.max(1, ...heat.flat());
  let busiest = null;
  heat.forEach((row, wd) => row.forEach((n, hr) => { if (n && (!busiest || n > busiest.n)) busiest = { wd, hr, n }; }));
  const hour = h => String(h).padStart(2, '0') + ':00';
  let html = '<div class="heatmap" role="img" aria-label="' + escapeAttr(busiest
    ? `Busiest time: ${DAY_NAMES[busiest.wd]} around ${hour(busiest.hr)}, ${busiest.n} items` : 'Nothing published in this period') + '"><span></span>';
  for (let h = 0; h < 24; h++) html += `<span class="hm-hour">${h % 3 === 0 ? String(h).padStart(2, '0') : ''}</span>`;
  for (const wd of [1, 2, 3, 4, 5, 6, 0]) {
    html += `<span class="hm-label">${DAY_NAMES[wd]}</span>`;
    heat[wd].forEach((n, h) => {
      html += `<span class="hm-cell" style="background:${heatColor(n, max)}" title="${DAY_NAMES[wd]} ${hour(h)}: ${n} item${n === 1 ? '' : 's'}"></span>`;
    });
  }
  html += '</div><div class="hm-legend">Fewer ' + [0, 0.25, 0.5, 0.75, 1].map(f => `<i style="background:${heatColor(f * max, max)}"></i>`).join('') + ' More</div>';
  el.innerHTML = html;
}

function renderRankList(el, rows, emptyText) {
  if (!rows.length) { el.innerHTML = `<p class="muted">${escapeHtml(emptyText)}</p>`; return; }
  const max = Math.max(...rows.map(r => r.count));
  el.innerHTML = '<div class="rank-list">' + rows.map(r => `<div class="rank-row">
      <span class="rank-name" title="${escapeAttr(r.label || r.name)}">${escapeHtml(r.label || r.name)}</span>
      <span class="rank-track"><i style="width:${((r.count / max) * 100).toFixed(1)}%${r.color ? `; background:${r.color}` : ''}"></i></span>
      <span class="num">${r.count}</span>
    </div>`).join('') + '</div>';
}

function connectWs() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(proto + '//' + location.host + '/ws');
  ws.onopen = () => {
    wsOpen = true;
    wsEverOpened = true;
    renderConnStatus();
  };
  ws.onclose = () => {
    wsOpen = false;
    renderConnStatus();
    setTimeout(connectWs, 2000);
  };
  ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    if (msg.type === 'new_items') {
      // Whatever view is open just re-fetches — simplest correct behavior,
      // and item volume is low enough that this stays fast.
      VIEW_LOADERS[currentView()]?.();
      if (currentView() !== 'dashboard') refreshShell();
      loadSources();
      notifyForNewItems(msg.items);
    } else if (msg.type === 'sources_changed') {
      loadSources();
      if (currentView() === 'sources') loadSourcesView();
      if (currentView() === 'dashboard') loadDashboard(); else refreshShell();
    }
  };
}

// -------------------------------------------------------------- boot

(async function init() {
  initThemeControls();
  await initNotificationControls();
  try { await loadSources(); } catch (e) { console.warn('loadSources() failed during boot — continuing anyway:', e); }
  const initial = VIEWS.includes(location.hash.slice(1)) ? location.hash.slice(1) : 'dashboard';
  navigateTo(initial);
  if (initial !== 'dashboard') refreshShell();
  connectWs();
  setInterval(() => {
    VIEW_LOADERS[currentView()]?.();
    if (currentView() !== 'dashboard') refreshShell();
  }, 30000);
})();
