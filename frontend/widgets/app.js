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
    return nativeFetch(url, opts).then(res => {
      // 0.8.0: the server asks for sign-in (session expired or revoked).
      if (res.status === 401 && res.headers.get('X-Pantomath-Sign-In') && !document.body.classList.contains('signed-out')) {
        showSignIn(null, 'expired');
      }
      return res;
    });
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
  'dashboard', 'affects-us', 'exploited', 'live-feed', 'critical', 'vulnerabilities', 'malware',
  'ransomware', 'threat-actors', 'vendors', 'iocs', 'saved', 'sources', 'analytics', 'settings'
];
const VIEW_LOADERS = {
  'dashboard': loadDashboard,
  'affects-us': () => loadFeedPage('affects-us'),
  'exploited': () => loadFeedPage('exploited'),
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
  document.getElementById('attentionSub').textContent = `Critical and high priority, published in the last ${range}`;

  const src = ov.sources, ind = ov.indicators_week;
  const count = (n, one, many) => `${n} ${n === 1 ? one : many}`;
  let sourcesNote = 'add one to get started', sourcesTone = '';
  if (src.failing) { sourcesNote = `${src.failing} failing, see why`; sourcesTone = 'bad'; }
  else if (src.pending) sourcesNote = `${src.pending} waiting for a first poll`;
  else if (src.paused) sourcesNote = `${src.paused} paused`;
  else if (src.total) sourcesNote = 'all working';

  const kpis = [
    { label: 'Critical and high', value: ov.high_in_window,
      note: `${ov.critical_in_window || 0} critical, published in the last ${range}`,
      goto: 'critical', tone: ov.critical_in_window ? 'critical' : ov.high_in_window ? 'high' : '' },
    { label: 'New since you last looked', value: adjustedNewCount(ov.new_since, ov.since), note: `since ${fmtClock(ov.since)}`, goto: 'live-feed' },
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
        <a class="attention-title" href="${safeHref(i.link)}" target="_blank" rel="noopener">${flagsHtml(i)}${escapeHtml(i.title)}</a>
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
  days.forEach(d => { d.critical = d.critical || 0; });
  const max = Math.max(1, ...days.map(d => d.critical + d.high + d.medium + d.low));
  const px = n => Math.max(3, Math.round((n / max) * 96));
  const todayKey = days[days.length - 1].date;
  el.innerHTML = days.map(d => {
    const total = d.critical + d.high + d.medium + d.low;
    const isToday = d.date === todayKey;
    const label = isToday ? 'Today' : new Date(d.date + 'T12:00:00').toLocaleDateString([], { weekday: 'short' });
    const summary = `${label}: ${total} published, ${d.critical} critical, ${d.high} high, ${d.medium} medium, ${d.low} low`;
    return `<div class="day-col" role="img" aria-label="${escapeAttr(summary)}">
      <span class="day-total">${total}</span>
      <div class="day-bars">
        ${d.critical ? `<i class="bar-critical" style="height:${px(d.critical)}px"></i>` : ''}
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
let liveSeverities = new Set(['critical', 'high', 'medium', 'low']);
let liveDateFrom = '';
let liveDateTo = '';
let liveCurrentPage = 1;
const LIVE_PAGE_SIZE = 50;
let liveSearchDebounce = null;
let liveSourceId = '';
let liveCategory = '';
let liveOnlyOurs = false;
let liveOnlyExploited = false;

function liveFilterParams() {
  const params = {};
  if (liveSeverities.size < 4) params.severity = [...liveSeverities].join(',');
  if (liveSearchTerm) params.keyword = liveSearchTerm;
  if (liveDateFrom) params.date_from = liveDateFrom;
  if (liveDateTo) params.date_to = liveDateTo;
  if (liveSourceId) params.source_id = liveSourceId;
  if (liveCategory) params.category = liveCategory;
  if (liveOnlyOurs) params.affects_us = true;
  if (liveOnlyExploited) params.exploited = true;
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
    { label: 'Critical and high', value: t.critical + t.high, tone: t.critical ? 'critical' : t.high ? 'high' : '', note: `${t.critical} critical; ${t.items ? Math.round(((t.critical + t.high) / t.items) * 100) : 0}% of items, ${change(t.critical + t.high, p.critical + p.high)}` },
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
  refreshActiveSettingsTab();
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
    if (w.only_affects_us) parts.push('affects our stack');
    if (w.only_exploited) parts.push('exploited (CISA KEV)');
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
  document.getElementById('whOnlyOurs').checked = webhook ? !!webhook.only_affects_us : false;
  document.getElementById('whOnlyExploited').checked = webhook ? !!webhook.only_exploited : false;
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
  const only_affects_us = document.getElementById('whOnlyOurs').checked;
  const only_exploited = document.getElementById('whOnlyExploited').checked;
  const wantsProtection = whProtectCheckbox.checked;
  const keyInput = whKeyInput.value;
  if (!name || !url) { alert('Name and webhook URL are required'); return; }

  const isEditing = !!editingWebhookId;
  const body = { name, url, keyword, source_id, min_severity, allow_insecure_tls, only_affects_us, only_exploited };
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
    document.getElementById('whOnlyOurs').checked = false;
    document.getElementById('whOnlyExploited').checked = false;
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
  // The sign-in page isn't a visit: signing in (which reloads the page)
  // must not mark everything as already seen.
  if (document.body.classList.contains('signed-out') || document.body.classList.contains('booting')) return;
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
  renderStackBanner(ov);
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
  setNavCount('navNewCount', adjustedNewCount(ov.new_since, ov.since));
  if (ov.affects_us) setNavCount('navAffectsCount', ov.affects_us.items);
  if (ov.exploited) setNavCount('navExploitedCount', ov.exploited.items);
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
// 0.8.0: opening an item marks just that item read, at once. `read` holds
// items opened after the time mark (so they stop counting as new);
// `unread` holds items marked unread again from before it. Both are small:
// entries the time mark already covers are pruned.
const READ_ITEMS_KEY = 'pantomath-read-items';
let readState = loadReadState();
function loadReadState() {
  try {
    const stored = JSON.parse(localStorage.getItem(READ_ITEMS_KEY) || '{}');
    return { read: stored.read || {}, unread: stored.unread || {} };
  } catch (e) {
    return { read: {}, unread: {} };
  }
}
function saveReadState() {
  const since = unreadSince();
  const keep = (map, test) => Object.fromEntries(Object.entries(map).filter(([, ts]) => test(ts)).sort((x, y) => y[1] - x[1]).slice(0, 3000));
  readState = { read: keep(readState.read, ts => ts > since), unread: keep(readState.unread, ts => ts <= since) };
  try { localStorage.setItem(READ_ITEMS_KEY, JSON.stringify(readState)); } catch (e) { /* not remembered */ }
}
function isUnread(item) {
  if (readState.unread[item.id]) return true;
  if (readState.read[item.id]) return false;
  return item.fetched_at > unreadSince();
}
function adjustedNewCount(serverCount, since) {
  const mark = since || unreadSince();
  let count = serverCount || 0;
  Object.values(readState.read).forEach(ts => { if (ts > mark) count -= 1; });
  Object.values(readState.unread).forEach(ts => { if (ts <= mark) count += 1; });
  return Math.max(0, count);
}
function setItemRead(item, read) {
  if (isUnread(item) === !read) return;
  delete readState.read[item.id];
  delete readState.unread[item.id];
  if (read && item.fetched_at > unreadSince()) readState.read[item.id] = item.fetched_at;
  if (!read && item.fetched_at <= unreadSince()) readState.unread[item.id] = item.fetched_at;
  saveReadState();
  applyReadState();
}
// Everything that shows "new" catches up without a refresh; rows keep
// their place so the list doesn't move under the pointer.
function applyReadState() {
  const all = Object.values(FEED_PANELS).flatMap(p => p.items);
  document.querySelectorAll('.feed-row[data-id]').forEach(row => {
    const item = all.find(i => i.id === row.dataset.id);
    if (item) row.classList.toggle('unread', isUnread(item));
  });
  document.querySelectorAll('.detail-panel [data-role="read-toggle"]').forEach(btn => {
    const item = all.find(i => i.id === btn.dataset.id);
    if (item) btn.textContent = isUnread(item) ? 'Mark as read' : 'Mark as unread';
  });
  if (lastOverviewData) updateShellIndicators(lastOverviewData);
  updateLiveSubtitle();
  const view = currentView();
  if (FEED_PAGES[view]) renderFeedStats(FEED_PAGES[view].key + 'Stats', FEED_PAGES[view].allItems, FEED_PAGES[view].fourth);
  if (view === 'dashboard') VIEW_LOADERS.dashboard();
}
window.addEventListener('storage', (e) => {
  if (e.key === READ_ITEMS_KEY || e.key === READ_MARK_KEY) {
    readState = loadReadState();
    applyReadState();
  }
});

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
  readState = { read: {}, unread: {} };
  saveReadState();
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
  const filtered = liveSearchTerm || liveSeverities.size < 4 || liveDateFrom || liveDateTo || liveSourceId || liveCategory || liveOnlyOurs || liveOnlyExploited;
  const newCount = livePanel.items.filter(isUnread).length;
  document.getElementById('liveSubtitle').textContent =
    `${liveTotal} item${liveTotal === 1 ? '' : 's'}${filtered ? ' match these filters' : ''}, newest arrivals first. ` +
    (newCount ? `${newCount} new on this page since ${fmtClock(unreadSince())}.` : 'Nothing new on this page.');
}

function whyHtml(i) {
  const reasons = i.priority_reasons || [];
  if (!reasons.length) return '';
  const kind = r => (r.startsWith('Exploited') ? ' exploited' : r.startsWith('Affects us') ? ' ours' : '');
  return `<div class="why"><span class="why-label">Why ${escapeHtml(i.severity.charAt(0).toUpperCase() + i.severity.slice(1))}:</span>${reasons.map(r => `<span class="why-chip${kind(r)}">${escapeHtml(r)}</span>`).join('')}</div>`;
}

function flagsHtml(i) {
  const exploited = i.kev_cves && i.kev_cves.length
    ? `<span class="flag flag-exploited" title="${escapeAttr(i.kev_cves.join(', '))} on CISA's Known Exploited Vulnerabilities list">Exploited</span>` : '';
  const ours = i.watch_hits && i.watch_hits.length
    ? `<span class="flag flag-ours" title="Affects us: ${escapeAttr(i.watch_hits.join(', '))}">Affects us</span>` : '';
  return exploited + ours;
}

function feedRowHtml(panel, i, unread) {
  const chip = i.cves[0] || i.ips[0] || (i.hashes[0] ? i.hashes[0].slice(0, 12) + '…' : '') || i.emails[0] || '';
  const total = i.cves.length + i.ips.length + i.hashes.length + i.emails.length;
  const saved = !!i.bookmarked;
  return `<div class="feed-row${unread ? ' unread' : ''}${i.id === panel.selectedId ? ' selected' : ''}" data-id="${escapeAttr(i.id)}" role="listitem">
    <span class="unread-dot" aria-label="${unread ? 'New' : ''}"></span>
    <span class="sev-pill sev-${escapeAttr(i.severity)}" title="${escapeAttr((i.priority_reasons || []).join('. '))}">${escapeHtml(i.severity)}</span>
    <div class="feed-row-main">
      <div class="feed-row-headline">${flagsHtml(i)}<button type="button" class="feed-row-title">${escapeHtml(i.title)}</button></div>
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
    const unread = isUnread(i);
    if (anyUnread && i.fetched_at <= since && !earlierShown) { parts.push('<div class="feed-divider">Earlier</div>'); earlierShown = true; }
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
    ${whyHtml(i)}
    ${i.kev_cves.length ? `<div class="detail-flags">
      ${i.kev_cves.length ? `<div class="flag-box exploited">
        <strong>Exploited in the wild</strong>
        <span>${escapeHtml(i.kev_cves.join(', '))} ${i.kev_cves.length === 1 ? 'is' : 'are'} on CISA's Known Exploited Vulnerabilities list.</span>
        <span class="flag-box-detail" data-role="kev"></span>
      </div>` : ''}
    </div>` : ''}
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
        <div class="ioc-line${i.kev_cves.includes(v) ? ' exploited' : ''}"${i.kev_cves.includes(v) ? ' title="On CISA\'s Known Exploited Vulnerabilities list"' : ''}>
          <span class="ioc-type">${label}</span>
          <button type="button" class="ioc-value" data-ioc-type="${type}" data-ioc-value="${escapeAttr(v)}" title="Show every item mentioning this">${escapeHtml(v)}</button>
          <button type="button" class="row-icon" data-copy="${escapeAttr(v)}" aria-label="Copy ${escapeAttr(v)}">${COPY_ICON}</button>
        </div>`).join('') : '<p class="muted">No CVEs, IP addresses, hashes or emails were found in this item.</p>'}
    </section>
    <section class="detail-section" data-role="related"></section>
    <div class="detail-actions">
      <a class="btn btn-primary" href="${safeHref(i.link)}" target="_blank" rel="noopener">Open original &#8599;</a>
      <button type="button" class="btn" data-role="save">${i.bookmarked ? '&#9733; Saved' : '&#9734; Save'}</button>
      <button type="button" class="btn" data-role="read-toggle" data-id="${escapeAttr(i.id)}">Mark as unread</button>
    </div>`;
  el.querySelector('[data-role="close"]').onclick = () => closeFeedDetail(panel);
  el.querySelector('[data-role="save"]').onclick = () => toggleFeedBookmark(panel, i);
  el.querySelector('[data-role="read-toggle"]').onclick = () => setItemRead(i, isUnread(i));
  el.querySelector('.detail-actions a').addEventListener('click', () => setItemRead(i, true));
  if (!force) setItemRead(i, true);  // opening an item is reading it (a re-render isn't)
  const copyAll = el.querySelector('[data-role="copy-all"]');
  if (copyAll) copyAll.onclick = () => copyText(indicators.map(x => x[2]).join('\n'), `${indicators.length} indicator${indicators.length === 1 ? '' : 's'}`);
  el.querySelectorAll('[data-copy]').forEach(btn => { btn.onclick = () => copyText(btn.dataset.copy, btn.dataset.copy); });
  el.querySelectorAll('.ioc-value').forEach(btn => {
    btn.onclick = () => openMention({ cve: 'cves', ip: 'ips', hash: 'hashes', email: 'emails' }[btn.dataset.iocType], btn.dataset.iocValue);
  });
  loadRelated(panel, i);
  if (i.kev_cves.length) loadKevDetail(panel, i);
}

async function loadKevDetail(panel, i) {
  const entries = await (await fetch('/api/kev?cves=' + encodeURIComponent(i.kev_cves.join(',')))).json();
  if (panel.shownId !== i.id) return;
  const el = document.getElementById(panel.detailId).querySelector('[data-role="kev"]');
  const day = d => (d ? new Date(d + 'T00:00:00').toLocaleDateString([], { day: 'numeric', month: 'short', year: 'numeric' }) : '?');
  el.textContent = entries.map(e => `${e.cve}${e.name ? `, ${e.name}` : ''}: added ${day(e.date_added)}, CISA deadline ${day(e.due_date)}${e.ransomware === 'Known' ? ', used in ransomware campaigns' : ''}.`).join(' ');
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
  if (field === 'watch_hits') {
    const cfg = FEED_PAGES['affects-us'];
    document.getElementById('oursFilter').value = value;
    cfg.filterText = value.toLowerCase();
    navigateTo('affects-us');
    return;
  }
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
  'affects-us': {
    key: 'ours', list: 'feedOurs', mentions: ['watch_hits', 'cves', 'actors'], fourth: 'exploited',
    fetch: () => fetchItems({ limit: FEED_PAGE_LIMIT, affects_us: true }),
    empty: () => (lastOverviewData && lastOverviewData.affects_us && lastOverviewData.affects_us.watchlist
      ? { title: 'Nothing mentions our stack yet', hint: 'Items that name something on Our stack will appear here.' }
      : { title: 'Tell Pantomath what you run', hint: 'Add your vendors and products under Settings, Our stack. Stored items are checked straight away.' }),
  },
  exploited: {
    key: 'exploited', list: 'feedExploited', mentions: ['cves', 'vendors', 'watch_hits'], fourth: 'ours',
    fetch: () => fetchItems({ limit: FEED_PAGE_LIMIT, exploited: true }),
    empty: () => {
      const x = lastOverviewData && lastOverviewData.exploited;
      if (x && !x.enabled) return { title: 'The KEV catalog is turned off', hint: 'Turn it on under Settings, Exploited vulnerabilities.' };
      if (x && !x.catalog) return { title: 'No catalog downloaded yet', hint: 'Settings, Exploited vulnerabilities shows whether the download worked.' };
      return { title: 'No exploited vulnerabilities mentioned', hint: "Items that mention a CVE on CISA's list will appear here." };
    },
  },
  critical: {
    key: 'critical', list: 'feedCritical', mentions: ['watch_hits', 'cves', 'vendors', 'actors'], fourth: 'critical',
    fetch: () => fetchItems({ limit: FEED_PAGE_LIMIT, severity: 'critical,high' }),
    empty: { title: 'Nothing critical or high', hint: 'Items with Critical or High priority will appear here.' },
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
    cfg.filterText ? { title: 'Nothing matches the filter', hint: 'Clear the filter to see every item.' }
      : (typeof cfg.empty === 'function' ? cfg.empty() : cfg.empty)
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
  return [i.title, i.source_name, stripHtml(i.summary || ''), ...i.cves, ...i.ips, ...i.hashes, ...i.vendors, ...i.actors, ...(i.watch_hits || [])]
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
  const unread = items.filter(isUnread).length;
  const capped = items.length >= FEED_PAGE_LIMIT;
  const cells = [
    first || { label: 'Items', value: capped ? `${FEED_PAGE_LIMIT}+` : items.length, note: capped ? `showing the newest ${FEED_PAGE_LIMIT}` : 'newest arrivals first' },
    { label: 'New since you last looked', value: unread, tone: unread ? 'signal' : '', note: unread ? `since ${fmtClock(since)}` : 'nothing new' },
    { label: 'Published in the last 24 hours', value: items.filter(i => effectiveTs(i) >= dayAgo).length, note: 'by published date' },
    {
      cve: { label: 'Mention a CVE', value: items.filter(i => i.cves.length).length, note: `${new Set(items.flatMap(i => i.cves)).size} distinct CVEs` },
      exploited: { label: 'Exploited', value: items.filter(i => i.kev_cves.length).length, tone: 'high', note: "on CISA's KEV list" },
      ours: { label: 'Affect our stack', value: items.filter(i => i.watch_hits.length).length, tone: 'signal', note: `of ${items.length} shown` },
      critical: { label: 'Critical', value: items.filter(i => i.severity === 'critical').length, tone: 'critical', note: 'our stack, exploited or serious' },
    }[fourth] || { label: 'Critical or high', value: items.filter(i => i.severity === 'critical' || i.severity === 'high').length, tone: 'high', note: `of ${items.length} shown` },
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
  vendors: 'Open this vendor', actors: 'Open this threat actor', watch_hits: 'Show only items that mention this',
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

// One section at a time; the last one opened is remembered in this browser.
const SETTINGS_TAB_KEY = 'pantomath-settings-tab';
const SETTINGS_TAB_LOADERS = { 'set-stack': () => loadStackSettings(), 'set-kev': () => loadKevSettings() };
function showSettingsTab(id) {
  if (!document.getElementById(id)) id = 'set-collection';
  document.querySelectorAll('.settings-main > .settings-card').forEach(c => c.classList.toggle('active', c.id === id));
  document.querySelectorAll('.settings-nav button').forEach(b => {
    const on = b.dataset.target === id;
    b.classList.toggle('active', on);
    if (on) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current');
  });
  try { localStorage.setItem(SETTINGS_TAB_KEY, id); } catch (e) { /* not remembered */ }
  if (currentView() === 'settings') SETTINGS_TAB_LOADERS[id]?.();
}
function openSettingsTab(id) {
  try { localStorage.setItem(SETTINGS_TAB_KEY, id); } catch (e) { /* not remembered */ }
  showSettingsTab(id);
  navigateTo('settings');
}
function refreshActiveSettingsTab() {
  const active = document.querySelector('.settings-main > .settings-card.active');
  if (active) SETTINGS_TAB_LOADERS[active.id]?.();
}
document.querySelectorAll('.settings-nav button').forEach(btn => {
  btn.addEventListener('click', () => showSettingsTab(btn.dataset.target));
});
(function restoreSettingsTab() {
  let saved = null;
  try { saved = localStorage.getItem(SETTINGS_TAB_KEY); } catch (e) { /* default */ }
  showSettingsTab(saved || 'set-collection');
})();

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
      <span role="columnheader">Highest priority</span><span role="columnheader">First seen</span><span role="columnheader">Last seen</span><span></span>
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
  const max = Math.max(1, ...days.map(d => d.critical + d.high + d.medium + d.low));
  const width = days.length * 10;
  const barWidth = days.length > 120 ? 9 : 7;
  const inset = (10 - barWidth) / 2;
  const label = d => new Date(d.date + 'T12:00:00').toLocaleDateString([], { day: 'numeric', month: 'short' });
  const bars = days.map((d, idx) => {
    let y = 100;
    const segments = [['low', d.low], ['medium', d.medium], ['high', d.high], ['critical', d.critical]].map(([sev, n]) => {
      if (!n) return '';
      const h = (n / max) * 98;
      y -= h;
      return `<rect class="bar-${sev}" x="${idx * 10 + inset}" y="${y.toFixed(2)}" width="${barWidth}" height="${h.toFixed(2)}"></rect>`;
    }).join('');
    const total = d.critical + d.high + d.medium + d.low;
    return `<g><title>${escapeHtml(label(d))}: ${total} published (${d.critical} critical, ${d.high} high, ${d.medium} medium, ${d.low} low)</title>` +
      `<rect x="${idx * 10}" y="0" width="10" height="100" fill="transparent"></rect>${segments}</g>`;
  }).join('');
  const total = days.reduce((sum, d) => sum + d.critical + d.high + d.medium + d.low, 0);
  el.innerHTML = `<div class="an-ymax">Busiest day: ${max} item${max === 1 ? '' : 's'}</div>
    <svg viewBox="0 0 ${width} 100" preserveAspectRatio="none" role="img" aria-label="${total} items published over ${days.length} days">${bars}</svg>
    <div class="an-axis"><span>${escapeHtml(label(days[0]))}</span><span>${escapeHtml(label(days[Math.floor(days.length / 2)]))}</span><span>Today</span></div>`;
}

function renderSeverityMix(el, t, p, previous) {
  if (!t.items) { el.innerHTML = '<p class="muted">Nothing was published in this period.</p>'; return; }
  const share = n => Math.round((n / t.items) * 100);
  el.innerHTML = `<div class="mix-bar" role="img" aria-label="${share(t.critical)}% critical, ${share(t.high)}% high, ${share(t.medium)}% medium, ${share(t.low)}% low">` +
    ['critical', 'high', 'medium', 'low'].map(s => (t[s] ? `<i class="bar-${s}" style="width:${((t[s] / t.items) * 100).toFixed(2)}%"></i>` : '')).join('') +
    '</div><div class="mix-rows">' + ['critical', 'high', 'medium', 'low'].map(s => {
      const diff = t[s] - p[s];
      const tone = (s === 'high' || s === 'critical') && diff > 0 ? ' worse' : (s === 'high' || s === 'critical') && diff < 0 ? ' better' : '';
      return `<div class="mix-row">
        <span><span class="sev-pill sev-${s}">${s}</span></span>
        <span class="num">${t[s]}<span class="share">${share(t[s])}%</span></span>
        <span class="delta${tone}">${diff === 0 ? 'no change' : `${diff > 0 ? '+' : '−'}${Math.abs(diff)}`} vs ${escapeHtml(previous)}</span>
      </div>`;
    }).join('') + '</div>';
}

function renderTopSources(el, rows, totalItems) {
  if (!rows.length) { el.innerHTML = '<p class="muted">Nothing was published in this period.</p>'; return; }
  el.innerHTML = '<div class="src-rank head"><span>Source</span><span class="num">Items</span><span class="num" title="Critical or high">Crit./high</span><span>Share of all items</span></div>' +
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

// -------------------------------------------------------------- our stack + KEV (0.7.0)

const STACK_RANGE_WORDS = { 24: 'the last 24 hours', 168: 'the last 7 days', 720: 'the last 30 days', 2160: 'the last 90 days' };
function renderStackBanner(ov) {
  const el = document.getElementById('dashStackBanner');
  if (!el || !ov.affects_us) return;
  const ours = ov.affects_us, exploited = ov.exploited || { items: 0 };
  const range = STACK_RANGE_WORDS[ov.hours] || `the last ${ov.hours} hours`;
  let tone, title, text, action = null;
  if (!ours.watchlist) {
    tone = 'setup';
    title = 'Tell Pantomath what you run';
    text = "List your vendors, products and systems, and every item that mentions one is marked Affects us. Exploited vulnerabilities are marked from CISA's catalog.";
    action = ['Set up Our stack', () => openSettingsTab('set-stack')];
  } else if (ours.items) {
    tone = ours.exploited ? 'alert' : 'ours';
    title = `${ours.items} item${ours.items === 1 ? '' : 's'} in ${range} ${ours.items === 1 ? 'affects' : 'affect'} our stack`;
    text = ours.exploited
      ? `${ours.exploited} of them ${ours.exploited === 1 ? 'mentions a vulnerability' : 'mention vulnerabilities'} being exploited in real attacks.`
      : "None of them mention a CVE on CISA's exploited list.";
    action = ['View', () => navigateTo('affects-us')];
  } else {
    tone = 'calm';
    title = `Nothing in ${range} mentions our stack`;
    text = exploited.items
      ? `${exploited.items} other item${exploited.items === 1 ? '' : 's'} mention an exploited vulnerability.`
      : `Watching ${ours.watchlist} entr${ours.watchlist === 1 ? 'y' : 'ies'} on Our stack.`;
    if (exploited.items) action = ['View exploited', () => navigateTo('exploited')];
  }
  el.className = `stack-banner tone-${tone}`;
  el.hidden = false;
  el.innerHTML = `<span class="stack-banner-icon" aria-hidden="true"></span>
    <div class="stack-banner-text"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(text)}</span></div>
    ${action ? `<button type="button" class="btn ${tone === 'alert' ? 'btn-danger' : 'btn-primary'}" data-role="go">${escapeHtml(action[0])}</button>` : ''}`;
  if (action) el.querySelector('[data-role="go"]').onclick = action[1];
}

document.getElementById('liveOnlyOurs').addEventListener('click', (e) => {
  liveOnlyOurs = !liveOnlyOurs;
  e.currentTarget.setAttribute('aria-pressed', String(liveOnlyOurs));
  loadLiveFeed(1);
});
document.getElementById('liveOnlyExploited').addEventListener('click', (e) => {
  liveOnlyExploited = !liveOnlyExploited;
  e.currentTarget.setAttribute('aria-pressed', String(liveOnlyExploited));
  loadLiveFeed(1);
});

let stackEditingId = null;
function setStackResult(text, isError = false) {
  const el = document.getElementById('stackResult');
  el.textContent = text;
  el.classList.toggle('error', isError);
}
function resetStackForm() {
  stackEditingId = null;
  document.getElementById('stackName').value = '';
  document.getElementById('stackAliases').value = '';
  document.getElementById('stackSaveBtn').textContent = 'Add';
  document.getElementById('stackCancelBtn').hidden = true;
  document.querySelectorAll('.stack-row.editing').forEach(r => r.classList.remove('editing'));
}

async function loadStackSettings() {
  const res = await fetch('/api/watchlist');
  if (!res.ok) return;
  const entries = await res.json();
  const list = document.getElementById('stackList');
  list.innerHTML = entries.length
    ? '<div class="stack-row stack-head"><span>Name</span><span>Also matches</span><span class="num">Items</span><span></span></div>' +
      entries.map(e => `<div class="stack-row${e.id === stackEditingId ? ' editing' : ''}" data-id="${escapeAttr(e.id)}">
        <span class="stack-name">${escapeHtml(e.name)}</span>
        <span class="stack-aliases">${e.aliases ? escapeHtml(e.aliases.split(',').join(', ')) : '<span class="muted">—</span>'}</span>
        <span class="num" title="Stored items that mention it">${e.items}</span>
        <span class="stack-actions">
          <button type="button" class="row-icon" data-action="edit" aria-label="Edit ${escapeAttr(e.name)}" title="Edit">${EDIT_ICON}</button>
          <button type="button" class="row-icon danger" data-action="delete" aria-label="Remove ${escapeAttr(e.name)}" title="Remove">${TRASH_ICON}</button>
        </span>
      </div>`).join('')
    : '<div class="card-empty"><strong>Nothing on the list yet</strong>Add what you run: firewalls, switches and routers, hypervisors, storage, remote access, UPS and cooling management, and the software on top.</div>';
  list.querySelectorAll('[data-action="edit"]').forEach(btn => {
    btn.onclick = () => {
      const entry = entries.find(e => e.id === btn.closest('.stack-row').dataset.id);
      stackEditingId = entry.id;
      document.getElementById('stackName').value = entry.name;
      document.getElementById('stackAliases').value = entry.aliases ? entry.aliases.split(',').join(', ') : '';
      document.getElementById('stackSaveBtn').textContent = 'Save changes';
      document.getElementById('stackCancelBtn').hidden = false;
      list.querySelectorAll('.stack-row').forEach(r => r.classList.toggle('editing', r.dataset.id === entry.id));
      document.getElementById('stackName').focus();
    };
  });
  list.querySelectorAll('[data-action="delete"]').forEach(btn => {
    btn.onclick = async () => {
      const entry = entries.find(e => e.id === btn.closest('.stack-row').dataset.id);
      if (!confirm(`Remove "${entry.name}" from Our stack? Items that only matched it lose the Affects us mark.`)) return;
      const r = await fetch('/api/watchlist/' + entry.id, { method: 'DELETE' });
      if (r.ok) {
        if (stackEditingId === entry.id) resetStackForm();
        const out = await r.json();
        setStackResult(`Removed. ${out.items_marked} stored item${out.items_marked === 1 ? '' : 's'} now affect our stack.`);
        loadStackSettings();
        refreshShell();
      }
    };
  });
  loadStackSuggestions(entries);
}

async function loadStackSuggestions(entries) {
  const el = document.getElementById('stackSuggest');
  const tags = await (await fetch('/api/tags?type=vendor&limit=40')).json();
  const have = new Set(entries.flatMap(e => [e.name, ...(e.aliases ? e.aliases.split(',') : [])]).map(x => x.toLowerCase()));
  const picks = tags.filter(t => !have.has(t.name.toLowerCase())).slice(0, 12);
  el.innerHTML = picks.length
    ? '<span class="muted">Vendors named in your items:</span>' + picks.map(t => `<button type="button" class="mention-chip" data-name="${escapeAttr(t.name)}" title="Put this name in the form">+ ${escapeHtml(t.name)}<span class="count">${t.count}</span></button>`).join('')
    : '';
  el.querySelectorAll('[data-name]').forEach(chip => {
    chip.onclick = () => {
      resetStackForm();
      document.getElementById('stackName').value = chip.dataset.name;
      document.getElementById('stackAliases').focus();
    };
  });
}

async function saveStackEntry() {
  const name = document.getElementById('stackName').value.trim();
  const aliases = document.getElementById('stackAliases').value;
  if (!name) { setStackResult('Give the entry a name.', true); document.getElementById('stackName').focus(); return; }
  const btn = document.getElementById('stackSaveBtn');
  btn.disabled = true;
  const res = await fetch(stackEditingId ? '/api/watchlist/' + stackEditingId : '/api/watchlist', {
    method: stackEditingId ? 'PATCH' : 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, aliases }),
  });
  btn.disabled = false;
  const out = await res.json().catch(() => ({}));
  if (!res.ok) { setStackResult(out.detail || "Couldn't save that entry.", true); return; }
  setStackResult(`Saved. ${out.items_marked} stored item${out.items_marked === 1 ? '' : 's'} now affect our stack.`);
  resetStackForm();
  loadStackSettings();
  refreshShell();
}
document.getElementById('stackSaveBtn').addEventListener('click', saveStackEntry);
document.getElementById('stackCancelBtn').addEventListener('click', () => { resetStackForm(); setStackResult(''); });
['stackName', 'stackAliases'].forEach(id => document.getElementById(id).addEventListener('keydown', (e) => {
  if (e.key === 'Enter') { e.preventDefault(); saveStackEntry(); }
}));

async function loadKevSettings(status = null) {
  if (!status) {
    const res = await fetch('/api/kev/status');
    if (!res.ok) return;
    status = await res.json();
  }
  document.getElementById('kevToggle').classList.toggle('on', status.enabled);
  document.getElementById('kevStatusLabel').textContent = status.count
    ? `${status.count.toLocaleString()} exploited vulnerabilities in the catalog`
    : 'No catalog downloaded yet';
  const hint = document.getElementById('kevStatusHint');
  hint.classList.toggle('error', !!status.error);
  if (status.error) {
    hint.textContent = `The last update failed ${timeAgo(status.checked_at)}: ${status.error}.` +
      (status.count ? ` Still using the copy from ${timeAgo(status.updated_at)}.` : '');
  } else if (status.updated_at) {
    hint.textContent = `Updated ${timeAgo(status.updated_at)}. ${status.enabled ? 'Checked again once a day.' : 'Automatic updates are off.'}`;
  } else {
    hint.textContent = status.enabled ? 'The first download starts a few minutes after Pantomath starts, or press Update now.' : 'Turned off.';
  }
  const url = document.getElementById('kevUrl');
  if (document.activeElement !== url) url.value = status.url || '';
  url.placeholder = status.default_url;
}

document.getElementById('kevToggle').addEventListener('click', async (e) => {
  const next = !e.currentTarget.classList.contains('on');
  const res = await fetch('/api/kev/settings', {
    method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled: next }),
  });
  if (!res.ok) return;
  const status = await res.json();
  loadKevSettings(status);
  refreshShell();
  if (next && !status.count) document.getElementById('kevRefreshBtn').click();
});
document.getElementById('kevRefreshBtn').addEventListener('click', async (e) => {
  const btn = e.currentTarget;
  btn.disabled = true;
  btn.textContent = 'Updating…';
  const res = await fetch('/api/kev/refresh', { method: 'POST' });
  btn.disabled = false;
  btn.textContent = 'Update now';
  if (!res.ok) return;
  const status = await res.json();
  loadKevSettings(status);
  showToast(status.error ? 'The update failed. See the reason under the switch.' : 'Catalog updated');
  refreshShell();
});
document.getElementById('kevUrlSaveBtn').addEventListener('click', async () => {
  const out = document.getElementById('kevUrlResult');
  const res = await fetch('/api/kev/settings', {
    method: 'PATCH', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: document.getElementById('kevUrl').value.trim() }),
  });
  const body = await res.json().catch(() => ({}));
  out.classList.toggle('error', !res.ok);
  if (!res.ok) { out.textContent = body.detail || "Couldn't save the address."; return; }
  out.textContent = body.url ? 'Saved. Press Update now to download from this address.' : "Saved. Using CISA's official feed.";
  loadKevSettings(body);
});

// -------------------------------------------------------------- sign-in (0.8.0)

let authStatus = null;
let signinMode = 'login';
const EYE_ICON = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>';
const EYE_OFF_ICON = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 3l18 18"/><path d="M10.6 5.1A10.8 10.8 0 0 1 12 5c6.4 0 10 7 10 7a17.6 17.6 0 0 1-3.2 4.2M6.6 6.6A17.4 17.4 0 0 0 2 12s3.6 7 10 7a9.9 9.9 0 0 0 5.4-1.6"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/></svg>';

async function fetchAuthStatus() {
  try {
    const res = await fetch('/api/auth/status');
    return res.ok ? await res.json() : null;
  } catch (e) {
    return null;
  }
}

function signinError(message, field = 'password') {
  const el = document.getElementById('signinError');
  el.textContent = message || '';
  el.hidden = !message;
  document.getElementById('signinPasswordBox').classList.toggle('invalid', !!message && field === 'password');
  document.getElementById('signinCodeBox').classList.toggle('invalid', !!message && field === 'code');
  if (message) {
    const card = document.getElementById('signinCard');
    card.classList.remove('shake');
    void card.offsetWidth;  // restart the animation
    card.classList.add('shake');
  }
}

function setSigninBusy(busy, label) {
  const btn = document.getElementById('signinSubmit');
  btn.disabled = busy;
  btn.innerHTML = busy ? `<span class="spinner" aria-hidden="true"></span>${escapeHtml(label)}` : escapeHtml(label);
}

function showSignIn(status, reason = null) {
  if (status) authStatus = status;
  document.body.classList.remove('booting');
  document.body.classList.add('signed-out');
  document.getElementById('signin').hidden = false;
  setSigninMode((authStatus || {}).setup_needed ? 'setup' : 'login', reason);
}

// Three modes on one card: first-run setup (needs the setup code from the
// server), sign in, and reset with the recovery code.
const SIGNIN_MODES = {
  setup: {
    title: 'Welcome to Pantomath', button: 'Create and sign in', remember: true,
    sub: 'Create the Settings password. It manages sources and settings, and signs you in until you add a team password for everyone else.',
    code: 'Setup code', codeHint: 'Printed at the end of the installation. Show it again on the server with <code>sudo pantomath-admin setup-code</code>.',
    password: 'New Settings password (at least 8 characters)', confirm: true, link: null,
  },
  login: {
    title: 'Sign in', button: 'Sign in', remember: false,
    code: null, password: 'Password', confirm: false, link: 'Forgot the Settings password?',
  },
  recover: {
    title: 'Reset the Settings password', button: 'Reset and sign in', remember: false,
    sub: 'Enter the recovery code you saved when Pantomath was set up. It works once, and you get a new one straight away.',
    code: 'Recovery code', codeHint: 'Lost that too? On the server, run <code>sudo pantomath-admin reset-settings-password</code>.',
    password: 'New Settings password (at least 8 characters)', confirm: true, link: 'Back to sign in',
  },
};

function setSigninMode(mode, reason = null) {
  const st = authStatus || {};
  const m = SIGNIN_MODES[mode];
  signinMode = mode;
  document.getElementById('signinForm').hidden = false;
  document.getElementById('signinRecovery').hidden = true;
  document.getElementById('signinTitle').textContent = m.title;
  document.getElementById('signinSub').textContent = m.sub
    || (reason === 'expired' ? 'Your session has ended. Sign in again to carry on where you were.'
      : st.team_password ? 'Use the team password. Administrators can use the Settings password.'
      : 'Pantomath now asks everyone to sign in. Until a team password is added in Settings, use the Settings password.');
  document.getElementById('signinCodeField').hidden = !m.code;
  if (m.code) {
    document.getElementById('signinCodeLabel').textContent = m.code;
    document.getElementById('signinCodeHint').innerHTML = m.codeHint;
    document.getElementById('signinCode').value = '';
  }
  document.getElementById('signinPasswordLabel').textContent = m.password;
  document.getElementById('signinPassword').autocomplete = m.confirm ? 'new-password' : 'current-password';
  document.getElementById('signinPassword').value = '';
  document.getElementById('signinConfirm').value = '';
  document.getElementById('signinConfirmField').hidden = !m.confirm;
  document.getElementById('signinRemember').checked = m.remember;
  const link = document.getElementById('signinModeLink');
  link.hidden = !m.link;
  if (m.link) link.textContent = m.link;
  setSigninBusy(false, m.button);
  signinError('');
  setTimeout(() => document.getElementById(m.code ? 'signinCode' : 'signinPassword').focus(), 60);
}
document.getElementById('signinModeLink').addEventListener('click', () => setSigninMode(signinMode === 'recover' ? 'login' : 'recover'));

document.querySelectorAll('.signin-reveal').forEach(btn => {
  btn.addEventListener('click', () => {
    const input = document.getElementById(btn.dataset.for);
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    btn.setAttribute('aria-pressed', String(show));
    btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
    btn.innerHTML = show ? EYE_OFF_ICON : EYE_ICON;
    input.focus();
  });
});
document.getElementById('signinPassword').addEventListener('input', () => {
  if (!document.getElementById('signinError').hidden) signinError('');
});

document.getElementById('signinForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const m = SIGNIN_MODES[signinMode];
  const code = document.getElementById('signinCode').value.trim();
  const password = document.getElementById('signinPassword').value;
  const remember = document.getElementById('signinRemember').checked;
  if (m.code && !code) { signinError(`Enter the ${m.code.toLowerCase()}.`, 'code'); document.getElementById('signinCode').focus(); return; }
  if (!password) { signinError('Enter the password.'); return; }
  if (m.confirm && password.length < 8) { signinError('Use at least 8 characters.'); return; }
  if (m.confirm && password !== document.getElementById('signinConfirm').value) { signinError("The two passwords don't match."); return; }
  const request = {
    setup: ['/api/auth/setup', { password, setup_code: code, remember }],
    login: ['/api/auth/login', { password, remember }],
    recover: ['/api/auth/recover', { recovery_code: code, new_password: password, remember }],
  }[signinMode];
  setSigninBusy(true, { setup: 'Setting up…', login: 'Signing in…', recover: 'Resetting…' }[signinMode]);
  let res;
  try {
    res = await fetch(request[0], { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(request[1]) });
  } catch (err) {
    setSigninBusy(false, m.button);
    signinError("Pantomath can't be reached. Check the connection and try again.");
    return;
  }
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 409) { showSignIn(await fetchAuthStatus()); signinError(body.detail || ''); return; }
    setSigninBusy(false, m.button);
    signinError(body.detail || 'That didn’t work. Try again.', /code/i.test(body.detail || '') ? 'code' : 'password');
    return;
  }
  if (body.settings_token) setSettingsToken(body.settings_token);
  if (body.recovery_code) {
    document.getElementById('signinForm').hidden = true;
    document.getElementById('signinRecovery').hidden = false;
    document.getElementById('signinRecoveryTitle').textContent = signinMode === 'recover' ? 'Save your new recovery code' : 'Save your recovery code';
    document.getElementById('signinRecoveryCode').textContent = body.recovery_code;
    return;
  }
  setSigninBusy(true, 'Signed in');
  location.reload();
});
document.getElementById('signinCopyCode').addEventListener('click', () => copyText(document.getElementById('signinRecoveryCode').textContent, 'the recovery code'));
document.getElementById('signinSaved').addEventListener('change', (e) => { document.getElementById('signinContinue').disabled = !e.target.checked; });
document.getElementById('signinContinue').addEventListener('click', () => location.reload());

document.getElementById('signOutBtn').addEventListener('click', async () => {
  await fetch('/api/auth/logout', { method: 'POST' }).catch(() => {});
  setSettingsToken(null);
  location.reload();
});

// -------------------------------------------------------------- settings: security (0.8.0)

const DEVICE_ICON = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/></svg>';
const PHONE_ICON = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="7" y="2.5" width="10" height="19" rx="2"/><path d="M11 18h2"/></svg>';
const KEY_ICON = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="8" cy="15" r="4"/><path d="M10.8 12.2L20 3M16 7l3 3M14 9l2 2"/></svg>';

async function loadSecuritySettings() {
  const [statusRes, sessionsRes] = await Promise.all([fetch('/api/auth/status'), fetch('/api/auth/sessions')]);
  if (!sessionsRes.ok) return;
  const status = await statusRes.json();
  const { devices, api_keys: keys } = await sessionsRes.json();
  document.getElementById('teamPwHint').textContent = status.team_password
    ? "Set. People sign in with it to view Pantomath; it can't change settings."
    : 'Not set, so only the Settings password can sign in, and everyone who views Pantomath can also change it. Set a team password for viewers.';
  document.getElementById('teamPwBtn').textContent = status.team_password ? 'Change' : 'Set team password';
  document.getElementById('teamPwRemove').hidden = !status.team_password;

  document.getElementById('deviceList').innerHTML = devices.map(d => {
    const phone = /iPhone|Android|iPad/.test(d.label);
    const via = d.role === 'admin' ? 'Settings password' : 'team password';
    return `<div class="device-row">
      <span class="device-icon">${phone ? PHONE_ICON : DEVICE_ICON}</span>
      <div><div class="device-name">${escapeHtml(d.label || 'Browser')}${d.current ? '<span class="badge-current">This device</span>' : ''}</div>
        <div class="device-sub">Signed in with the ${via}, ${d.remember ? 'remembered for 90 days' : 'until the browser closes'}. Active ${escapeHtml(timeAgo(d.last_seen))}${d.ip ? `, from ${escapeHtml(d.ip)}` : ''}.</div></div>
      <button type="button" class="btn btn-sm" data-revoke="${escapeAttr(d.id)}" data-current="${d.current ? 1 : 0}">Sign out</button>
    </div>`;
  }).join('');
  document.getElementById('apiKeyList').innerHTML = keys.map(k => `<div class="device-row">
      <span class="device-icon">${KEY_ICON}</span>
      <div><div class="device-name">${escapeHtml(k.label)}</div>
        <div class="device-sub">Created ${escapeHtml(timeAgo(k.created_at))}, last used ${escapeHtml(timeAgo(k.last_seen))}.</div></div>
      <button type="button" class="btn btn-sm" data-revoke="${escapeAttr(k.id)}">Revoke</button>
    </div>`).join('');
  document.querySelectorAll('#deviceList [data-revoke], #apiKeyList [data-revoke]').forEach(btn => {
    btn.onclick = async () => {
      const own = btn.dataset.current === '1';
      if (own && !confirm('Sign out this device?')) return;
      await fetch('/api/auth/sessions/' + btn.dataset.revoke, { method: 'DELETE' });
      if (own) { setSettingsToken(null); location.reload(); return; }
      loadSecuritySettings();
    };
  });
}
SETTINGS_TAB_LOADERS['set-security'] = () => loadSecuritySettings();

function toggleTeamPwForm(open) {
  document.getElementById('teamPwForm').hidden = !open;
  document.getElementById('teamPw1').value = '';
  document.getElementById('teamPw2').value = '';
  if (open) document.getElementById('teamPw1').focus();
}
document.getElementById('teamPwBtn').addEventListener('click', () => { document.getElementById('teamPwResult').textContent = ''; toggleTeamPwForm(true); });
document.getElementById('teamPwCancel').addEventListener('click', () => toggleTeamPwForm(false));
document.getElementById('teamPwSave').addEventListener('click', async () => {
  const out = document.getElementById('teamPwResult');
  const pw = document.getElementById('teamPw1').value;
  out.classList.add('error');
  if (pw.length < 8) { out.textContent = 'Use at least 8 characters.'; return; }
  if (pw !== document.getElementById('teamPw2').value) { out.textContent = "The two passwords don't match."; return; }
  const res = await fetch('/api/auth/team-password', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: pw }) });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) { out.textContent = body.detail || "Couldn't save the password."; return; }
  toggleTeamPwForm(false);
  document.getElementById('teamPwForm').hidden = false;
  document.querySelector('#teamPwForm .stack-form').hidden = true;
  out.classList.remove('error');
  out.textContent = 'Saved. Anyone signed in with the previous team password has been signed out.';
  setTimeout(() => { document.getElementById('teamPwForm').hidden = true; document.querySelector('#teamPwForm .stack-form').hidden = false; out.textContent = ''; }, 6000);
  loadSecuritySettings();
});
document.getElementById('teamPwRemove').addEventListener('click', async () => {
  if (!confirm('Remove the team password? Everyone signed in with it is signed out, and only the Settings password can sign in.')) return;
  await fetch('/api/auth/team-password', { method: 'DELETE' });
  loadSecuritySettings();
});
document.getElementById('signOutOthersBtn').addEventListener('click', async () => {
  if (!confirm('Sign out every other device, including wall screens? They will need to sign in again.')) return;
  const res = await fetch('/api/auth/sessions/sign-out-others', { method: 'POST' });
  if (res.ok) { const out = await res.json(); showToast(`Signed out ${out.signed_out} device${out.signed_out === 1 ? '' : 's'}`); }
  loadSecuritySettings();
});
document.getElementById('apiKeyCreateBtn').addEventListener('click', async () => {
  const label = document.getElementById('apiKeyLabel').value.trim();
  const box = document.getElementById('apiKeyNew');
  if (!label) { document.getElementById('apiKeyLabel').focus(); return; }
  const res = await fetch('/api/auth/api-keys', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ label }) });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) { showToast(body.detail || "Couldn't create the key"); return; }
  document.getElementById('apiKeyLabel').value = '';
  box.hidden = false;
  box.innerHTML = `<strong>Key for ${escapeHtml(label)}</strong><code>${escapeHtml(body.key)}</code>
    <button type="button" class="btn btn-sm" id="apiKeyCopy">Copy key</button>
    <span class="muted"> Copy it now: Pantomath keeps only a fingerprint and can't show it again.</span>`;
  document.getElementById('apiKeyCopy').onclick = () => copyText(body.key, 'the API key');
  loadSecuritySettings();
});

function connectWs() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(proto + '//' + location.host + '/ws');
  ws.onopen = () => {
    wsOpen = true;
    wsEverOpened = true;
    renderConnStatus();
  };
  ws.onclose = (event) => {
    wsOpen = false;
    renderConnStatus();
    if (event.code === 4401) { showSignIn(null, 'expired'); return; }  // signed out: stop reconnecting
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
  const status = await fetchAuthStatus();
  if (!status || !status.signed_in) {
    showSignIn(status || {});
    if (!status) signinError("Pantomath can't be reached right now. Check the connection, then sign in.");
    return;
  }
  authStatus = status;
  document.body.classList.remove('booting');
  document.getElementById('signOutBtn').hidden = !!status.open;
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
