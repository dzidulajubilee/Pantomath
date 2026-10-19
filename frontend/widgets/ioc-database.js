// ------------------------------------------------------------ IOC database (1.0.0)
//
// The IOC database tab, its two Settings sections (IOC feeds, Allowlist)
// and SIEM keys in Settings, Security. Loaded after app.js and uses its
// helpers (escapeHtml, escapeAttr, safeHref, timeAgo, fmtFull, copyText,
// showToast, ensureSettingsUnlocked...). Browsing and looking up need only
// sign-in; adding, editing and marking indicators need the Settings
// password, because what's in here ends up in SIEMs and firewalls.

const IOC_TYPES = [
  ['ipv4', 'IPv4'], ['ipv6', 'IPv6'], ['domain', 'Domain'], ['url', 'URL'], ['email', 'Email'],
  ['md5', 'MD5'], ['sha1', 'SHA-1'], ['sha256', 'SHA-256'], ['ja3', 'JA3'], ['ja4', 'JA4'], ['x509', 'Certificate'],
];
const IOC_TYPE_LABEL = Object.fromEntries(IOC_TYPES);
const IOC_TYPE_TABS = [
  ['', 'All', null], ['ip', 'IP', ['ipv4', 'ipv6']], ['domain', 'Domain', ['domain']], ['url', 'URL', ['url']],
  ['hash', 'Hash', ['md5', 'sha1', 'sha256']], ['email', 'Email', ['email']], ['network', 'JA3 / JA4 / cert', ['ja3', 'ja4', 'x509']],
];
const IOC_LIFETIMES = [
  ['0', "Each type's default"], ['7', '7 days after last seen'], ['14', '14 days after last seen'],
  ['30', '30 days after last seen'], ['90', '90 days after last seen'], ['180', '180 days after last seen'],
  ['365', '1 year after last seen'], ['-1', 'Never expires'],
];
const IOC_STATUS_LABEL = { active: 'Active', expired: 'Expired', false_positive: 'False positive', allowlisted: 'Allowlisted' };
const IOCDB_PAGE = 50;

const iocdb = {
  type: '', q: '', status: 'active', minConfidence: 0, malware: '', source: '', page: 1,
  items: [], total: 0, summary: null, selectedId: null, shown: null, editing: false,
};

function fillSelect(id, options, selected) {
  const el = document.getElementById(id);
  el.innerHTML = options.map(([v, label]) => `<option value="${escapeAttr(v)}">${escapeHtml(label)}</option>`).join('');
  if (selected !== undefined) el.value = selected;
}
fillSelect('iocAddType', [['', 'Detect automatically'], ...IOC_TYPES]);
fillSelect('iocFeedType', [['', 'Detect automatically'], ...IOC_TYPES]);
fillSelect('iocAddLifetime', IOC_LIFETIMES);
fillSelect('iocFeedLifetime', IOC_LIFETIMES);

function fmtNumber(n) {
  return Number(n || 0).toLocaleString();
}
function plural(n, one, many) {
  return `${fmtNumber(n)} ${n === 1 ? one : many || one + 's'}`;
}
function isoTs(iso) {
  return iso ? Date.parse(iso) / 1000 : 0;
}

// Calls a Settings-password route, asking for the password first when
// Settings is locked. `retry` runs again once it's unlocked.
async function iocAdminFetch(url, opts, retry) {
  if (!(await ensureSettingsUnlocked(retry))) return null;
  const res = await fetch(url, opts);
  if (res.status === 401) { setSettingsToken(null); showAuthGate('login', retry); return null; }
  return res;
}
function jsonBody(method, body) {
  return { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
}

// ------------------------------------------------------------------ the tab

async function loadIocDatabase() {
  const params = new URLSearchParams({
    status: iocdb.status, limit: String(IOCDB_PAGE), offset: String((iocdb.page - 1) * IOCDB_PAGE),
  });
  if (iocdb.type) params.set('type', iocdb.type);
  if (iocdb.q) params.set('q', iocdb.q);
  if (iocdb.minConfidence) params.set('min_confidence', String(iocdb.minConfidence));
  if (iocdb.malware) params.set('malware', iocdb.malware);
  if (iocdb.source) params.set('source', iocdb.source);
  let summaryRes, listRes;
  try {
    [summaryRes, listRes] = await Promise.all([fetch('/api/ioc/summary'), fetch('/api/ioc/indicators?' + params)]);
  } catch (e) {
    showIocdbError("Pantomath can't be reached right now. It will try again in 30 seconds.");
    return;
  }
  if (!summaryRes.ok || !listRes.ok) {
    const failed = !summaryRes.ok ? summaryRes : listRes;
    const body = await failed.json().catch(() => ({}));
    showIocdbError(body.detail || `The IOC database didn't answer (HTTP ${failed.status}).`);
    return;
  }
  document.getElementById('iocdbError').hidden = true;
  iocdb.summary = await summaryRes.json();
  const list = await listRes.json();
  iocdb.items = list.items;
  iocdb.total = list.total;
  renderIocdbKpis(iocdb.summary);
  renderIocdbFilters(iocdb.summary);
  renderIocdbTable();
}

function showIocdbError(message) {
  const el = document.getElementById('iocdbError');
  el.hidden = false;
  el.textContent = message;
}

function renderIocdbKpis(s) {
  const expired = s.by_status.expired || 0, fp = s.by_status.false_positive || 0;
  const feeds = s.feeds;
  const feedNote = !feeds.total ? 'no IOC feeds yet'
    : feeds.failing.length ? `failing: ${feeds.failing.map(f => f.name).join(', ')}`
    : s.last_feed_update ? `last update ${timeAgo(s.last_feed_update)}` : 'waiting for a first download';
  const cells = [
    { label: 'Active indicators', value: fmtNumber(s.active), tone: s.active ? 'signal' : '',
      note: `${fmtNumber(expired)} expired, ${fmtNumber(fp)} false positive${fp === 1 ? '' : 's'}` },
    { label: 'Added today', value: fmtNumber(s.added_today), note: 'first reported since midnight' },
    { label: 'Expire within 7 days', value: fmtNumber(s.expiring_week), note: 'unless a source reports them again' },
    { label: 'Feeds updating', value: feeds.enabled ? `${feeds.ok} / ${feeds.enabled}` : '0', tone: feeds.failing.length ? 'bad' : '', note: feedNote },
  ];
  document.getElementById('iocdbKpis').innerHTML = cells.map(c => `
    <div class="kpi static">
      <span class="kpi-label">${escapeHtml(c.label)}</span>
      <span class="kpi-value${c.tone ? ' tone-' + c.tone : ''}">${escapeHtml(String(c.value))}</span>
      <span class="kpi-note${c.tone === 'bad' ? ' tone-bad' : ''}">${escapeHtml(c.note)}</span>
    </div>`).join('');
}

function renderIocdbFilters(s) {
  const counts = s.by_type || {};
  document.getElementById('iocdbTypes').innerHTML = IOC_TYPE_TABS.map(([key, label, types]) => {
    const n = types ? types.reduce((sum, t) => sum + (counts[t] || 0), 0) : s.active;
    return `<button type="button" data-type="${key}" aria-pressed="${iocdb.type === key}">${escapeHtml(label)}<span class="seg-count">${fmtNumber(n)}</span></button>`;
  }).join('');
  document.querySelectorAll('#iocdbTypes button').forEach(btn => {
    btn.onclick = () => { iocdb.type = btn.dataset.type; iocdb.page = 1; loadIocDatabase(); };
  });
  const malware = s.malware.map(m => [m.name, `${m.name} (${fmtNumber(m.count)})`]);
  if (iocdb.malware && !s.malware.some(m => m.name === iocdb.malware)) malware.unshift([iocdb.malware, iocdb.malware]);
  fillSelect('iocdbMalware', [['', 'Any malware'], ...malware], iocdb.malware);
  fillSelect('iocdbSource', [['', 'Any source'], ['manual', 'Added by hand'], ...s.feeds.list.map(f => [f.id, f.name])], iocdb.source);
}

function confidenceHtml(value) {
  const level = value >= 80 ? 'high' : value >= 50 ? 'mid' : 'low';
  return `<span class="conf conf-${level}" title="Confidence ${value} of 100"><span class="conf-bar"><i style="width:${Math.max(0, Math.min(100, value))}%"></i></span><span class="conf-num">${value}</span></span>`;
}

function renderIocdbTable() {
  const table = document.getElementById('iocdbTable');
  const filtered = iocdb.type || iocdb.q || iocdb.minConfidence || iocdb.malware || iocdb.source || iocdb.status !== 'active';
  document.getElementById('iocdbCount').textContent = iocdb.total ? `${plural(iocdb.total, 'indicator')}${filtered ? ' match' : ''}` : '';
  if (!iocdb.items.length) {
    const empty = !iocdb.summary.active && !filtered;
    table.innerHTML = empty
      ? `<div class="card-empty"><strong>No indicators yet</strong>Add an IOC feed (a plain text or CSV list published at a URL), or add indicators by hand. Nothing is collected until you do.<br>
          <button type="button" class="btn btn-primary" data-act="feed">+ Add an IOC feed</button> <button type="button" class="btn" data-act="add">Add indicators by hand</button></div>`
      : '<div class="card-empty"><strong>Nothing matches these filters</strong>Try another type or status, or clear the filter.</div>';
    table.querySelector('[data-act="feed"]')?.addEventListener('click', () => { openSettingsTab('set-ioc-feeds'); });
    table.querySelector('[data-act="add"]')?.addEventListener('click', openIocAdd);
    renderPagination(document.getElementById('iocdbPagination'), 1, 1, () => {});
    return;
  }
  table.innerHTML = `<div class="iocdb-row iocdb-head" role="row">
      <span role="columnheader">Value</span><span role="columnheader">Type</span><span role="columnheader">Threat</span>
      <span role="columnheader">Malware / campaign</span><span role="columnheader">Confidence</span>
      <span role="columnheader" class="num">Sources</span><span role="columnheader" class="num">Last seen</span>
    </div>` + iocdb.items.map(i => {
    const context = [i.malware, i.campaign].filter(Boolean).join(' · ');
    return `<div class="iocdb-row${i.id === iocdb.selectedId ? ' selected' : ''}" role="row" tabindex="0" data-id="${i.id}">
      <span class="iocdb-value" role="cell">${escapeHtml(i.value)}${i.status !== 'active' ? ` <span class="status-tag status-${escapeAttr(i.status)}">${escapeHtml(IOC_STATUS_LABEL[i.status] || i.status)}</span>` : ''}</span>
      <span role="cell"><span class="chip">${escapeHtml(IOC_TYPE_LABEL[i.type] || i.type)}</span></span>
      <span class="iocdb-cell" role="cell">${escapeHtml(i.threat_type || '—')}</span>
      <span class="iocdb-cell" role="cell">${escapeHtml(context || '—')}</span>
      <span role="cell">${confidenceHtml(i.confidence)}</span>
      <span class="iocdb-cell num" role="cell">${i.sources}</span>
      <span class="iocdb-cell num" role="cell" title="${escapeAttr(fmtFull(i.last_seen))}">${escapeHtml(timeAgo(i.last_seen))}</span>
    </div>`;
  }).join('');
  table.querySelectorAll('.iocdb-row[data-id]').forEach(row => {
    const open = () => openIocDetail(Number(row.dataset.id));
    row.onclick = open;
    row.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); } };
  });
  renderPagination(document.getElementById('iocdbPagination'), iocdb.page, Math.ceil(iocdb.total / IOCDB_PAGE), (p) => {
    iocdb.page = p;
    loadIocDatabase();
    document.getElementById('iocdbTable').scrollIntoView({ block: 'start', behavior: 'smooth' });
  });
}

let iocdbSearchDebounce = null;
document.getElementById('iocdbSearch').addEventListener('input', (e) => {
  clearTimeout(iocdbSearchDebounce);
  iocdbSearchDebounce = setTimeout(() => { iocdb.q = e.target.value.trim(); iocdb.page = 1; loadIocDatabase(); }, 300);
});
[['iocdbConfidence', 'minConfidence', Number], ['iocdbMalware', 'malware', String], ['iocdbSource', 'source', String], ['iocdbStatus', 'status', String]]
  .forEach(([id, key, cast]) => {
    document.getElementById(id).addEventListener('change', (e) => { iocdb[key] = cast(e.target.value); iocdb.page = 1; loadIocDatabase(); });
  });
document.getElementById('iocdbFeedsBtn').onclick = () => openSettingsTab('set-ioc-feeds');
document.getElementById('iocdbAddBtn').onclick = () => openIocAdd();

// ------------------------------------------------------------ detail panel

async function openIocDetail(id) {
  iocdb.selectedId = id;
  iocdb.editing = false;
  document.querySelectorAll('#iocdbTable .iocdb-row').forEach(r => r.classList.toggle('selected', Number(r.dataset.id) === id));
  const res = await fetch('/api/ioc/indicators/' + id);
  if (!res.ok) { showToast(res.status === 404 ? 'That indicator is gone' : "Couldn't load the indicator"); return; }
  if (iocdb.selectedId !== id) return;
  iocdb.shown = await res.json();
  renderIocDetail();
}

function closeIocDetail() {
  iocdb.selectedId = null;
  iocdb.shown = null;
  document.getElementById('iocdbDetail').hidden = true;
  document.getElementById('view-ioc-database').classList.remove('has-detail');
  document.querySelectorAll('#iocdbTable .iocdb-row.selected').forEach(r => r.classList.remove('selected'));
}

function sightingHtml(s) {
  const context = [];
  if (s.context.port) context.push(`port ${s.context.port}`);
  if (s.context.reported) context.push(`reported ${s.context.reported}`);
  const ref = s.reference ? (/^https?:\/\//i.test(s.reference)
    ? `<a href="${safeHref(s.reference)}" target="_blank" rel="noopener">${escapeHtml(s.reference)}</a>` : escapeHtml(s.reference)) : '';
  return `<div class="sighting${s.active ? '' : ' inactive'}">
    <div class="sighting-head"><strong>${escapeHtml(s.source_name || s.source)}</strong>${confidenceHtml(s.confidence)}</div>
    <div class="sighting-sub">${s.active ? '' : 'No longer listed. '}First ${escapeHtml(timeAgo(s.first_seen))}, last ${escapeHtml(timeAgo(s.last_seen))}${context.length ? `, ${escapeHtml(context.join(', '))}` : ''}.</div>
    ${ref ? `<div class="sighting-ref">${ref}</div>` : ''}
  </div>`;
}

function renderIocDetail() {
  const i = iocdb.shown;
  if (!i) return;
  const el = document.getElementById('iocdbDetail');
  document.getElementById('view-ioc-database').classList.add('has-detail');
  el.hidden = false;
  const expires = i.status === 'false_positive' || i.status === 'allowlisted' ? '—'
    : !i.expires_at ? 'Never' : `${fmtFull(i.expires_at)}${i.expires_at < Date.now() / 1000 ? ' (expired)' : ''}`;
  const flag = {
    false_positive: ['fp', 'Marked as a false positive', "Lookups and exports don't return it, and feeds can't bring it back."],
    allowlisted: ['fp', 'On the allowlist', "Settings, Allowlist covers it, so lookups and exports don't return it."],
    expired: ['expired', 'Expired', 'No source has reported it for its lifetime. A lookup only returns it when asked for expired indicators.'],
  }[i.status];
  el.innerHTML = `
    <div class="detail-top">
      <span class="status-tag status-${escapeAttr(i.status)}">${escapeHtml(IOC_STATUS_LABEL[i.status] || i.status)}</span>
      <span class="chip">${escapeHtml(i.type_label)}</span>
      <button type="button" class="icon-btn-sq" data-role="close" aria-label="Close details">${CLOSE_ICON}</button>
    </div>
    <div class="iocdb-detail-value">
      <h3 class="detail-title mono">${escapeHtml(i.value)}</h3>
      <button type="button" class="row-icon" data-role="copy" aria-label="Copy the value" title="Copy">${COPY_ICON}</button>
    </div>
    ${flag ? `<div class="flag-box ${flag[0]}"><strong>${escapeHtml(flag[1])}</strong><span>${escapeHtml(flag[2])}</span></div>` : ''}
    <dl class="detail-meta">
      <dt>Confidence</dt><dd>${confidenceHtml(i.confidence)}<div class="muted">${escapeHtml(i.confidence_explained)}</div></dd>
      <dt>Threat type</dt><dd>${escapeHtml(i.threat_type || '—')}</dd>
      <dt>Malware</dt><dd>${escapeHtml(i.malware || '—')}</dd>
      ${i.campaign ? `<dt>Campaign</dt><dd>${escapeHtml(i.campaign)}</dd>` : ''}
      ${i.tags ? `<dt>Tags</dt><dd>${escapeHtml(i.tags)}</dd>` : ''}
      <dt>First seen</dt><dd>${escapeHtml(fmtFull(i.first_seen))}</dd>
      <dt>Last reported</dt><dd>${escapeHtml(fmtFull(i.last_seen))}</dd>
      <dt>Expires</dt><dd>${escapeHtml(expires)}</dd>
    </dl>
    ${i.note ? `<p class="detail-summary">${escapeHtml(i.note)}</p>` : ''}
    <section class="detail-section">
      <div class="detail-section-head"><h4>Sources (${i.sightings.length})</h4></div>
      ${i.sightings.length ? i.sightings.map(sightingHtml).join('') : '<p class="muted">No source reports it.</p>'}
    </section>
    <form class="iocdb-edit" data-role="edit-form" ${iocdb.editing ? '' : 'hidden'}>
      <h4>Edit</h4>
      <div class="field-grid">
        <div class="field"><label for="iocEditConfidence">Confidence</label><input type="number" id="iocEditConfidence" min="0" max="100" value="${i.analyst_confidence ?? ''}" placeholder="From the sources"></div>
        <div class="field"><label for="iocEditThreat">Threat type</label><input type="text" id="iocEditThreat" list="iocThreatTypes" maxlength="40" value="${escapeAttr(i.threat_type)}"></div>
        <div class="field"><label for="iocEditMalware">Malware</label><input type="text" id="iocEditMalware" maxlength="100" value="${escapeAttr(i.malware)}"></div>
        <div class="field"><label for="iocEditCampaign">Campaign</label><input type="text" id="iocEditCampaign" maxlength="100" value="${escapeAttr(i.campaign)}"></div>
      </div>
      <div class="field"><label for="iocEditTags">Tags</label><input type="text" id="iocEditTags" maxlength="300" value="${escapeAttr(i.tags)}"></div>
      <div class="field"><label for="iocEditNote">Note</label><input type="text" id="iocEditNote" maxlength="2000" value="${escapeAttr(i.note)}"></div>
      <p class="hint">Leave confidence empty to use the sources' number. A feed never overwrites what you type here.</p>
      <div class="detail-actions"><button type="submit" class="btn btn-primary">Save</button><button type="button" class="btn" data-role="edit-cancel">Cancel</button></div>
    </form>
    <div class="detail-actions" data-role="actions" ${iocdb.editing ? 'hidden' : ''}>
      <button type="button" class="btn" data-role="edit">Edit</button>
      ${i.status === 'false_positive'
        ? '<button type="button" class="btn" data-role="fp" data-to="active">Not a false positive</button>'
        : '<button type="button" class="btn" data-role="fp" data-to="false_positive">Mark as false positive</button>'}
      <button type="button" class="btn btn-quiet-danger" data-role="delete">Delete</button>
    </div>
    <p class="muted">Changing an indicator needs the Settings password.</p>`;
  el.querySelector('[data-role="close"]').onclick = closeIocDetail;
  el.querySelector('[data-role="copy"]').onclick = () => copyText(i.value, i.value);
  el.querySelector('[data-role="edit"]').onclick = async () => {
    if (!(await ensureSettingsUnlocked(() => { iocdb.editing = true; renderIocDetail(); }))) return;
    iocdb.editing = true;
    renderIocDetail();
    document.getElementById('iocEditConfidence').focus();
  };
  el.querySelector('[data-role="edit-cancel"]').onclick = () => { iocdb.editing = false; renderIocDetail(); };
  el.querySelector('[data-role="edit-form"]').onsubmit = (e) => { e.preventDefault(); saveIocEdit(i); };
  el.querySelector('[data-role="fp"]').onclick = (e) => setIocStatus(i, e.currentTarget.dataset.to);
  el.querySelector('[data-role="delete"]').onclick = () => deleteIndicator(i);
}

async function saveIocEdit(i) {
  const conf = document.getElementById('iocEditConfidence').value.trim();
  const body = {
    confidence: conf === '' ? null : Number(conf),
    threat_type: document.getElementById('iocEditThreat').value,
    malware: document.getElementById('iocEditMalware').value,
    campaign: document.getElementById('iocEditCampaign').value,
    tags: document.getElementById('iocEditTags').value,
    note: document.getElementById('iocEditNote').value,
  };
  const res = await iocAdminFetch('/api/ioc/indicators/' + i.id, jsonBody('PATCH', body), () => saveIocEdit(i));
  if (!res) return;
  const out = await res.json().catch(() => ({}));
  if (!res.ok) { showToast(out.detail || "Couldn't save the changes"); return; }
  iocdb.editing = false;
  iocdb.shown = out;
  renderIocDetail();
  loadIocDatabase();
}

async function setIocStatus(i, status) {
  const res = await iocAdminFetch('/api/ioc/indicators/' + i.id, jsonBody('PATCH', { status }), () => setIocStatus(i, status));
  if (!res) return;
  const out = await res.json().catch(() => ({}));
  if (!res.ok) { showToast(out.detail || "Couldn't change it"); return; }
  iocdb.shown = out;
  showToast(status === 'false_positive' ? 'Marked as a false positive' : 'No longer a false positive');
  renderIocDetail();
  loadIocDatabase();
}

async function deleteIndicator(i) {
  if (!confirm(`Delete ${i.value} and its sources? A feed that still lists it will add it again. To keep it out for good, mark it as a false positive instead.`)) return;
  const res = await iocAdminFetch('/api/ioc/indicators/' + i.id, { method: 'DELETE' }, () => deleteIndicator(i));
  if (!res) return;
  if (!res.ok) { showToast("Couldn't delete it"); return; }
  closeIocDetail();
  loadIocDatabase();
}

document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape' || currentView() !== 'ioc-database' || !iocdb.selectedId) return;
  if (document.querySelector('.modal-overlay.open')) return;
  closeIocDetail();
});

// ------------------------------------------------------------------ lookup

document.getElementById('iocdbLookupBtn').onclick = runIocLookup;
document.getElementById('iocdbLookupInput').addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) runIocLookup();
});
document.getElementById('iocdbLookupClear').onclick = () => {
  document.getElementById('iocdbLookupInput').value = '';
  document.getElementById('iocdbLookupResult').innerHTML = '';
  document.getElementById('iocdbLookupClear').hidden = true;
};

async function runIocLookup() {
  const values = document.getElementById('iocdbLookupInput').value.split(/[\r\n]+/).map(v => v.trim()).filter(Boolean);
  const out = document.getElementById('iocdbLookupResult');
  if (!values.length) { document.getElementById('iocdbLookupInput').focus(); return; }
  if (values.length > 1000) { out.innerHTML = '<p class="set-result error">Up to 1,000 values at a time.</p>'; return; }
  const btn = document.getElementById('iocdbLookupBtn');
  btn.disabled = true;
  try {
    const res = await fetch('/api/ioc/lookup', jsonBody('POST', { values, include_expired: document.getElementById('iocdbLookupExpired').checked }));
    const body = await res.json().catch(() => ({}));
    if (!res.ok) { out.innerHTML = `<p class="set-result error">${escapeHtml(body.detail || 'The lookup failed.')}</p>`; return; }
    renderIocLookup(body);
  } finally {
    btn.disabled = false;
    document.getElementById('iocdbLookupClear').hidden = false;
  }
}

function lookupVerdict(r) {
  if (r.match) {
    const what = [r.threat_type, r.malware, r.campaign].filter(Boolean).join(' · ');
    const names = r.sources.map(s => s.name).join(', ');
    return `<span class="lookup-hit">Match</span> ${confidenceHtml(r.confidence)} ${escapeHtml(what)}${r.status === 'expired' ? ' <span class="status-tag status-expired">Expired</span>' : ''}
      <span class="muted">${escapeHtml(names ? `from ${names}` : '')}${r.expires_at ? `, expires ${escapeHtml(fmtFull(isoTs(r.expires_at)))}` : ''}</span>`;
  }
  if (r.status) return `<span class="lookup-miss">No match</span> <span class="muted">stored, but ${escapeHtml((IOC_STATUS_LABEL[r.status] || r.status).toLowerCase())}</span>`;
  if (r.reason && r.reason !== 'not stored') return `<span class="lookup-miss">No match</span> <span class="muted">${escapeHtml(r.reason)}</span>`;
  return '<span class="lookup-miss">No match</span>';
}

function renderIocLookup(body) {
  const out = document.getElementById('iocdbLookupResult');
  const rows = [...body.results].sort((a, b) => (b.match - a.match));
  out.innerHTML = `<p class="lookup-summary"><strong>${plural(body.matched, 'match', 'matches')}</strong> in ${plural(body.checked, 'value')} checked.</p>
    <div class="lookup-table">${rows.map(r => `<div class="lookup-row${r.match ? ' hit' : ''}">
      <span class="lookup-value">${r.id ? `<button type="button" class="ioc-value" data-id="${r.id}" title="Show details">${escapeHtml(r.value)}</button>` : `<span class="mono">${escapeHtml(r.value)}</span>`}
        ${r.normalized ? `<span class="muted"> = ${escapeHtml(r.normalized)}</span>` : ''}</span>
      <span class="lookup-type">${escapeHtml(IOC_TYPE_LABEL[r.type] || r.type || '?')}</span>
      <span class="lookup-verdict">${lookupVerdict(r)}</span>
    </div>`).join('')}</div>`;
  out.querySelectorAll('[data-id]').forEach(btn => { btn.onclick = () => openIocDetail(Number(btn.dataset.id)); });
}

// ------------------------------------------------------- add indicators

async function openIocAdd() {
  if (!(await ensureSettingsUnlocked(openIocAdd))) return;
  ['iocAddText', 'iocAddColumn', 'iocAddThreat', 'iocAddMalware', 'iocAddCampaign', 'iocAddReference', 'iocAddNote']
    .forEach(id => { document.getElementById(id).value = ''; });
  document.getElementById('iocAddType').value = '';
  document.getElementById('iocAddLifetime').value = '0';
  document.getElementById('iocAddConfidence').value = '70';
  document.getElementById('iocAddResult').hidden = true;
  document.getElementById('iocAddColumnField').hidden = true;
  document.getElementById('iocAddFileName').textContent = 'Defanged values are restored. Private addresses are refused.';
  iocAddFormat = 'text';
  document.getElementById('iocAddSubmit').disabled = false;
  document.getElementById('iocAddOverlay').classList.add('open');
  document.getElementById('iocAddText').focus();
}
let iocAddFormat = 'text';
document.getElementById('iocAddCancel').onclick = () => document.getElementById('iocAddOverlay').classList.remove('open');
document.getElementById('iocAddFileBtn').onclick = () => document.getElementById('iocAddFile').click();
document.getElementById('iocAddFile').addEventListener('change', async (e) => {
  const file = e.target.files[0];
  e.target.value = '';
  if (!file) return;
  if (file.size > 20 * 1024 * 1024) { showToast('That file is over 20 MB. Publish it at a URL and add it as an IOC feed.'); return; }
  document.getElementById('iocAddText').value = await file.text();
  iocAddFormat = /\.csv$/i.test(file.name) || file.type === 'text/csv' ? 'csv' : 'text';
  document.getElementById('iocAddColumnField').hidden = iocAddFormat !== 'csv';
  document.getElementById('iocAddFileName').textContent = `${file.name}, read as ${iocAddFormat === 'csv' ? 'CSV' : 'plain text'}.`;
});
document.getElementById('iocAddText').addEventListener('input', () => {
  if (iocAddFormat === 'csv' && !document.getElementById('iocAddText').value) {
    iocAddFormat = 'text';
    document.getElementById('iocAddColumnField').hidden = true;
  }
});

document.getElementById('iocAddSubmit').onclick = submitIocAdd;
async function submitIocAdd() {
  const text = document.getElementById('iocAddText').value;
  const out = document.getElementById('iocAddResult');
  if (!text.trim()) { document.getElementById('iocAddText').focus(); return; }
  const body = {
    text, format: iocAddFormat, value_column: document.getElementById('iocAddColumn').value.trim(),
    type: document.getElementById('iocAddType').value, confidence: Number(document.getElementById('iocAddConfidence').value || 0),
    threat_type: document.getElementById('iocAddThreat').value, malware: document.getElementById('iocAddMalware').value,
    campaign: document.getElementById('iocAddCampaign').value, lifetime_days: Number(document.getElementById('iocAddLifetime').value),
    reference: document.getElementById('iocAddReference').value, note: document.getElementById('iocAddNote').value,
  };
  const btn = document.getElementById('iocAddSubmit');
  btn.disabled = true;
  const res = await iocAdminFetch('/api/ioc/indicators', jsonBody('POST', body), submitIocAdd);
  btn.disabled = false;
  if (!res) return;
  const r = await res.json().catch(() => ({}));
  out.hidden = false;
  if (!res.ok) {
    out.className = 'feed-test bad';
    out.innerHTML = `<strong>Nothing was added</strong>${escapeHtml(r.detail || 'The request failed.')}`;
    return;
  }
  const skipped = [r.allowlisted ? `${fmtNumber(r.allowlisted)} on the allowlist` : '', r.false_positive ? `${fmtNumber(r.false_positive)} marked as false positives` : '']
    .filter(Boolean).join(', ');
  out.className = 'feed-test ' + (r.added + r.updated ? 'ok' : 'bad');
  out.innerHTML = `<strong>${plural(r.added, 'new indicator')}, ${plural(r.updated, 'already stored and updated', 'already stored and updated')}</strong>
    ${r.rejected ? `${plural(r.rejected, 'value')} refused: ${r.rejected_samples.map(s => `${escapeHtml(s.value)} (${escapeHtml(s.reason)})`).join(', ')}${r.rejected > r.rejected_samples.length ? '…' : ''}. ` : ''}
    ${skipped ? `Skipped ${escapeHtml(skipped)}.` : ''}`;
  if (r.added + r.updated) {
    btn.disabled = true;
    setTimeout(() => { document.getElementById('iocAddOverlay').classList.remove('open'); }, r.rejected || skipped ? 4000 : 1400);
    if (currentView() === 'ioc-database') loadIocDatabase();
  }
}

// ------------------------------------------------- Settings: IOC feeds

let iocFeeds = [];
let iocFeedEditing = null;

function feedState(f) {
  if (!f.enabled) return 'paused';
  if (f.last_status === 'ok') return 'healthy';
  if ((f.last_status || '').startsWith('error')) return 'failing';
  return 'pending';
}

async function loadIocKeepSetting() {
  const res = await fetch('/api/ioc/settings');
  if (res.ok) document.getElementById('iocKeepExpired').value = String((await res.json()).keep_expired_days);
}
document.getElementById('iocKeepExpired').addEventListener('change', async (e) => {
  const out = document.getElementById('iocKeepExpiredResult');
  const days = Number(e.target.value);
  const res = await iocAdminFetch('/api/ioc/settings', jsonBody('PATCH', { keep_expired_days: days }), loadIocKeepSetting);
  if (!res) return;
  const r = await res.json().catch(() => ({}));
  out.classList.toggle('error', !res.ok);
  out.textContent = !res.ok ? (r.detail || "Couldn't save it.")
    : r.keep_expired_days ? `Saved. Expired indicators are deleted ${e.target.selectedOptions[0].textContent.replace(' (default)', '')} after they expire.`
    : 'Saved. Expired indicators are kept for ever.';
});

async function loadIocFeedSettings() {
  loadIocKeepSetting();
  const res = await fetch('/api/ioc/feeds');
  const table = document.getElementById('iocFeedTable');
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    if (res.status !== 401) table.innerHTML = `<div class="card-empty"><strong>The IOC database isn't available</strong>${escapeHtml(body.detail || '')}</div>`;
    return;
  }
  const data = await res.json();
  iocFeeds = data.feeds;
  if (!iocFeeds.length) {
    table.innerHTML = `<div class="card-empty"><strong>No IOC feeds yet</strong>Paste the URL of a list, say what it holds and how often to fetch it, and test it before saving.${data.manual ? ` ${plural(data.manual, 'indicator was', 'indicators were')} added by hand.` : ''}</div>`;
    return;
  }
  const label = { healthy: 'Healthy', failing: 'Failing', pending: 'Waiting', paused: 'Paused' };
  table.innerHTML = `<div class="src-row src-head" role="row">
      <span role="columnheader">Status</span><span role="columnheader">Feed</span><span role="columnheader">Last success</span>
      <span role="columnheader" class="src-cell num">Active</span><span role="columnheader" class="src-cell num">Every</span>
      <span role="columnheader" style="text-align:right;">Actions</span>
    </div>` + iocFeeds.map(f => {
    const state = feedState(f);
    const name = escapeAttr(f.name);
    const error = state === 'failing' ? f.last_status.replace(/^error:\s*/, '') : '';
    const what = [f.format === 'csv' ? 'CSV' : 'Plain text', f.default_type ? IOC_TYPE_LABEL[f.default_type] : 'type detected per value',
      `confidence ${f.confidence}`, f.threat_type, f.snapshot ? 'snapshot' : '', f.has_key ? 'with a key' : ''].filter(Boolean).join(', ');
    const last = f.last_success ? `Last download: ${plural(f.last_count, 'value')} changed or new, ${fmtNumber(f.last_new)} new${f.snapshot ? `, ${fmtNumber(f.last_dropped)} dropped off` : ''}${f.last_rejected ? `, ${fmtNumber(f.last_rejected)} refused` : ''}.` : '';
    return `<div class="src-row state-${state}" role="row">
      <span class="src-status" role="cell"><span class="health-dot" aria-hidden="true"></span>${label[state]}</span>
      <div class="src-main" role="cell">
        <div class="src-name"><span>${escapeHtml(f.name)}</span></div>
        <div class="src-sub iocfeed-url">${escapeHtml(f.url)}</div>
        <div class="src-sub">${escapeHtml(what)}</div>
        ${last ? `<div class="src-sub">${escapeHtml(last)}</div>` : ''}
        ${error ? `<div class="src-error">${escapeHtml(error)}</div>` : ''}
        <div class="src-test" data-run-result="${escapeAttr(f.id)}" role="status" hidden></div>
      </div>
      <span class="src-cell src-last" role="cell">${escapeHtml(f.last_success ? timeAgo(f.last_success) : 'never')}</span>
      <span class="src-cell num" role="cell">${fmtNumber(f.indicators)}</span>
      <span class="src-cell num" role="cell">${escapeHtml(formatInterval(f.interval_seconds))}</span>
      <div class="src-actions" role="cell">
        <button type="button" class="btn btn-sm" data-action="run" data-id="${escapeAttr(f.id)}" aria-label="Update ${name} now">Update now</button>
        <button type="button" class="row-icon" data-action="edit" data-id="${escapeAttr(f.id)}" aria-label="Edit ${name}" title="Edit">${EDIT_ICON}</button>
        <button type="button" class="row-icon" data-action="toggle" data-id="${escapeAttr(f.id)}" aria-label="${f.enabled ? 'Pause' : 'Resume'} ${name}" title="${f.enabled ? 'Pause' : 'Resume'}">${f.enabled ? PAUSE_ICON : PLAY_ICON}</button>
        <button type="button" class="row-icon danger" data-action="delete" data-id="${escapeAttr(f.id)}" aria-label="Remove ${name}" title="Remove">${TRASH_ICON}</button>
      </div>
    </div>`;
  }).join('');
  const byId = id => iocFeeds.find(f => f.id === id);
  table.querySelectorAll('[data-action="edit"]').forEach(btn => { btn.onclick = () => openIocFeedModal(byId(btn.dataset.id)); });
  table.querySelectorAll('[data-action="toggle"]').forEach(btn => {
    btn.onclick = async () => {
      const f = byId(btn.dataset.id);
      await fetch('/api/ioc/feeds/' + f.id, jsonBody('PATCH', { enabled: !f.enabled }));
      loadIocFeedSettings();
    };
  });
  table.querySelectorAll('[data-action="delete"]').forEach(btn => {
    btn.onclick = async () => {
      const f = byId(btn.dataset.id);
      if (!confirm(`Remove "${f.name}"? Indicators that only it reported expire now; ones other sources report stay.`)) return;
      await fetch('/api/ioc/feeds/' + f.id, { method: 'DELETE' });
      loadIocFeedSettings();
    };
  });
  table.querySelectorAll('[data-action="run"]').forEach(btn => {
    btn.onclick = async () => {
      const out = table.querySelector(`[data-run-result="${CSS.escape(btn.dataset.id)}"]`);
      out.hidden = false;
      out.className = 'src-test';
      out.textContent = 'Downloading…';
      btn.disabled = true;
      const res = await fetch(`/api/ioc/feeds/${btn.dataset.id}/run`, { method: 'POST' });
      const r = await res.json().catch(() => ({ ok: false, error: 'no answer' }));
      btn.disabled = false;
      out.className = 'src-test ' + (r.ok ? 'ok' : 'bad');
      out.textContent = !r.ok ? `Failed: ${r.error}`
        : r.unchanged ? 'The list has not changed since the last download.'
        : `${plural(r.values, 'value')}: ${fmtNumber(r.new)} new, ${fmtNumber(r.refreshed)} refreshed, ${fmtNumber(r.unchanged)} unchanged${r.dropped ? `, ${fmtNumber(r.dropped)} dropped off` : ''}${r.rejected ? `, ${fmtNumber(r.rejected)} refused` : ''}.`;
      setTimeout(loadIocFeedSettings, r.ok ? 2500 : 6000);
    };
  });
}
SETTINGS_TAB_LOADERS['set-ioc-feeds'] = () => loadIocFeedSettings();
document.getElementById('iocFeedAddBtn').onclick = () => openIocFeedModal(null);

const FEED_FIELDS = [
  ['iocFeedName', 'name'], ['iocFeedUrl', 'url'], ['iocFeedFormat', 'format'], ['iocFeedType', 'default_type'],
  ['iocFeedValueCol', 'value_column'], ['iocFeedMalwareCol', 'malware_column'], ['iocFeedDateCol', 'date_column'],
  ['iocFeedConfidence', 'confidence'], ['iocFeedThreat', 'threat_type'], ['iocFeedInterval', 'interval_seconds'],
  ['iocFeedLifetime', 'lifetime_days'], ['iocFeedMaxMb', 'max_mb'], ['iocFeedKeyHeader', 'key_header'],
];
const FEED_NUMBERS = new Set(['confidence', 'interval_seconds', 'lifetime_days', 'max_mb']);

async function openIocFeedModal(feed) {
  if (!(await ensureSettingsUnlocked(() => openIocFeedModal(feed)))) return;
  iocFeedEditing = feed;
  const defaults = { format: 'text', default_type: '', confidence: 75, interval_seconds: 21600, lifetime_days: 0, max_mb: 30 };
  FEED_FIELDS.forEach(([id, key]) => {
    const v = feed ? feed[key] : defaults[key];
    document.getElementById(id).value = v === undefined || v === null ? '' : String(v);
  });
  const interval = document.getElementById('iocFeedInterval');
  if (feed && ![...interval.options].some(o => o.value === String(feed.interval_seconds))) {
    interval.insertAdjacentHTML('beforeend', `<option value="${feed.interval_seconds}">${escapeHtml(formatInterval(feed.interval_seconds))}</option>`);
    interval.value = String(feed.interval_seconds);
  }
  document.getElementById('iocFeedSnapshot').checked = !!(feed && feed.snapshot);
  document.getElementById('iocFeedKey').value = '';
  document.getElementById('iocFeedClearKey').checked = false;
  document.getElementById('iocFeedClearKeyField').hidden = !(feed && feed.has_key);
  document.getElementById('iocFeedKey').placeholder = feed && feed.has_key ? 'Stored. Leave empty to keep it.' : '';
  document.getElementById('iocFeedKeyHint').textContent = feed && feed.has_key ? 'A key is stored. It is never shown again.' : 'Stored, never shown again.';
  document.getElementById('iocFeedTitle').textContent = feed ? 'Edit IOC feed' : 'Add IOC feed';
  document.getElementById('iocFeedSave').textContent = feed ? 'Save changes' : 'Add feed';
  document.getElementById('iocFeedTestResult').hidden = true;
  document.getElementById('iocFeedColumns').innerHTML = '';
  syncFeedFormat();
  document.getElementById('iocFeedOverlay').classList.add('open');
  document.getElementById('iocFeedName').focus();
}
function syncFeedFormat() {
  document.getElementById('iocFeedCsvFields').hidden = document.getElementById('iocFeedFormat').value !== 'csv';
}
document.getElementById('iocFeedFormat').addEventListener('change', syncFeedFormat);
document.getElementById('iocFeedCancel').onclick = () => document.getElementById('iocFeedOverlay').classList.remove('open');

function readFeedForm() {
  const body = {};
  FEED_FIELDS.forEach(([id, key]) => {
    const v = document.getElementById(id).value.trim();
    body[key] = FEED_NUMBERS.has(key) ? Number(v || 0) : v;
  });
  body.snapshot = document.getElementById('iocFeedSnapshot').checked;
  const key = document.getElementById('iocFeedKey').value;
  if (key) body.key_value = key;
  return body;
}

document.getElementById('iocFeedTestBtn').onclick = testIocFeed;
async function testIocFeed() {
  const body = readFeedForm();
  const out = document.getElementById('iocFeedTestResult');
  if (!body.url) { document.getElementById('iocFeedUrl').focus(); return; }
  out.hidden = false;
  out.className = 'feed-test';
  out.textContent = 'Downloading and reading the list…';
  const btn = document.getElementById('iocFeedTestBtn');
  btn.disabled = true;
  const res = await iocAdminFetch('/api/ioc/feeds/test', jsonBody('POST', { ...body, feed_id: iocFeedEditing ? iocFeedEditing.id : '' }), testIocFeed);
  btn.disabled = false;
  if (!res) return;
  const r = await res.json().catch(() => ({ ok: false, error: 'no answer' }));
  if (!res.ok || !r.ok) {
    out.className = 'feed-test bad';
    out.innerHTML = `<strong>Test failed</strong>${escapeHtml(r.error || r.detail || 'The request failed.')}`;
    return;
  }
  const types = Object.entries(r.by_type).map(([t, n]) => `${fmtNumber(n)} ${IOC_TYPE_LABEL[t] || t}`).join(', ');
  out.className = 'feed-test ' + (r.valid ? 'ok' : 'bad');
  out.innerHTML = `<strong>${r.valid ? 'Test passed' : 'Nothing usable in this list'}</strong>
    ${plural(r.lines, 'line')} in ${(r.duration_ms / 1000).toFixed(1)} s: ${escapeHtml(types || 'no indicators')}, ${plural(r.skipped, 'comment or blank line')} skipped, ${fmtNumber(r.rejected)} refused.
    ${r.rejected_samples.length ? `<div class="hint">Refused, for example: ${r.rejected_samples.map(s => `${escapeHtml(s.value)} (${escapeHtml(s.reason)})`).join(', ')}</div>` : ''}
    ${r.sample.length ? `<div class="test-sample">${r.sample.map(v => `<code>${escapeHtml(v)}</code>`).join(' ')}</div>` : ''}
    ${r.columns.length ? `<div class="hint">Columns: ${r.columns.map(c => escapeHtml(c)).join(', ')}. Values read from <strong>${escapeHtml(r.value_column)}</strong>.</div>` : ''}`;
  if (r.columns.length) {
    document.getElementById('iocFeedColumns').innerHTML = r.columns.map(c => `<option value="${escapeAttr(c)}">`).join('');
    if (!document.getElementById('iocFeedValueCol').value) document.getElementById('iocFeedValueCol').value = r.value_column;
  }
}

document.getElementById('iocFeedSave').onclick = saveIocFeed;
async function saveIocFeed() {
  const body = readFeedForm();
  if (!body.name) { document.getElementById('iocFeedName').focus(); return; }
  if (!body.url) { document.getElementById('iocFeedUrl').focus(); return; }
  if (iocFeedEditing && document.getElementById('iocFeedClearKey').checked) body.clear_key = true;
  const res = await iocAdminFetch(iocFeedEditing ? '/api/ioc/feeds/' + iocFeedEditing.id : '/api/ioc/feeds',
    jsonBody(iocFeedEditing ? 'PATCH' : 'POST', body), saveIocFeed);
  if (!res) return;
  const r = await res.json().catch(() => ({}));
  if (!res.ok) {
    const out = document.getElementById('iocFeedTestResult');
    out.hidden = false;
    out.className = 'feed-test bad';
    out.innerHTML = `<strong>Not saved</strong>${escapeHtml(r.detail || 'The request failed.')}`;
    return;
  }
  document.getElementById('iocFeedOverlay').classList.remove('open');
  showToast(iocFeedEditing ? 'Feed saved' : 'Feed added. The first download starts within a minute.');
  loadIocFeedSettings();
}

// ------------------------------------------------- Settings: Allowlist

const ALLOW_TYPE_LABEL = { cidr: 'IP range', domain: 'Domain and subdomains', exact: 'Exact value' };

async function loadAllowlistSettings() {
  const res = await fetch('/api/ioc/allowlist');
  const list = document.getElementById('allowList');
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    if (res.status !== 401) list.innerHTML = `<div class="card-empty"><strong>The IOC database isn't available</strong>${escapeHtml(body.detail || '')}</div>`;
    return;
  }
  const entries = await res.json();
  list.innerHTML = entries.length
    ? '<div class="stack-row stack-head"><span>Value</span><span>Why</span><span>Covers</span><span></span></div>' +
      entries.map(e => `<div class="stack-row" data-id="${escapeAttr(e.id)}">
        <span class="stack-name mono">${escapeHtml(e.value)}</span>
        <span class="stack-aliases">${e.reason ? escapeHtml(e.reason) : '<span class="muted">—</span>'}</span>
        <span class="stack-aliases">${escapeHtml(ALLOW_TYPE_LABEL[e.type] || e.type)}</span>
        <span class="stack-actions"><button type="button" class="row-icon danger" data-action="delete" aria-label="Remove ${escapeAttr(e.value)}" title="Remove">${TRASH_ICON}</button></span>
      </div>`).join('')
    : '<div class="card-empty"><strong>Nothing on the allowlist yet</strong>Add your public address ranges, your own domains, and suppliers you must never block.</div>';
  list.querySelectorAll('[data-action="delete"]').forEach(btn => {
    btn.onclick = async () => {
      const entry = entries.find(e => e.id === btn.closest('.stack-row').dataset.id);
      if (!confirm(`Remove ${entry.value} from the allowlist? Stored indicators it covered are returned to SIEMs again.`)) return;
      await fetch('/api/ioc/allowlist/' + entry.id, { method: 'DELETE' });
      document.getElementById('allowResult').textContent = `Removed ${entry.value}.`;
      loadAllowlistSettings();
    };
  });
}
SETTINGS_TAB_LOADERS['set-ioc-allowlist'] = () => loadAllowlistSettings();

document.getElementById('allowAddBtn').onclick = addAllowEntry;
document.getElementById('allowValue').addEventListener('keydown', (e) => { if (e.key === 'Enter') addAllowEntry(); });
async function addAllowEntry() {
  const value = document.getElementById('allowValue').value.trim();
  const out = document.getElementById('allowResult');
  if (!value) { document.getElementById('allowValue').focus(); return; }
  const res = await fetch('/api/ioc/allowlist', jsonBody('POST', { value, reason: document.getElementById('allowReason').value }));
  const r = await res.json().catch(() => ({}));
  out.classList.toggle('error', !res.ok);
  if (!res.ok) { out.textContent = r.detail || "Couldn't add it."; return; }
  document.getElementById('allowValue').value = '';
  document.getElementById('allowReason').value = '';
  out.textContent = `Added ${r.value} (${(ALLOW_TYPE_LABEL[r.type] || r.type).toLowerCase()}). ${plural(r.allowlisted_total, 'stored indicator is', 'stored indicators are')} allowlisted now.`;
  loadAllowlistSettings();
}

// ------------------------------------------------- Settings: SIEM keys

document.getElementById('siemKeyCreateBtn').addEventListener('click', async () => {
  const label = document.getElementById('siemKeyLabel').value.trim();
  const box = document.getElementById('siemKeyNew');
  if (!label) { document.getElementById('siemKeyLabel').focus(); return; }
  const res = await fetch('/api/auth/siem-keys', jsonBody('POST', { label }));
  const body = await res.json().catch(() => ({}));
  if (!res.ok) { showToast(body.detail || "Couldn't create the key"); return; }
  document.getElementById('siemKeyLabel').value = '';
  box.hidden = false;
  box.innerHTML = `<strong>SIEM key for ${escapeHtml(label)}</strong><code>${escapeHtml(body.key)}</code>
    <button type="button" class="btn btn-sm" id="siemKeyCopy">Copy key</button>
    <span class="muted"> Copy it now: Pantomath keeps only a fingerprint and can't show it again. Send it as <code>Authorization: Bearer …</code> to <code>${escapeHtml(location.origin)}/api/v1/lookup</code>.</span>`;
  document.getElementById('siemKeyCopy').onclick = () => copyText(body.key, 'the SIEM key');
  loadSecuritySettings();
});
