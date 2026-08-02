/**
 * A month-grid calendar heatmap — pure CSS/DOM, same dependency-free
 * approach as charts.js. Renders one month at a time with prev/next
 * navigation, shades each day by how many matching items landed on it
 * (a GitHub-contribution-graph-style intensity, using the IOC type's own
 * color), and reports clicks back via a callback so the caller decides
 * what "selecting a day" means (the IOCs page uses it to scope the top
 * chart + donut + article drilldown to that day).
 */

/**
 * @param containerEl   element to render into
 * @param opts.year     displayed year (e.g. 2026)
 * @param opts.month    displayed month, 1-12
 * @param opts.counts   { "2026-07-14": 3, ... } — only days with activity need appear
 * @param opts.color    CSS color (hex or var()) used for the heat intensity
 * @param opts.selected "YYYY-MM-DD" or null — highlights that day if it falls in the displayed month
 * @param opts.minYear  earliest year navigation is allowed to reach (inclusive)
 * @param opts.maxYear  latest year navigation is allowed to reach (inclusive)
 * @param opts.onSelectDay  (dateStr) => void — called when a day cell is clicked (including to toggle off)
 * @param opts.onNavigate   (year, month) => void — called with the new year/month from any nav control
 *                          (prev/next month, prev/next year, or the jump popover). Callers should still
 *                          clamp/validate year/month themselves — see loadIocCalendar in app.js — this
 *                          widget clamps its own controls but a caller should never trust a UI layer as
 *                          its only line of defense.
 */
function _hexToRgb(hex) {
  const m = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
  return m ? `${parseInt(m[1], 16)}, ${parseInt(m[2], 16)}, ${parseInt(m[3], 16)}` : '79, 216, 196';
}

const MONTH_ABBR = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

// Closing the jump popover on an outside click or Escape needs *one*
// document-level listener, registered once — not one per render. This
// widget's render function runs on every single navigation (each prev/
// next click, each day selection), so attaching a fresh
// `document.addEventListener` inside it would leak a new listener every
// time and never remove the old ones. Instead there's exactly one
// delegated listener, registered lazily on first use and guarded so a
// second call to renderCalendarHeatmap can't register a second one.
let _calendarGlobalListenerAttached = false;
let _closeOpenPopover = null; // sensible default until a popover actually opens

function _ensureGlobalListener() {
  if (_calendarGlobalListenerAttached) return;
  _calendarGlobalListenerAttached = true;
  document.addEventListener('click', (e) => {
    if (_closeOpenPopover && !e.target.closest('.cal-jump-popover') && !e.target.closest('.cal-month-label')) {
      _closeOpenPopover();
    }
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && _closeOpenPopover) _closeOpenPopover();
  });
}

function renderCalendarHeatmap(containerEl, opts) {
  const { year, month, counts, color, selected, onSelectDay, onNavigate } = opts;
  // Bounds default to a wide-but-finite window if the caller doesn't supply
  // real data-backed ones — this widget never navigates to an unbounded
  // year, even if the caller forgets to pass minYear/maxYear.
  const minYear = Number.isInteger(opts.minYear) ? opts.minYear : year - 20;
  const maxYear = Number.isInteger(opts.maxYear) ? opts.maxYear : year + 1;

  const monthLabel = new Date(year, month - 1, 1).toLocaleDateString(undefined, { month: 'long', year: 'numeric' });
  const firstWeekday = new Date(year, month - 1, 1).getDay(); // 0=Sun
  const daysInMonth = new Date(year, month, 0).getDate();
  const max = Math.max(1, ...Object.values(counts));
  const todayStr = new Date().toISOString().slice(0, 10);
  const rgb = _hexToRgb(color);

  const weekdayLabels = ['S', 'M', 'T', 'W', 'T', 'F', 'S'];
  const atEarliest = year <= minYear && month <= 1;
  const atLatest = year >= maxYear && month >= 12;

  let cells = '';
  for (let i = 0; i < firstWeekday; i++) {
    cells += `<div class="cal-day cal-day-empty"></div>`;
  }
  for (let d = 1; d <= daysInMonth; d++) {
    const dateStr = `${year}-${String(month).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
    const count = counts[dateStr] || 0;
    const intensity = count > 0 ? Math.max(0.18, count / max) : 0;
    const isSelected = selected === dateStr;
    const isToday = dateStr === todayStr;
    const bg = count > 0 ? `rgba(${rgb}, ${intensity.toFixed(2)})` : 'transparent';
    cells += `
      <div class="cal-day ${count > 0 ? 'has-data' : ''} ${isSelected ? 'selected' : ''} ${isToday ? 'today' : ''}"
           data-date="${dateStr}"
           style="background:${bg};"
           title="${dateStr}: ${count} item${count === 1 ? '' : 's'} with ${opts.itemLabel || 'IOCs'}">
        <span class="cal-day-num">${d}</span>
        ${count > 0 ? `<span class="cal-day-count">${count}</span>` : ''}
      </div>`;
  }

  // Year options for the jump popover are only ever years within
  // [minYear, maxYear] — i.e. years the database could plausibly have
  // data for — never an arbitrary free-typed value. All values here come
  // from a fixed numeric loop, not user text, so there's nothing to
  // escape/sanitize going into this template.
  let yearOptions = '';
  for (let y = maxYear; y >= minYear; y--) {
    yearOptions += `<option value="${y}" ${y === year ? 'selected' : ''}>${y}</option>`;
  }
  let monthButtons = '';
  MONTH_ABBR.forEach((label, i) => {
    const m = i + 1;
    const isCurrent = m === month;
    monthButtons += `<button class="cal-jump-month-btn ${isCurrent ? 'active' : ''}" data-month="${m}">${label}</button>`;
  });

  containerEl.innerHTML = `
    <div class="cal-header">
      <div class="cal-nav-group">
        <button class="cal-nav-btn" data-nav="prev-year" title="Previous year" ${year <= minYear ? 'disabled' : ''}>&#171;</button>
        <button class="cal-nav-btn" data-nav="prev-month" title="Previous month" ${atEarliest ? 'disabled' : ''}>&#8249;</button>
      </div>
      <button class="cal-month-label" type="button" title="Jump to a specific month/year">${monthLabel}</button>
      <div class="cal-nav-group">
        <button class="cal-nav-btn" data-nav="next-month" title="Next month" ${atLatest ? 'disabled' : ''}>&#8250;</button>
        <button class="cal-nav-btn" data-nav="next-year" title="Next year" ${year >= maxYear ? 'disabled' : ''}>&#187;</button>
      </div>
      <div class="cal-jump-popover" style="display:none;">
        <select class="cal-jump-year">${yearOptions}</select>
        <div class="cal-jump-months">${monthButtons}</div>
      </div>
    </div>
    <div class="cal-weekdays">${weekdayLabels.map(w => `<span>${w}</span>`).join('')}</div>
    <div class="cal-grid">${cells}</div>
  `;

  // Clamps and validates before ever calling onNavigate — defense in depth:
  // even though the buttons above are only enabled within [minYear, maxYear]
  // and the popover's year <select> only ever offers values in that same
  // range, a caller changing this widget later (or a stray keyboard/devtools
  // interaction) shouldn't be able to smuggle an out-of-range or non-numeric
  // year/month into an API call built from these values.
  function safeNavigate(newYear, newMonth) {
    newYear = parseInt(newYear, 10);
    newMonth = parseInt(newMonth, 10);
    if (!Number.isInteger(newYear) || !Number.isInteger(newMonth)) return;
    newMonth = Math.min(12, Math.max(1, newMonth));
    newYear = Math.min(maxYear, Math.max(minYear, newYear));
    onNavigate(newYear, newMonth);
  }

  containerEl.querySelectorAll('.cal-nav-btn').forEach(btn => {
    btn.onclick = () => {
      if (btn.disabled) return;
      let newMonth = month, newYear = year;
      switch (btn.dataset.nav) {
        case 'prev-month': newMonth -= 1; if (newMonth < 1) { newMonth = 12; newYear -= 1; } break;
        case 'next-month': newMonth += 1; if (newMonth > 12) { newMonth = 1; newYear += 1; } break;
        case 'prev-year': newYear -= 1; break;
        case 'next-year': newYear += 1; break;
      }
      safeNavigate(newYear, newMonth);
    };
  });

  containerEl.querySelectorAll('.cal-day.has-data').forEach(cell => {
    cell.onclick = () => onSelectDay(cell.dataset.date);
  });

  // Jump popover: pick a year, then click a month — navigates immediately
  // and closes. Also closable via outside-click or Escape (handled by the
  // single delegated listener set up in _ensureGlobalListener).
  const labelBtn = containerEl.querySelector('.cal-month-label');
  const popover = containerEl.querySelector('.cal-jump-popover');
  const yearSelect = containerEl.querySelector('.cal-jump-year');

  _ensureGlobalListener();
  _closeOpenPopover = () => { popover.style.display = 'none'; };

  labelBtn.onclick = (e) => {
    e.stopPropagation();
    const isOpen = popover.style.display !== 'none';
    _closeOpenPopover();
    popover.style.display = isOpen ? 'none' : 'flex';
  };
  popover.querySelectorAll('.cal-jump-month-btn').forEach(mbtn => {
    mbtn.onclick = () => {
      safeNavigate(yearSelect.value, mbtn.dataset.month);
      _closeOpenPopover();
    };
  });
}
