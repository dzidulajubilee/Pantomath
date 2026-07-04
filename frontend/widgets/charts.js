/**
 * Dependency-free chart primitives. Pantomath deliberately avoids a chart
 * library (Recharts, Chart.js, etc.) for these simple cases — a handful of
 * bars and a sparkline don't need 100KB+ of dependency for something CSS
 * can render just as well, and it keeps the dashboard fast to load.
 */

const SEVERITY_COLORS = { high: 'var(--red)', medium: 'var(--amber)', low: 'var(--text-dim)' };

function renderBarChart(containerEl, data, opts) {
  opts = opts || {};
  const colorFn = opts.colorFn || (() => 'var(--signal)');
  if (!data.length) {
    containerEl.innerHTML = `<div style="font-size:11.5px;color:var(--text-faint);padding:8px 0;">No data yet</div>`;
    return;
  }
  const max = Math.max(...data.map(d => d.count), 1);
  const clickable = typeof opts.onClick === 'function';
  containerEl.innerHTML = data.map(d => `
    <div class="bar-row" ${clickable ? `data-label="${d.label}" style="cursor:pointer;"` : ''}>
      <span class="bar-label" title="${d.label}">${d.label}</span>
      <div class="bar-track"><div class="bar-fill" style="width:${Math.max(4, (d.count/max)*100)}%; background:${colorFn(d.label)}"></div></div>
      <span class="bar-count">${d.count}</span>
    </div>
  `).join('');
  if (clickable) {
    containerEl.querySelectorAll('.bar-row').forEach(row => {
      row.onclick = () => opts.onClick(row.dataset.label);
    });
  }
}

function renderSparkline(containerEl, dayBuckets) {
  const days = [];
  const now = new Date();
  for (let i = 6; i >= 0; i--) {
    const d = new Date(now);
    d.setDate(d.getDate() - i);
    const key = d.toISOString().slice(0, 10);
    days.push({ key, label: d.toLocaleDateString(undefined, { weekday: 'short' }).slice(0,2), count: dayBuckets[key] || 0 });
  }
  const max = Math.max(...days.map(d => d.count), 1);
  containerEl.innerHTML = `
    <div class="sparkline-wrap">
      ${days.map(d => `<div class="spark-bar" style="height:${Math.max(2,(d.count/max)*100)}%" title="${d.key}: ${d.count}"></div>`).join('')}
    </div>
    <div class="spark-labels">${days.map(d => `<span>${d.label}</span>`).join('')}</div>
  `;
}

/**
 * A donut chart built entirely from CSS conic-gradient — no canvas, no
 * SVG library, no chart dependency. `segments` is [{label, count, color}].
 */
function renderDonutChart(containerEl, segments, opts) {
  opts = opts || {};
  const total = segments.reduce((sum, s) => sum + s.count, 0);
  if (total === 0) {
    containerEl.innerHTML = `<div style="font-size:11.5px;color:var(--text-faint);padding:8px 0;">No data yet</div>`;
    return;
  }

  let cursor = 0;
  const stops = segments.filter(s => s.count > 0).map(s => {
    const start = (cursor / total) * 100;
    cursor += s.count;
    const end = (cursor / total) * 100;
    return `${s.color} ${start}% ${end}%`;
  }).join(', ');

  containerEl.innerHTML = `
    <div class="donut-wrap">
      <div class="donut" style="background:conic-gradient(${stops});">
        <div class="donut-center"><div class="total">${total}</div><div class="label">${opts.centerLabel || 'total'}</div></div>
      </div>
      <div class="donut-legend">
        ${segments.map(s => `
          <div class="donut-legend-item">
            <span class="donut-legend-dot" style="background:${s.color}"></span>
            ${s.label}
            <span class="val">${s.count}</span>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}
