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
  containerEl.innerHTML = data.map(d => `
    <div class="bar-row">
      <span class="bar-label" title="${d.label}">${d.label}</span>
      <div class="bar-track"><div class="bar-fill" style="width:${Math.max(4, (d.count/max)*100)}%; background:${colorFn(d.label)}"></div></div>
      <span class="bar-count">${d.count}</span>
    </div>
  `).join('');
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
