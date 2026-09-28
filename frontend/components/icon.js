/**
 * Renders a small source icon with a graceful fallback.
 * Icons are served from our own backend (GET /api/sources/{id}/icon),
 * which fetches the favicon once and caches it to disk — this never
 * hotlinks an external image URL from the browser. If the icon isn't
 * available (fetch failed, offline, 404), it's swapped for a plain
 * colored dot so the UI never shows a broken-image glyph.
 */
function sourceIconHtml(sourceId, color, sizeClass) {
  const cls = sizeClass || 'src-icon';
  if (!sourceId) {
    return `<span class="dot" style="background:${color}"></span>`;
  }
  return `<img class="${cls}" src="/api/sources/${sourceId}/icon" alt=""
            onerror="this.outerHTML='<span class=&quot;dot&quot; style=&quot;background:${color}&quot;></span>'">`;
}
