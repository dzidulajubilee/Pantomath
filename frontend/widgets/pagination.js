/**
 * Numbered pagination — first/prev, a windowed set of page numbers with
 * ellipsis for large page counts, next/last. Replaces the old "Load
 * more" button: with severity/keyword filters now fully server-side
 * (see app.js), the backend can report an accurate total, so real page
 * numbers are meaningful instead of an open-ended "keep clicking to
 * load more" pattern.
 */
function renderPagination(containerEl, currentPage, totalPages, onPageClick) {
  if (totalPages <= 1) {
    containerEl.innerHTML = '';
    return;
  }

  const windowSize = 2; // pages shown on each side of the current page
  const pages = new Set([1, totalPages]);
  for (let p = currentPage - windowSize; p <= currentPage + windowSize; p++) {
    if (p >= 1 && p <= totalPages) pages.add(p);
  }
  const sorted = [...pages].sort((a, b) => a - b);

  let html = `<button class="page-btn" data-page="1" ${currentPage === 1 ? 'disabled' : ''} title="First page">&#171;</button>`;
  html += `<button class="page-btn" data-page="${currentPage - 1}" ${currentPage === 1 ? 'disabled' : ''} title="Previous page">&#8249;</button>`;

  let prev = 0;
  for (const p of sorted) {
    if (p - prev > 1) html += `<span class="page-ellipsis">…</span>`;
    html += `<button class="page-btn ${p === currentPage ? 'active' : ''}" data-page="${p}">${p}</button>`;
    prev = p;
  }

  html += `<button class="page-btn" data-page="${currentPage + 1}" ${currentPage === totalPages ? 'disabled' : ''} title="Next page">&#8250;</button>`;
  html += `<button class="page-btn" data-page="${totalPages}" ${currentPage === totalPages ? 'disabled' : ''} title="Last page">&#187;</button>`;

  containerEl.innerHTML = html;
  containerEl.querySelectorAll('.page-btn:not(:disabled)').forEach(btn => {
    btn.onclick = () => onPageClick(parseInt(btn.dataset.page, 10));
  });
}
