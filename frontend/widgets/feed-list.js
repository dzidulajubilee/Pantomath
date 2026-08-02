/**
 * Renders a list of intelligence items into a container, with a Save
 * (bookmark) and Open Original button on each card. Reused by Live Feed,
 * Critical, Vulnerabilities, Malware, Ransomware, Vendors, Threat Actors,
 * Saved, and the Dashboard's "Latest intelligence" panel — each just
 * passes a different pre-filtered item list.
 */

async function fetchItems(params) {
  const qs = new URLSearchParams(params).toString();
  const res = await fetch('/api/items?' + qs);
  return res.json();
}

async function toggleBookmark(itemId, bookmarked) {
  await fetch(`/api/items/${itemId}/bookmark?bookmarked=${bookmarked}`, { method: 'PATCH' });
}

/**
 * Truncates at the end of the first complete sentence instead of an
 * arbitrary character count, so cards read as a finished thought rather
 * than cutting off mid-word. Falls back to a hard cut with an ellipsis
 * only if no sentence-ending punctuation shows up within a reasonable
 * window (some summaries are just one long run-on sentence or a
 * fragment with no period at all).
 */
function truncateAtSentence(text, targetLen, maxLen) {
  targetLen = targetLen || 220;
  maxLen = maxLen || 320;
  if (text.length <= targetLen) return text;

  const window = text.slice(0, maxLen);
  // Look for '.', '!', or '?' followed by a space/end-of-string — avoids
  // stopping at abbreviation-style periods like "U.S." or "Inc." by
  // requiring whitespace (or end of the window) right after it.
  const sentenceEnd = /[.!?](?=\s|$)/g;
  let match, lastGoodMatch = null;
  while ((match = sentenceEnd.exec(window)) !== null) {
    if (match.index + 1 >= targetLen * 0.5) {  // don't stop on a too-short first "sentence"
      lastGoodMatch = match.index + 1;
      break;  // first qualifying sentence end is what we want
    }
  }
  if (lastGoodMatch) return text.slice(0, lastGoodMatch);
  return text.slice(0, targetLen).trim() + '…';
}

function renderFeedCards(containerEl, items, opts) {
  opts = opts || {};
  if (items.length === 0) {
    containerEl.innerHTML = `<div class="empty-state">
      <h3>${opts.emptyTitle || 'Nothing here yet'}</h3>
      <div>${opts.emptyHint || 'Check back after the next poll cycle.'}</div>
    </div>`;
    return;
  }

  containerEl.innerHTML = items.map(i => `
    <div class="item sev-${i.severity}" data-item-id="${i.id}">
      <div class="item-main">
        <div class="item-head">
          <span class="src-tag" style="background:${i.source_color}22; color:${i.source_color}">
            ${sourceIconHtml(i.source_id, i.source_color)}
            ${escapeHtml(i.source_name)}
          </span>
          ${(i.vendors||[]).slice(0,2).map(v => `<span class="tag-chip" style="padding:2px 8px; margin:0;">${escapeHtml(v)}</span>`).join('')}
          ${(i.actors||[]).slice(0,2).map(a => `<span class="tag-chip" style="padding:2px 8px; margin:0; color:var(--red); border-color:var(--red);">${escapeHtml(a)}</span>`).join('')}
          ${(i.cves||[]).slice(0,2).map(c => `<span class="tag-chip" style="padding:2px 8px; margin:0; color:var(--signal); border-color:var(--signal);">${escapeHtml(c)}</span>`).join('')}
          <span class="item-time">${timeAgo(i.fetched_at)}</span>
        </div>
        <div class="item-title"><a href="${safeHref(i.link)}" target="_blank" rel="noopener">${escapeHtml(i.title)}</a></div>
        <div class="item-summary">${escapeHtml(truncateAtSentence(stripHtml(i.summary)))}</div>
      </div>
      <div class="item-side">
        <span class="sev-pill sev-${i.severity}">${i.severity}</span>
        <div style="display:flex; gap:2px;">
          <button class="save-btn ${i.bookmarked ? 'saved' : ''}" data-action="bookmark" data-id="${i.id}" data-bookmarked="${i.bookmarked}" title="Save">${i.bookmarked ? '&#9733;' : '&#9734;'}</button>
          <a class="save-btn" href="${safeHref(i.link)}" target="_blank" rel="noopener" title="Open original">&#8599;</a>
        </div>
      </div>
    </div>
  `).join('');

  containerEl.querySelectorAll('[data-action="bookmark"]').forEach(btn => {
    btn.onclick = async () => {
      const newState = btn.dataset.bookmarked !== 'true';
      await toggleBookmark(btn.dataset.id, newState);
      btn.dataset.bookmarked = newState;
      btn.classList.toggle('saved', newState);
      btn.innerHTML = newState ? '&#9733;' : '&#9734;';
      if (opts.onBookmarkChange) opts.onBookmarkChange();
    };
  });
}
