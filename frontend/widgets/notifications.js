/**
 * Desktop notifications for new items, using the standard browser
 * Notification API. Pantomath is a locally-hosted web app (not a native
 * Tauri/Electron app), so this is the correct mechanism for this
 * architecture — it produces real OS-level notification popups, but only
 * while this dashboard tab is open in the browser. There's no
 * background/service-worker push when the tab is closed; being upfront
 * about that in Settings rather than pretending otherwise.
 */

const SEVERITY_RANK = { high: 3, medium: 2, low: 1 };

function notifPrefs() {
  return {
    enabled: localStorage.getItem('pantomath-notif-enabled') === 'true',
    threshold: localStorage.getItem('pantomath-notif-threshold') || 'high',
  };
}

function saveNotifPrefs(enabled, threshold) {
  localStorage.setItem('pantomath-notif-enabled', String(enabled));
  localStorage.setItem('pantomath-notif-threshold', threshold);
}

function updatePermissionHint() {
  const el = document.getElementById('notifPermissionState');
  if (!el) return;
  if (!('Notification' in window)) {
    el.textContent = 'unsupported by this browser';
    el.style.color = 'var(--text-dim)';
    return;
  }
  if (!window.isSecureContext) {
    // Browsers block the Notification permission prompt entirely on
    // insecure origins (plain HTTP at anything other than localhost) —
    // requestPermission() silently resolves to "denied" with no dialog
    // ever shown. This is a browser policy, not something fixable in JS.
    el.textContent = 'blocked — insecure connection (see note below)';
    el.style.color = 'var(--amber)';
    return;
  }
  const state = Notification.permission;
  el.textContent = state;
  el.style.color = state === 'granted' ? 'var(--signal)' : (state === 'denied' ? 'var(--red)' : 'var(--text-dim)');
}

function insecureContextWarning() {
  const isIpAddress = /^(\d{1,3}\.){3}\d{1,3}$/.test(location.hostname);
  const suggestion = isIpAddress
    ? `Try accessing this dashboard as "http://localhost:${location.port}" if you're on the same machine Pantomath runs on, or put it behind HTTPS (a reverse proxy like Caddy/nginx with a certificate) for remote access.`
    : `Access this dashboard over HTTPS, or as "http://localhost:${location.port}" if you're on the same machine Pantomath runs on.`;
  return `Desktop notifications require a secure connection. This page is loaded over plain HTTP at "${location.hostname}", which isn't localhost or HTTPS — browsers block the notification permission prompt entirely on insecure origins, so no dialog will ever appear here no matter how many times you click this toggle. ${suggestion}`;
}

async function initNotificationControls() {
  const { enabled, threshold } = notifPrefs();
  const toggle = document.getElementById('notifToggle');
  const thresholdSelect = document.getElementById('notifThreshold');

  toggle.classList.toggle('on', enabled && ('Notification' in window) && Notification.permission === 'granted');
  thresholdSelect.value = threshold;
  updatePermissionHint();

  toggle.onclick = async () => {
    if (!('Notification' in window)) {
      alert('This browser does not support desktop notifications.');
      return;
    }
    const turningOn = !toggle.classList.contains('on');
    if (turningOn) {
      if (!window.isSecureContext) {
        alert(insecureContextWarning());
        return;
      }
      const permission = await Notification.requestPermission();
      updatePermissionHint();
      if (permission !== 'granted') {
        alert('Notification permission was not granted — check your browser\'s site settings for this page.');
        return;
      }
      saveNotifPrefs(true, thresholdSelect.value);
      toggle.classList.add('on');
      new Notification('Pantomath notifications enabled', {
        body: `You'll be notified for ${thresholdSelect.options[thresholdSelect.selectedIndex].text.toLowerCase()} items.`,
      });
    } else {
      saveNotifPrefs(false, thresholdSelect.value);
      toggle.classList.remove('on');
    }
  };

  thresholdSelect.onchange = () => {
    saveNotifPrefs(notifPrefs().enabled, thresholdSelect.value);
  };
}

/** Called from the WebSocket handler in app.js whenever new items arrive. */
function notifyForNewItems(items) {
  const { enabled, threshold } = notifPrefs();
  if (!enabled || !('Notification' in window) || Notification.permission !== 'granted') return;

  const minRank = SEVERITY_RANK[threshold] || 3;
  const qualifying = items.filter(i => (SEVERITY_RANK[i.severity] || 0) >= minRank);
  if (qualifying.length === 0) return;

  if (qualifying.length === 1) {
    const i = qualifying[0];
    const n = new Notification(`[${i.severity.toUpperCase()}] ${i.source_name}`, { body: i.title });
    n.onclick = () => { window.focus(); window.open(i.link, '_blank'); };
  } else {
    new Notification('Pantomath', { body: `${qualifying.length} new items match your notification threshold.` });
  }
}
