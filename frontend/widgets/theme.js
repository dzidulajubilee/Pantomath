/**
 * Light/dark theme toggle. The actual switch happens via a single
 * `data-theme` attribute on <html> — see themes/pantomath.css for the
 * variable overrides. This file just handles the two toggle controls
 * (header button + Settings row) and persistence.
 *
 * Applied early (see the inline script in dashboard.html's <head>) so
 * there's no flash of the wrong theme on load.
 */

function getTheme() {
  return document.documentElement.getAttribute('data-theme') || 'dark';
}

function setTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('pantomath-theme', theme);
  syncThemeControls();
}

function syncThemeControls() {
  const isLight = getTheme() === 'light';
  const headerBtn = document.getElementById('themeToggle');
  const settingsToggle = document.getElementById('themeToggleSettings');
  if (headerBtn) headerBtn.innerHTML = isLight ? '&#9788;' : '&#9789;'; // sun / moon glyph
  if (settingsToggle) settingsToggle.classList.toggle('on', isLight);
}

function initThemeControls() {
  syncThemeControls();
  document.getElementById('themeToggle').onclick = () => {
    setTheme(getTheme() === 'light' ? 'dark' : 'light');
  };
  document.getElementById('themeToggleSettings').onclick = () => {
    setTheme(getTheme() === 'light' ? 'dark' : 'light');
  };
}
