// Theme: Auto (follow the system), Light or Dark. Loaded as a classic script in
// <head> so the saved choice applies before first paint. One button cycles
// through the three and names the current one.
(() => {
  const KEY = 'vault-theme';
  const MODES = ['auto', 'light', 'dark'];
  const NAMES = { auto: 'Auto', light: 'Light', dark: 'Dark' };
  const root = document.documentElement;

  const normal = (mode) => (MODES.includes(mode) ? mode : 'auto');

  function apply(mode) {
    const m = normal(mode);
    if (m === 'auto') root.removeAttribute('data-theme');
    else root.setAttribute('data-theme', m);
    for (const el of document.querySelectorAll('[data-theme-name]')) el.textContent = NAMES[m];
    for (const b of document.querySelectorAll('[data-theme-cycle]')) {
      b.dataset.theme = m;
      b.setAttribute('aria-label', `Theme: ${NAMES[m]}. Change theme`);
    }
  }

  let saved = null;
  try {
    saved = localStorage.getItem(KEY);
  } catch {}
  apply(saved);

  document.addEventListener('DOMContentLoaded', () => {
    apply(saved);
    for (const b of document.querySelectorAll('[data-theme-cycle]')) {
      b.addEventListener('click', () => {
        saved = MODES[(MODES.indexOf(normal(saved)) + 1) % MODES.length];
        apply(saved);
        try {
          localStorage.setItem(KEY, saved);
        } catch {}
      });
    }
  });
})();
