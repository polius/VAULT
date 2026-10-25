// Theme: Auto (follow the system), Light or Dark. Loaded as a classic script in
// <head> so the saved choice applies before first paint.
(() => {
  const KEY = 'vault-theme';
  const root = document.documentElement;

  function apply(mode) {
    if (mode === 'light' || mode === 'dark') root.setAttribute('data-theme', mode);
    else root.removeAttribute('data-theme');
    for (const b of document.querySelectorAll('[data-theme-set]')) {
      b.setAttribute('aria-pressed', String(b.dataset.themeSet === (mode || 'auto')));
    }
  }

  let saved = null;
  try {
    saved = localStorage.getItem(KEY);
  } catch {}
  apply(saved);

  document.addEventListener('DOMContentLoaded', () => {
    apply(saved);
    for (const b of document.querySelectorAll('[data-theme-set]')) {
      b.addEventListener('click', () => {
        saved = b.dataset.themeSet;
        apply(saved);
        try {
          localStorage.setItem(KEY, saved);
        } catch {}
      });
    }
  });
})();
