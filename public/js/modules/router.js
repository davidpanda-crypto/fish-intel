/**
 * Hash-based router — makes searches shareable / bookmarkable.
 *
 * URL format:  #search?q=Mowi+ASA&t=farm
 *              #record?id=abc123
 *
 * Exposes window.AppRouter with read / write / init methods.
 */
(function () {
  const AppRouter = {
    /**
     * Parse the current URL hash into { path, q, t, id }
     * Returns null when hash is empty.
     */
    read() {
      try {
        const hash = location.hash.slice(1);
        if (!hash) return null;
        const [path, qs = ''] = hash.split('?');
        const p = new URLSearchParams(qs);
        return {
          path: path || 'search',
          q:    p.get('q') || '',
          t:    p.get('t') || 'farm',
          id:   p.get('id') || '',
        };
      } catch { return null; }
    },

    /**
     * Push a new route without reloading the page.
     * @param {string} path  e.g. 'search'
     * @param {Object} params  e.g. { q: 'Mowi ASA', t: 'farm' }
     */
    write(path, params = {}) {
      const qs = new URLSearchParams(
        Object.fromEntries(Object.entries(params).filter(([, v]) => v))
      ).toString();
      const hash = '#' + path + (qs ? '?' + qs : '');
      // pushState: adds a history entry so the browser Back button returns to the previous search
      history.pushState(null, '', hash);
    },

    /**
     * Clear the route (e.g. after a search is cancelled).
     */
    clear() {
      history.replaceState(null, '', location.pathname);
    },

    /**
     * Boot: read the current hash and trigger the matching action.
     * Call this once after the app is initialised.
     * Requires window.setMode and window.runBot to already be defined.
     */
    init() {
      const state = this.read();
      if (!state) return;

      if (state.path === 'search' && state.q) {
        const input = document.getElementById('main-search');
        const sel   = document.getElementById('search-type');
        if (input) input.value = decodeURIComponent(state.q);
        if (sel && state.t) sel.value = state.t;
        // Small delay so the app is fully rendered before auto-running
        setTimeout(() => {
          if (typeof window.setMode === 'function') window.setMode('search');
          if (typeof window.runBot  === 'function') window.runBot();
        }, 120);
      }

      // Handle browser back/forward
      window.addEventListener('popstate', () => {
        const s = this.read();
        if (!s && typeof window.cancelSearch === 'function') window.cancelSearch();
      });
    },
  };

  window.AppRouter = AppRouter;
})();
