/**
 * TTL-aware search result cache backed by IndexedDB.
 * Falls back to a session Map when IDB is unavailable.
 *
 * Exposes window.AppCache with get / set / invalidate methods.
 *
 * Default TTL: 30 minutes (configurable).
 */
(function () {
  const DEFAULT_TTL_MS = 30 * 60 * 1000; // 30 min

  // In-memory fallback (session-scoped, cleared on page refresh)
  const _mem = new Map();

  const AppCache = {
    /**
     * Retrieve a cached result by key.
     * Returns null when missing or expired.
     * @param {string} key
     * @returns {Promise<any|null>}
     */
    async get(key) {
      // Try IDB first
      if (window.AppIDB) {
        try {
          const entry = await AppIDB.get('cache', key);
          if (!entry) return this._memGet(key);
          if (Date.now() - entry.ts > (entry.ttl || DEFAULT_TTL_MS)) {
            await AppIDB.delete('cache', key);
            return null;
          }
          return entry.data;
        } catch {
          return this._memGet(key);
        }
      }
      return this._memGet(key);
    },

    /**
     * Store a result under key with optional custom TTL (ms).
     * @param {string} key
     * @param {any} data
     * @param {number} [ttl]
     */
    async set(key, data, ttl = DEFAULT_TTL_MS) {
      const entry = { key, data, ts: Date.now(), ttl };
      // Write to IDB
      if (window.AppIDB) {
        try { await AppIDB.put('cache', entry); } catch {}
      }
      // Always write to memory as hot path
      _mem.set(key, entry);
      // Purge expired + oldest entries when memory store grows too large
      if (_mem.size > 100) {
        const now = Date.now();
        for (const [k, e] of _mem) {
          if (now - e.ts > (e.ttl || DEFAULT_TTL_MS)) _mem.delete(k);
        }
        if (_mem.size > 100) {
          // Still over cap — evict the 20 oldest entries
          [..._mem.entries()]
            .sort((a, b) => a[1].ts - b[1].ts)
            .slice(0, 20)
            .forEach(([k]) => _mem.delete(k));
        }
      }
    },

    /**
     * Remove a specific key from both stores.
     */
    async invalidate(key) {
      _mem.delete(key);
      if (window.AppIDB) {
        try { await AppIDB.delete('cache', key); } catch {}
      }
    },

    /**
     * Build a canonical cache key for a search.
     * Normalises whitespace and casing so "  Mowi ASA " === "mowi asa".
     */
    key(query, type = '') {
      return `search:${(query || '').toLowerCase().trim().replace(/\s+/g, ' ')}:${type}`;
    },

    // ── Private ──────────────────────────────────────────────────────────────

    _memGet(key) {
      const entry = _mem.get(key);
      if (!entry) return null;
      if (Date.now() - entry.ts > (entry.ttl || DEFAULT_TTL_MS)) {
        _mem.delete(key);
        return null;
      }
      return entry.data;
    },
  };

  window.AppCache = AppCache;
})();
