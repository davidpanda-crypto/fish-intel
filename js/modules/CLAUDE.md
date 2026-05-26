# js/modules/ — CLAUDE.md

Three lightweight modules loaded before `app.js`. Each is an IIFE that exposes a single object on `window`. They have no dependencies on each other or on `app.js`.

Load order in `index.html`: `idb.js` → `router.js` → `cache.js` → `app.js`

---

## idb.js — `window.AppIDB`

IndexedDB adapter that replaces localStorage for all persistent data.

**Database**: `fish-intel-db`, version 2

**Stores**:

| Store | keyPath | Contents |
|---|---|---|
| `records` | `id` | Saved facility/vessel records |
| `cache` | `key` | TTL search result cache entries |
| `knowledge` | `key` | Learned entities, domain stats, proxy health, Claude settings |

**API**:

```js
AppIDB.put(store, value)           // Write; object must include the store's keyPath field
AppIDB.get(store, key)             // Read by key → value or undefined
AppIDB.getAll(store)               // Read all → array
AppIDB.delete(store, key)          // Delete by key
AppIDB.clear(store)                // Delete everything in store
AppIDB.putAllRecords(records)      // Bulk replace all records in one transaction
AppIDB.migrateFromLocalStorage()   // One-time migration from legacy localStorage keys
```

**Migration**: On first run, `migrateFromLocalStorage()` reads `ship_saved3`, `ship_learned1`, and `ship_pfails1` from localStorage, writes them to the appropriate IDB stores, then removes the localStorage keys. Call this once during app init.

**Version history**:
- v1 → v2: `records` store keyPath was accidentally `'key'`; v2 migration deletes and recreates it with `keyPath: 'id'`.

**Known keys in `knowledge` store**:

| key | Contents |
|---|---|
| `'learned'` | Entity knowledge base object |
| `'pfails'` | Proxy health tracking object |
| `'claude-settings'` | `{ key: string, model: string }` API key + model selection |
| `'domainStats'` | Per-hostname success rate tracking |

---

## router.js — `window.AppRouter`

Hash-based URL router. Makes searches bookmarkable and shareable without a server.

**URL format**:
- Search: `#search?q=Mowi+ASA&t=farm`
- Record view: `#record?id=abc123`

**API**:

```js
AppRouter.read()                    // Parse current hash → { path, q, t, id } or null
AppRouter.write(path, params)       // Push new hash route (adds browser history entry)
AppRouter.clear()                   // Remove hash from URL (replaceState, no history entry)
AppRouter.init()                    // Boot: run search from URL if hash present; wire popstate
```

**`init()` behavior**: Reads the current hash on page load. If it finds `#search?q=...`, it populates the search input, sets the type selector, and calls `window.runBot()` after a 120ms delay (to let the DOM settle). It also wires `popstate` so the browser Back button calls `window.cancelSearch()`.

**Dependencies**: `AppRouter.init()` requires `window.setMode` and `window.runBot` to already exist — call it after `app.js` has initialized.

---

## cache.js — `window.AppCache`

TTL-aware search result cache. IDB-backed with an in-memory session Map as hot path and fallback.

**Default TTL**: 30 minutes

**API**:

```js
AppCache.key(query, type)           // Build canonical cache key (lowercased, whitespace-normalized)
AppCache.get(key)                   // → Promise<data|null>; returns null if missing or expired
AppCache.set(key, data, ttl?)       // Store with optional custom TTL in ms
AppCache.invalidate(key)            // Remove from both IDB and memory
```

**Cache key format**: `search:<normalized-query>:<type>` — e.g. `search:mowi asa:farm`

**Eviction**: When the in-memory Map exceeds 100 entries, expired entries are removed first; if still over 100, the 20 oldest entries are evicted.

**Behavior**: Reads check IDB first, then the memory Map. Writes go to both simultaneously. If IDB is unavailable (private browsing, quota exceeded), the memory Map provides session-scoped caching.

---

## Module loading notes

- All three modules are loaded with `<script src="..." type="module">` — they execute before `app.js`
- Asset versioning: URLs include `?v=N` cache-busting query params; increment in `index.html` when a module changes
- The service worker pre-caches all three module files on install — increment `CACHE_VER` in `sw.js` when module files change
