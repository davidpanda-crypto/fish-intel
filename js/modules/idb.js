/**
 * IndexedDB adapter — replaces localStorage for all persistent data.
 * Exposes window.AppIDB with async get/put/getAll/delete/clear.
 *
 * Stores:
 *   records   — saved facility/vessel records  (keyPath: id)
 *   cache     — TTL search result cache        (keyPath: key)
 *   knowledge — learned entities + domainStats (keyPath: key)
 */
(function () {
  const DB_NAME     = 'website-extractor-db';
  const DB_NAME_OLD = 'fish-intel-db';       // legacy — migrated on first open
  const DB_VERSION  = 2;  // v2: records keyPath fixed to 'id'
  let _db = null;

  function open() {
    if (_db) return Promise.resolve(_db);
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VERSION);

      req.onupgradeneeded = e => {
        const db  = e.target.result;
        const old = e.oldVersion;

        // cache + knowledge always use keyPath:'key'
        if (!db.objectStoreNames.contains('cache'))
          db.createObjectStore('cache',     { keyPath: 'key' });
        if (!db.objectStoreNames.contains('knowledge'))
          db.createObjectStore('knowledge', { keyPath: 'key' });

        // records uses keyPath:'id' — delete if it was accidentally created
        // with keyPath:'key' in DB v1, then recreate correctly.
        if (db.objectStoreNames.contains('records') && old < 2)
          db.deleteObjectStore('records');
        if (!db.objectStoreNames.contains('records'))
          db.createObjectStore('records',   { keyPath: 'id' });
      };

      req.onsuccess = e => { _db = e.target.result; resolve(_db); };
      req.onerror   = ()  => reject(req.error);
    });
  }

  const AppIDB = {
    /** Put a value. For 'records' store the object must have an `id` field.
     *  For 'cache'/'knowledge' the object must have a `key` field. */
    put(store, value) {
      return open().then(db => new Promise((resolve, reject) => {
        const t = db.transaction(store, 'readwrite');
        t.objectStore(store).put(value);
        t.oncomplete = resolve;
        t.onerror    = () => reject(t.error);
      }));
    },

    get(store, key) {
      return open().then(db => new Promise((resolve, reject) => {
        const t   = db.transaction(store, 'readonly');
        const req = t.objectStore(store).get(key);
        req.onsuccess = () => resolve(req.result);
        req.onerror   = () => reject(req.error);
      }));
    },

    getAll(store) {
      return open().then(db => new Promise((resolve, reject) => {
        const t   = db.transaction(store, 'readonly');
        const req = t.objectStore(store).getAll();
        req.onsuccess = () => resolve(req.result || []);
        req.onerror   = () => reject(req.error);
      }));
    },

    delete(store, key) {
      return open().then(db => new Promise((resolve, reject) => {
        const t = db.transaction(store, 'readwrite');
        t.objectStore(store).delete(key);
        t.oncomplete = resolve;
        t.onerror    = () => reject(t.error);
      }));
    },

    clear(store) {
      return open().then(db => new Promise((resolve, reject) => {
        const t = db.transaction(store, 'readwrite');
        t.objectStore(store).clear();
        t.oncomplete = resolve;
        t.onerror    = () => reject(t.error);
      }));
    },

    /** Put multiple items into a store in a single transaction. */
    putAll(store, items) {
      if (!items.length) return Promise.resolve();
      return open().then(db => new Promise((resolve, reject) => {
        const t = db.transaction(store, 'readwrite');
        const s = t.objectStore(store);
        items.forEach(item => s.put(item));
        t.oncomplete = resolve;
        t.onerror    = () => reject(t.error);
      }));
    },

    /** Persist all records in one transaction (replaces full set) */
    putAllRecords(records) {
      return open().then(db => new Promise((resolve, reject) => {
        const t = db.transaction('records', 'readwrite');
        const s = t.objectStore('records');
        s.clear();
        records.forEach(r => s.put(r));
        t.oncomplete = resolve;
        t.onerror    = () => reject(t.error);
      }));
    },

    /** One-time migration from localStorage → IDB */
    async migrateFromLocalStorage() {
      try {
        const raw = localStorage.getItem('ship_saved3');
        if (raw) {
          const records = JSON.parse(raw);
          if (records.length) await this.putAllRecords(records);
          localStorage.removeItem('ship_saved3');
          console.info('[IDB] Migrated', records.length, 'records from localStorage');
        }
        const lRaw = localStorage.getItem('ship_learned1');
        if (lRaw) {
          await this.put('knowledge', { key: 'learned', data: JSON.parse(lRaw) });
          localStorage.removeItem('ship_learned1');
        }
        const pfRaw = localStorage.getItem('ship_pfails1');
        if (pfRaw) {
          await this.put('knowledge', { key: 'pfails', data: JSON.parse(pfRaw) });
          localStorage.removeItem('ship_pfails1');
        }
      } catch (e) {
        console.warn('[IDB] Migration warning:', e);
      }
    },

    /**
     * One-time migration from the legacy 'fish-intel-db' database name.
     * Copies all data from the old DB into the current one, then deletes it.
     * Safe to call on every startup — exits immediately if the old DB is gone.
     */
    async migrateFromOldDB() {
      try {
        // Use indexedDB.databases() where available; fall back to optimistic open
        let oldExists = true;
        if ('databases' in indexedDB) {
          const dbs = await indexedDB.databases();
          oldExists = dbs.some(d => d.name === DB_NAME_OLD);
        }
        if (!oldExists) return;

        // Open the old DB (read-only — don't trigger its onupgradeneeded)
        const oldDb = await new Promise((resolve, reject) => {
          const req = indexedDB.open(DB_NAME_OLD);
          req.onsuccess = e => resolve(e.target.result);
          req.onerror   = () => reject(req.error);
        });

        const stores  = ['records', 'cache', 'knowledge'];
        let   migrated = 0;

        for (const store of stores) {
          if (!oldDb.objectStoreNames.contains(store)) continue;
          const items = await new Promise((resolve, reject) => {
            const t   = oldDb.transaction(store, 'readonly');
            const req = t.objectStore(store).getAll();
            req.onsuccess = () => resolve(req.result || []);
            req.onerror   = () => reject(req.error);
          });
          if (items.length) {
            await this.putAll(store, items);
            migrated += items.length;
          }
        }

        oldDb.close();
        indexedDB.deleteDatabase(DB_NAME_OLD);

        if (migrated > 0) {
          console.info('[IDB] Migrated', migrated, 'items from fish-intel-db → website-extractor-db');
        }
      } catch (e) {
        console.warn('[IDB] Old DB migration warning:', e);
      }
    },
  };

  window.AppIDB = AppIDB;
})();
