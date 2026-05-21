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
  const DB_NAME    = 'fish-intel-db';
  const DB_VERSION = 1;
  let _db = null;

  function open() {
    if (_db) return Promise.resolve(_db);
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VERSION);

      req.onupgradeneeded = e => {
        const db = e.target.result;
        ['records', 'cache', 'knowledge'].forEach(name => {
          if (!db.objectStoreNames.contains(name)) {
            db.createObjectStore(name, { keyPath: 'key' });
          }
        });
        // records store uses 'id' as keyPath — recreate with correct keyPath
        if (db.objectStoreNames.contains('records')) {
          db.deleteObjectStore('records');
        }
        db.createObjectStore('records', { keyPath: 'id' });
      };

      req.onsuccess = e => { _db = e.target.result; resolve(_db); };
      req.onerror   = ()  => reject(req.error);
    });
  }

  function tx(store, mode, fn) {
    return open().then(db => new Promise((resolve, reject) => {
      const t   = db.transaction(store, mode);
      const req = fn(t.objectStore(store));
      t.oncomplete = () => resolve(req ? req.result : undefined);
      t.onerror    = ()  => reject(t.error);
      if (req) req.onsuccess = () => {}; // let transaction complete
    }));
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
  };

  window.AppIDB = AppIDB;
})();
