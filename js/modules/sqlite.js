/**
 * fish-intel — Browser SQLite layer (sql.js / WebAssembly)
 * PRIMARY database for saved records.
 *
 * Exposed as window.AppSQLite. sql.js WASM is lazy-loaded from CDN on first
 * use. The binary .db file is persisted to IndexedDB after every write — IDB
 * is used only to store that one blob, not individual records.
 *
 * Public API
 * ──────────
 *   init()                  → bool   — load WASM, open DB, create schema
 *   upsert(record)          → bool   — insert or update one entity + species
 *   batchUpsert(records[])  → count  — all records in one transaction
 *   remove(localId)         → bool   — delete entity (cascades to children)
 *   clearAll()              → void   — DELETE all entities
 *   getAllEntities()         → obj[]  — all rows as plain JS objects
 *   rowToRecord(row)        → record — maps DB row → fish-intel record format
 *   addImages(id, imgs[])   → void   — add scraped images
 *   logSearch(q, type, n)   → void   — append to search_history
 *   bulkImport(records[])   → count  — alias for batchUpsert (migration helper)
 *   query(sql, params)      → result — raw sql.js exec result
 *   getStats()              → obj    — counts across all tables
 *   exportDB()              → Uint8Array  — download as .db file
 *   importDB(ArrayBuffer)   → bool   — load from .db file
 */
(function () {
  'use strict';

  const SQL_JS_CDN = 'https://cdn.jsdelivr.net/npm/sql.js@1.12.0/dist/sql-wasm.min.js';
  const WASM_BASE  = 'https://cdn.jsdelivr.net/npm/sql.js@1.12.0/dist/';
  const IDB_KEY    = 'sqlite-db';

  let _SQL         = null;
  let _db          = null;
  let _ready       = false;
  let _initPromise = null;

  /* ─────────────────────────────────────────────────────────────────
     SCHEMA
  ───────────────────────────────────────────────────────────────── */
  const SCHEMA = `
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS entities (
      id                    INTEGER PRIMARY KEY AUTOINCREMENT,
      local_id              TEXT    UNIQUE NOT NULL,
      directus_id           TEXT,

      -- Identity
      name                  TEXT,
      farm_name             TEXT,
      vessel_name           TEXT,
      entity_type           TEXT,    -- farm | vessel | mill | general
      category              TEXT,

      -- People / org
      operator              TEXT,
      owner                 TEXT,
      manager               TEXT,

      -- Location
      country               TEXT,
      flag                  TEXT,
      region                TEXT,
      latitude              REAL,
      longitude             REAL,

      -- Aquaculture
      water_type            TEXT,
      production_method     TEXT,
      capacity              TEXT,
      total_area            TEXT,
      stocking_density      TEXT,
      harvest_cycles        TEXT,
      water_temp            TEXT,
      salinity              TEXT,
      dissolved_oxygen      TEXT,
      ph                    TEXT,
      fcr                   TEXT,
      feed_type             TEXT,

      -- Fish mill
      processing_capacity   TEXT,
      input_species         TEXT,
      output_products       TEXT,
      fishmeal_pct          TEXT,
      fishoil_pct           TEXT,

      -- Vessel
      imo                   TEXT,
      mmsi                  TEXT,
      call_sign             TEXT,
      vessel_type           TEXT,
      gross_tonnage         TEXT,
      dwt                   TEXT,
      year_built            INTEGER,
      port_of_registry      TEXT,
      vessel_length         TEXT,
      beam                  TEXT,
      nav_status            TEXT,
      class_soc             TEXT,

      -- Shared content
      species               TEXT,
      certification         TEXT,
      license               TEXT,
      employees             TEXT,
      description           TEXT,

      -- User annotations
      notes                 TEXT,
      verified              INTEGER DEFAULT 0,

      -- Timestamps
      saved_at              TEXT,
      created_at            TEXT    DEFAULT (datetime('now')),
      updated_at            TEXT    DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS entity_species (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      entity_id     INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
      species_name  TEXT    NOT NULL
    );

    CREATE TABLE IF NOT EXISTS entity_images (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      entity_id   INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
      src         TEXT    NOT NULL,
      label       TEXT,
      added_at    TEXT    DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS entity_sources (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      entity_id   INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
      url         TEXT    NOT NULL,
      scraped_at  TEXT    DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS search_history (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      query         TEXT    NOT NULL,
      search_type   TEXT,
      result_count  INTEGER DEFAULT 0,
      searched_at   TEXT    DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_entities_local_id ON entities(local_id);
    CREATE INDEX IF NOT EXISTS idx_entities_type     ON entities(entity_type);
    CREATE INDEX IF NOT EXISTS idx_entities_country  ON entities(country);
    CREATE INDEX IF NOT EXISTS idx_entities_imo      ON entities(imo);
    CREATE INDEX IF NOT EXISTS idx_spc_eid           ON entity_species(entity_id);
    CREATE INDEX IF NOT EXISTS idx_img_eid           ON entity_images(entity_id);

    CREATE VIEW IF NOT EXISTS v_entities_full AS
    SELECT
      e.*,
      (SELECT json_group_array(s.species_name)
       FROM entity_species s WHERE s.entity_id = e.id) AS species_list,
      (SELECT COUNT(*) FROM entity_images i WHERE i.entity_id = e.id) AS image_count
    FROM entities e;
  `;

  /* ─────────────────────────────────────────────────────────────────
     INIT
  ───────────────────────────────────────────────────────────────── */
  async function _loadSqlJs() {
    if (window.initSqlJs) return;
    await new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = SQL_JS_CDN; s.crossOrigin = 'anonymous';
      s.onload = resolve;
      s.onerror = () => reject(new Error('sql.js CDN load failed'));
      document.head.appendChild(s);
    });
  }

  async function init() {
    if (_ready) return true;
    if (_initPromise) return _initPromise;
    _initPromise = (async () => {
      try {
        await _loadSqlJs();
        _SQL = await window.initSqlJs({ locateFile: f => WASM_BASE + f });
        let existing = null;
        if (window.AppIDB) {
          const entry = await AppIDB.get('knowledge', IDB_KEY).catch(() => null);
          if (entry?.data) existing = entry.data;
        }
        _db    = existing ? new _SQL.Database(existing) : new _SQL.Database();
        _ready = true;
        _db.run(SCHEMA);
        console.info('[SQLite] Ready —', existing ? 'loaded from IDB' : 'new database');
        return true;
      } catch (e) {
        console.error('[SQLite] Init failed:', e);
        _initPromise = null;
        return false;
      }
    })();
    return _initPromise;
  }

  /* ─────────────────────────────────────────────────────────────────
     PERSIST BINARY → IDB
  ───────────────────────────────────────────────────────────────── */
  async function _persist() {
    if (!_db || !window.AppIDB) return;
    try {
      const data = _db.export();
      await AppIDB.put('knowledge', { key: IDB_KEY, data });
    } catch (e) { console.warn('[SQLite] IDB persist failed:', e.message); }
  }

  /* ─────────────────────────────────────────────────────────────────
     INTERNAL UPSERT (synchronous — sql.js is synchronous in-memory)
  ───────────────────────────────────────────────────────────────── */
  function _upsertSync(record) {
    const lid = record._id || record.id;
    const lat = parseFloat(record.latitude)   || null;
    const lng = parseFloat(record.longitude)  || null;
    const yb  = parseInt(record.year_built, 10) || null;

    _db.run(`
      INSERT INTO entities (
        local_id, name, farm_name, vessel_name, entity_type, category,
        operator, owner, manager,
        country, flag, region, latitude, longitude,
        water_type, production_method, capacity, total_area,
        stocking_density, harvest_cycles, water_temp, salinity,
        dissolved_oxygen, ph, fcr, feed_type,
        processing_capacity, input_species, output_products, fishmeal_pct, fishoil_pct,
        imo, mmsi, call_sign, vessel_type, gross_tonnage, dwt, year_built,
        port_of_registry, vessel_length, beam, nav_status, class_soc,
        species, certification, license, employees, description,
        notes, verified, saved_at
      ) VALUES (
        ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,
        ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?
      )
      ON CONFLICT(local_id) DO UPDATE SET
        name=excluded.name, farm_name=excluded.farm_name,
        vessel_name=excluded.vessel_name, entity_type=excluded.entity_type,
        category=excluded.category,
        operator=excluded.operator, owner=excluded.owner, manager=excluded.manager,
        country=excluded.country, flag=excluded.flag, region=excluded.region,
        latitude=excluded.latitude, longitude=excluded.longitude,
        water_type=excluded.water_type, production_method=excluded.production_method,
        capacity=excluded.capacity, total_area=excluded.total_area,
        stocking_density=excluded.stocking_density, harvest_cycles=excluded.harvest_cycles,
        water_temp=excluded.water_temp, salinity=excluded.salinity,
        dissolved_oxygen=excluded.dissolved_oxygen, ph=excluded.ph,
        fcr=excluded.fcr, feed_type=excluded.feed_type,
        processing_capacity=excluded.processing_capacity,
        input_species=excluded.input_species, output_products=excluded.output_products,
        fishmeal_pct=excluded.fishmeal_pct, fishoil_pct=excluded.fishoil_pct,
        imo=excluded.imo, mmsi=excluded.mmsi, call_sign=excluded.call_sign,
        vessel_type=excluded.vessel_type, gross_tonnage=excluded.gross_tonnage,
        dwt=excluded.dwt, year_built=excluded.year_built,
        port_of_registry=excluded.port_of_registry, vessel_length=excluded.vessel_length,
        beam=excluded.beam, nav_status=excluded.nav_status, class_soc=excluded.class_soc,
        species=excluded.species, certification=excluded.certification,
        license=excluded.license, employees=excluded.employees,
        description=excluded.description, notes=excluded.notes,
        verified=excluded.verified, saved_at=excluded.saved_at,
        updated_at=datetime('now')
    `, [
      lid,
      record.name        || null, record.farm_name   || null, record.vessel_name || null,
      record._facilityType || null, record._category || null,
      record.operator || null, record.owner    || null, record.manager  || null,
      record.country  || null, record.flag     || null, record.region   || null, lat, lng,
      record.water_type        || null, record.production_method  || null,
      record.capacity          || null, record.total_area         || null,
      record.stocking_density  || null, record.harvest_cycles     || null,
      record.water_temp        || null, record.salinity           || null,
      record.dissolved_oxygen  || null, record.ph                 || null,
      record.fcr               || null, record.feed_type          || null,
      record.processing_capacity || null, record.input_species    || null,
      record.output_products   || null, record.fishmeal_pct       || null,
      record.fishoil_pct       || null,
      record.imo || record._imo  || null, record.mmsi     || null,
      record.call_sign         || null, record.vessel_type        || null,
      record.gross_tonnage     || null, record.dwt                || null, yb,
      record.port_of_registry  || null, record.length             || null,
      record.beam              || null, record.nav_status         || null,
      record.class_soc         || null,
      record.species           || null, record.certification      || null,
      record.license           || null, record.employees          || null,
      record.description       || null,
      record._notes || null, record._verified ? 1 : 0, record._savedAt || null,
    ]);

    // Sync normalized species (delete + re-insert)
    const res = _db.exec('SELECT id FROM entities WHERE local_id = ?', [lid]);
    if (res.length && res[0].values.length) {
      const eid = res[0].values[0][0];
      _db.run('DELETE FROM entity_species WHERE entity_id = ?', [eid]);
      const sp = record.species || record.input_species || '';
      sp.split(',').map(s => s.trim()).filter(Boolean).forEach(name => {
        _db.run('INSERT INTO entity_species (entity_id, species_name) VALUES (?,?)', [eid, name]);
      });
    }
  }

  /* ─────────────────────────────────────────────────────────────────
     PUBLIC: SINGLE UPSERT
  ───────────────────────────────────────────────────────────────── */
  async function upsert(record) {
    if (!await init()) return false;
    try { _upsertSync(record); await _persist(); return true; }
    catch (e) { console.error('[SQLite] upsert failed:', e); return false; }
  }

  /* ─────────────────────────────────────────────────────────────────
     PUBLIC: BATCH UPSERT — one transaction + one IDB write
  ───────────────────────────────────────────────────────────────── */
  async function batchUpsert(records) {
    if (!records || !records.length || !await init()) return 0;
    let count = 0;
    try {
      _db.run('BEGIN TRANSACTION');
      for (const r of records) {
        try { _upsertSync(r); count++; }
        catch (e) { console.warn('[SQLite] batch item failed:', r._id, e.message); }
      }
      _db.run('COMMIT');
      await _persist();
    } catch (e) {
      try { _db.run('ROLLBACK'); } catch {}
      console.error('[SQLite] batchUpsert failed:', e);
    }
    return count;
  }

  /* ─────────────────────────────────────────────────────────────────
     PUBLIC: DELETE
  ───────────────────────────────────────────────────────────────── */
  async function remove(localId) {
    if (!await init()) return false;
    try {
      _db.run('DELETE FROM entities WHERE local_id = ?', [localId]);
      await _persist();
      return true;
    } catch (e) { console.error('[SQLite] remove failed:', e); return false; }
  }

  /* ─────────────────────────────────────────────────────────────────
     PUBLIC: CLEAR ALL
  ───────────────────────────────────────────────────────────────── */
  async function clearAll() {
    if (!await init()) return;
    try {
      _db.run('DELETE FROM entities');
      await _persist();
    } catch (e) { console.error('[SQLite] clearAll failed:', e); }
  }

  /* ─────────────────────────────────────────────────────────────────
     PUBLIC: LOAD ALL ENTITIES → plain JS objects
  ───────────────────────────────────────────────────────────────── */
  async function getAllEntities() {
    if (!await init()) return [];
    try {
      const res = _db.exec(
        'SELECT * FROM entities ORDER BY COALESCE(saved_at, created_at) DESC'
      );
      if (!res.length) return [];
      const { columns, values } = res[0];
      return values.map(row => Object.fromEntries(columns.map((c, i) => [c, row[i]])));
    } catch (e) { console.error('[SQLite] getAllEntities failed:', e); return []; }
  }

  /* ─────────────────────────────────────────────────────────────────
     PUBLIC: MAP DB ROW → fish-intel record format
  ───────────────────────────────────────────────────────────────── */
  function rowToRecord(row) {
    return {
      id:                  row.local_id,
      _id:                 row.local_id,
      _savedAt:            row.saved_at            || null,
      _notes:              row.notes               || '',
      _verified:           row.verified            === 1,
      _category:           row.category            || '',
      _facilityType:       row.entity_type         || 'farm',
      name:                row.name                || null,
      farm_name:           row.farm_name           || null,
      vessel_name:         row.vessel_name         || null,
      operator:            row.operator            || null,
      owner:               row.owner               || null,
      manager:             row.manager             || null,
      country:             row.country             || null,
      flag:                row.flag                || null,
      region:              row.region              || null,
      latitude:            row.latitude            || null,
      longitude:           row.longitude           || null,
      water_type:          row.water_type          || null,
      production_method:   row.production_method   || null,
      capacity:            row.capacity            || null,
      total_area:          row.total_area          || null,
      stocking_density:    row.stocking_density    || null,
      harvest_cycles:      row.harvest_cycles      || null,
      water_temp:          row.water_temp          || null,
      salinity:            row.salinity            || null,
      dissolved_oxygen:    row.dissolved_oxygen    || null,
      ph:                  row.ph                  || null,
      fcr:                 row.fcr                 || null,
      feed_type:           row.feed_type           || null,
      processing_capacity: row.processing_capacity || null,
      input_species:       row.input_species       || null,
      output_products:     row.output_products     || null,
      fishmeal_pct:        row.fishmeal_pct        || null,
      fishoil_pct:         row.fishoil_pct         || null,
      imo:                 row.imo                 || null,
      _imo:                row.imo                 || null,
      mmsi:                row.mmsi                || null,
      call_sign:           row.call_sign           || null,
      vessel_type:         row.vessel_type         || null,
      gross_tonnage:       row.gross_tonnage       || null,
      dwt:                 row.dwt                 || null,
      year_built:          row.year_built          || null,
      port_of_registry:    row.port_of_registry    || null,
      length:              row.vessel_length       || null,
      beam:                row.beam                || null,
      nav_status:          row.nav_status          || null,
      class_soc:           row.class_soc           || null,
      species:             row.species             || null,
      certification:       row.certification       || null,
      license:             row.license             || null,
      employees:           row.employees           || null,
      description:         row.description         || null,
    };
  }

  /* ─────────────────────────────────────────────────────────────────
     PUBLIC: ADD IMAGES
  ───────────────────────────────────────────────────────────────── */
  async function addImages(localId, images = []) {
    if (!images.length || !await init()) return;
    try {
      const res = _db.exec('SELECT id FROM entities WHERE local_id = ?', [localId]);
      if (!res.length || !res[0].values.length) return;
      const eid = res[0].values[0][0];
      images.forEach(img => {
        _db.run(
          'INSERT OR IGNORE INTO entity_images (entity_id, src, label) VALUES (?,?,?)',
          [eid, img.src, img.label || null]
        );
      });
      await _persist();
    } catch (e) { console.warn('[SQLite] addImages failed:', e.message); }
  }

  /* ─────────────────────────────────────────────────────────────────
     PUBLIC: LOG SEARCH
  ───────────────────────────────────────────────────────────────── */
  async function logSearch(query, searchType, resultCount = 0) {
    if (!await init()) return;
    try {
      _db.run(
        'INSERT INTO search_history (query, search_type, result_count) VALUES (?,?,?)',
        [query, searchType || null, resultCount]
      );
      await _persist();
    } catch {}
  }

  /* ─────────────────────────────────────────────────────────────────
     PUBLIC: BULK IMPORT (alias for batchUpsert — used for migration)
  ───────────────────────────────────────────────────────────────── */
  async function bulkImport(records) {
    return batchUpsert(records);
  }

  /* ─────────────────────────────────────────────────────────────────
     PUBLIC: RAW QUERY
  ───────────────────────────────────────────────────────────────── */
  async function query(sql, params = []) {
    if (!await init()) return [];
    return _db.exec(sql, params);
  }

  /* ─────────────────────────────────────────────────────────────────
     PUBLIC: STATS
  ───────────────────────────────────────────────────────────────── */
  async function getStats() {
    if (!await init()) return {};
    try {
      const r = _db.exec(`
        SELECT
          (SELECT COUNT(*) FROM entities)                               AS total,
          (SELECT COUNT(*) FROM entities WHERE entity_type='farm')      AS farms,
          (SELECT COUNT(*) FROM entities WHERE entity_type='vessel')    AS vessels,
          (SELECT COUNT(*) FROM entities WHERE entity_type='mill')      AS mills,
          (SELECT COUNT(*) FROM entities WHERE verified=1)              AS verified,
          (SELECT COUNT(DISTINCT species_name) FROM entity_species)     AS unique_species,
          (SELECT COUNT(*) FROM search_history)                         AS searches,
          (SELECT COUNT(*) FROM entity_images)                          AS images
      `);
      if (!r.length) return {};
      return Object.fromEntries(r[0].columns.map((c, i) => [c, r[0].values[0][i]]));
    } catch { return {}; }
  }

  /* ─────────────────────────────────────────────────────────────────
     PUBLIC: EXPORT / IMPORT
  ───────────────────────────────────────────────────────────────── */
  async function exportDB() {
    if (!await init()) return null;
    return _db.export();
  }

  async function importDB(arrayBuffer) {
    if (!_SQL) {
      await _loadSqlJs();
      _SQL = await window.initSqlJs({ locateFile: f => WASM_BASE + f });
    }
    _db    = new _SQL.Database(new Uint8Array(arrayBuffer));
    _ready = true;
    // Run SCHEMA to add any tables/columns that are missing in the imported DB
    // (handles files exported from an older version of the app).
    _db.run(SCHEMA);
    await _persist();
    return true;
  }

  /* ─────────────────────────────────────────────────────────────────
     EXPOSE
  ───────────────────────────────────────────────────────────────── */
  window.AppSQLite = {
    init,
    upsert, batchUpsert, bulkImport,
    remove, clearAll,
    getAllEntities, rowToRecord,
    addImages, logSearch,
    query, getStats,
    exportDB, importDB,
  };

})();
