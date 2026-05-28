/**
 * fish-intel — Browser SQLite layer (sql.js / WebAssembly)
 *
 * Exposed as window.AppSQLite. sql.js is lazy-loaded from CDN on first use.
 * The database is persisted as a binary blob in IndexedDB after every write.
 * Download the .db file to open in DB Browser for SQLite, DBeaver, or any
 * SQLite-compatible tool.
 *
 * Schema covers all entity types — farms, vessels, fish mills — with
 * normalized species, images, and source-URL tables.
 */
(function () {
  'use strict';

  const SQL_JS_CDN  = 'https://cdn.jsdelivr.net/npm/sql.js@1.12.0/dist/sql-wasm.min.js';
  const WASM_BASE   = 'https://cdn.jsdelivr.net/npm/sql.js@1.12.0/dist/';
  const IDB_KEY     = 'sqlite-db';

  let _SQL         = null;
  let _db          = null;
  let _ready       = false;
  let _initPromise = null;

  /* ─────────────────────────────────────────────────────────────────
     SCHEMA
     All fields the bots extract, organized by entity type.
     Normalized child tables for species, images, and source URLs.
  ───────────────────────────────────────────────────────────────── */
  const SCHEMA = `
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;

    /* ── Core entity record ── */
    CREATE TABLE IF NOT EXISTS entities (
      id                    INTEGER PRIMARY KEY AUTOINCREMENT,
      local_id              TEXT    UNIQUE NOT NULL,  -- fish-intel browser id
      directus_id           TEXT,                     -- Directus UUID if synced

      -- Identity
      name                  TEXT,
      farm_name             TEXT,
      vessel_name           TEXT,
      entity_type           TEXT,    -- 'farm' | 'vessel' | 'mill' | 'general'
      category              TEXT,    -- salmon, trawler, longliner …

      -- People / organisation
      operator              TEXT,
      owner                 TEXT,
      manager               TEXT,

      -- Location
      country               TEXT,
      flag                  TEXT,    -- ISO-2 or full country name
      region                TEXT,
      latitude              REAL,
      longitude             REAL,

      -- Aquaculture (farms)
      water_type            TEXT,    -- Freshwater | Saltwater | Brackish
      production_method     TEXT,    -- Net Pen | RAS | Pond | Cage …
      capacity              TEXT,    -- annual harvest capacity
      total_area            TEXT,    -- hectares / m²
      stocking_density      TEXT,    -- kg/m³
      harvest_cycles        TEXT,    -- cycles per year
      water_temp            TEXT,    -- °C
      salinity              TEXT,    -- ppt / g/L
      dissolved_oxygen      TEXT,    -- mg/L
      ph                    TEXT,
      fcr                   TEXT,    -- feed conversion ratio
      feed_type             TEXT,

      -- Fish mill / processing plant
      processing_capacity   TEXT,    -- tonnes/year
      input_species         TEXT,    -- raw fish species used
      output_products       TEXT,    -- fishmeal | fish oil | blend
      fishmeal_pct          TEXT,    -- % of output
      fishoil_pct           TEXT,

      -- Vessel (maritime)
      imo                   TEXT,    -- 7-digit IMO number
      mmsi                  TEXT,    -- 9-digit MMSI
      call_sign             TEXT,
      vessel_type           TEXT,    -- Fishing Vessel | Bulk Carrier | Tanker …
      gross_tonnage         TEXT,    -- GT
      dwt                   TEXT,    -- deadweight tonnes
      year_built            INTEGER,
      port_of_registry      TEXT,
      vessel_length         TEXT,    -- metres (renamed from 'length' to avoid SQL keyword)
      beam                  TEXT,    -- metres
      nav_status            TEXT,    -- AIS navigation status
      class_soc             TEXT,    -- classification society

      -- Shared / content
      species               TEXT,    -- comma-separated (also normalized in entity_species)
      certification         TEXT,    -- ASC, MSC, BAP, GlobalG.A.P. …
      license               TEXT,
      employees             TEXT,
      description           TEXT,    -- polished AI-written or scraped paragraph

      -- User annotations
      notes                 TEXT,
      verified              INTEGER  DEFAULT 0,   -- 1 = manually verified

      -- Timestamps
      saved_at              TEXT,    -- ISO-8601 from fish-intel
      created_at            TEXT     DEFAULT (datetime('now')),
      updated_at            TEXT     DEFAULT (datetime('now'))
    );

    /* ── Normalized species (one row per species per entity) ── */
    CREATE TABLE IF NOT EXISTS entity_species (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      entity_id     INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
      species_name  TEXT    NOT NULL
    );

    /* ── Images found during scraping ── */
    CREATE TABLE IF NOT EXISTS entity_images (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      entity_id   INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
      src         TEXT    NOT NULL,
      label       TEXT,
      added_at    TEXT    DEFAULT (datetime('now'))
    );

    /* ── Source URLs where fields were scraped from ── */
    CREATE TABLE IF NOT EXISTS entity_sources (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      entity_id   INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
      url         TEXT    NOT NULL,
      scraped_at  TEXT    DEFAULT (datetime('now'))
    );

    /* ── Search history ── */
    CREATE TABLE IF NOT EXISTS search_history (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      query         TEXT    NOT NULL,
      search_type   TEXT,            -- farm | vessel | mill | general
      result_count  INTEGER DEFAULT 0,
      searched_at   TEXT    DEFAULT (datetime('now'))
    );

    /* ── Indexes ── */
    CREATE INDEX IF NOT EXISTS idx_entities_local_id    ON entities(local_id);
    CREATE INDEX IF NOT EXISTS idx_entities_type        ON entities(entity_type);
    CREATE INDEX IF NOT EXISTS idx_entities_country     ON entities(country);
    CREATE INDEX IF NOT EXISTS idx_entities_imo         ON entities(imo);
    CREATE INDEX IF NOT EXISTS idx_entity_species_eid   ON entity_species(entity_id);
    CREATE INDEX IF NOT EXISTS idx_entity_images_eid    ON entity_images(entity_id);
    CREATE INDEX IF NOT EXISTS idx_entity_sources_eid   ON entity_sources(entity_id);

    /* ── Convenience view: flat record + species as JSON array ── */
    CREATE VIEW IF NOT EXISTS v_entities_full AS
    SELECT
      e.*,
      (
        SELECT json_group_array(es.species_name)
        FROM entity_species es
        WHERE es.entity_id = e.id
      ) AS species_list,
      (
        SELECT COUNT(*) FROM entity_images ei WHERE ei.entity_id = e.id
      ) AS image_count,
      (
        SELECT COUNT(*) FROM entity_sources es WHERE es.entity_id = e.id
      ) AS source_count
    FROM entities e;
  `;

  /* ─────────────────────────────────────────────────────────────────
     INIT
  ───────────────────────────────────────────────────────────────── */
  async function _loadSqlJs() {
    if (window.initSqlJs) return;
    await new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = SQL_JS_CDN;
      s.crossOrigin = 'anonymous';
      s.onload = resolve;
      s.onerror = () => reject(new Error('Failed to load sql.js from CDN'));
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

        // Load saved binary from IDB if it exists
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
     PERSIST TO INDEXEDDB
  ───────────────────────────────────────────────────────────────── */
  async function _persist() {
    if (!_db || !window.AppIDB) return;
    try {
      const data = _db.export();   // Uint8Array
      await AppIDB.put('knowledge', { key: IDB_KEY, data });
    } catch (e) {
      console.warn('[SQLite] Persist failed:', e.message);
    }
  }

  /* ─────────────────────────────────────────────────────────────────
     UPSERT — insert or update an entity and its child rows
  ───────────────────────────────────────────────────────────────── */
  async function upsert(record) {
    if (!await init()) return false;
    try {
      const lat = parseFloat(record.latitude)  || null;
      const lng = parseFloat(record.longitude) || null;
      const yb  = parseInt(record.year_built, 10) || null;
      const lid = record._id || record.id;

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
          ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,
          ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?
        )
        ON CONFLICT(local_id) DO UPDATE SET
          name=excluded.name, farm_name=excluded.farm_name,
          vessel_name=excluded.vessel_name, entity_type=excluded.entity_type,
          category=excluded.category, operator=excluded.operator,
          owner=excluded.owner, manager=excluded.manager,
          country=excluded.country, flag=excluded.flag, region=excluded.region,
          latitude=excluded.latitude, longitude=excluded.longitude,
          water_type=excluded.water_type, production_method=excluded.production_method,
          capacity=excluded.capacity, total_area=excluded.total_area,
          stocking_density=excluded.stocking_density, harvest_cycles=excluded.harvest_cycles,
          water_temp=excluded.water_temp, salinity=excluded.salinity,
          dissolved_oxygen=excluded.dissolved_oxygen, ph=excluded.ph,
          fcr=excluded.fcr, feed_type=excluded.feed_type,
          processing_capacity=excluded.processing_capacity, input_species=excluded.input_species,
          output_products=excluded.output_products, fishmeal_pct=excluded.fishmeal_pct,
          fishoil_pct=excluded.fishoil_pct, imo=excluded.imo, mmsi=excluded.mmsi,
          call_sign=excluded.call_sign, vessel_type=excluded.vessel_type,
          gross_tonnage=excluded.gross_tonnage, dwt=excluded.dwt,
          year_built=excluded.year_built, port_of_registry=excluded.port_of_registry,
          vessel_length=excluded.vessel_length, beam=excluded.beam,
          nav_status=excluded.nav_status, class_soc=excluded.class_soc,
          species=excluded.species, certification=excluded.certification,
          license=excluded.license, employees=excluded.employees,
          description=excluded.description, notes=excluded.notes,
          verified=excluded.verified, saved_at=excluded.saved_at,
          updated_at=datetime('now')
      `, [
        lid,
        record.name        || null,
        record.farm_name   || null,
        record.vessel_name || null,
        record._facilityType || null,
        record._category     || null,
        record.operator || null,
        record.owner    || null,
        record.manager  || null,
        record.country  || null,
        record.flag     || null,
        record.region   || null,
        lat, lng,
        record.water_type         || null,
        record.production_method  || null,
        record.capacity           || null,
        record.total_area         || null,
        record.stocking_density   || null,
        record.harvest_cycles     || null,
        record.water_temp         || null,
        record.salinity           || null,
        record.dissolved_oxygen   || null,
        record.ph                 || null,
        record.fcr                || null,
        record.feed_type          || null,
        record.processing_capacity || null,
        record.input_species       || null,
        record.output_products     || null,
        record.fishmeal_pct        || null,
        record.fishoil_pct         || null,
        record.imo || record._imo  || null,
        record.mmsi       || null,
        record.call_sign  || null,
        record.vessel_type  || null,
        record.gross_tonnage || null,
        record.dwt             || null,
        yb,
        record.port_of_registry || null,
        record.length || null,
        record.beam   || null,
        record.nav_status  || null,
        record.class_soc   || null,
        record.species        || null,
        record.certification  || null,
        record.license        || null,
        record.employees      || null,
        record.description    || null,
        record._notes    || null,
        record._verified ? 1 : 0,
        record._savedAt  || null,
      ]);

      // Get integer id for child inserts
      const res = _db.exec('SELECT id FROM entities WHERE local_id = ?', [lid]);
      if (res.length && res[0].values.length) {
        const eid = res[0].values[0][0];

        // Normalized species (delete + re-insert so updates are clean)
        _db.run('DELETE FROM entity_species WHERE entity_id = ?', [eid]);
        const sp = record.species || record.input_species || '';
        sp.split(',').map(s => s.trim()).filter(Boolean).forEach(name => {
          _db.run('INSERT INTO entity_species (entity_id, species_name) VALUES (?,?)', [eid, name]);
        });
      }

      await _persist();
      return true;
    } catch (e) {
      console.error('[SQLite] upsert failed:', e);
      return false;
    }
  }

  /* ─────────────────────────────────────────────────────────────────
     INSERT IMAGES
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
    } catch (e) {
      console.warn('[SQLite] addImages failed:', e.message);
    }
  }

  /* ─────────────────────────────────────────────────────────────────
     LOG SEARCH
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
     DELETE
  ───────────────────────────────────────────────────────────────── */
  async function remove(localId) {
    if (!await init()) return false;
    try {
      _db.run('DELETE FROM entities WHERE local_id = ?', [localId]);
      await _persist();
      return true;
    } catch (e) {
      console.error('[SQLite] remove failed:', e);
      return false;
    }
  }

  /* ─────────────────────────────────────────────────────────────────
     BULK IMPORT — import all existing saved[] records on first run
  ───────────────────────────────────────────────────────────────── */
  async function bulkImport(records = []) {
    if (!records.length || !await init()) return 0;
    let count = 0;
    for (const r of records) {
      const ok = await upsert(r);
      if (ok) count++;
    }
    return count;
  }

  /* ─────────────────────────────────────────────────────────────────
     QUERY — run raw SQL (returns sql.js result array)
  ───────────────────────────────────────────────────────────────── */
  async function query(sql, params = []) {
    if (!await init()) return [];
    return _db.exec(sql, params);
  }

  /* ─────────────────────────────────────────────────────────────────
     STATS
  ───────────────────────────────────────────────────────────────── */
  async function getStats() {
    if (!await init()) return {};
    try {
      const r = _db.exec(`
        SELECT
          (SELECT COUNT(*) FROM entities)                                as total,
          (SELECT COUNT(*) FROM entities WHERE entity_type = 'farm')    as farms,
          (SELECT COUNT(*) FROM entities WHERE entity_type = 'vessel')  as vessels,
          (SELECT COUNT(*) FROM entities WHERE entity_type = 'mill')    as mills,
          (SELECT COUNT(*) FROM entities WHERE verified = 1)            as verified,
          (SELECT COUNT(DISTINCT species_name) FROM entity_species)     as unique_species,
          (SELECT COUNT(*) FROM search_history)                         as searches,
          (SELECT COUNT(*) FROM entity_images)                          as images
      `);
      if (!r.length) return {};
      return Object.fromEntries(r[0].columns.map((c, i) => [c, r[0].values[0][i]]));
    } catch { return {}; }
  }

  /* ─────────────────────────────────────────────────────────────────
     EXPORT — returns Uint8Array for download as .db file
  ───────────────────────────────────────────────────────────────── */
  async function exportDB() {
    if (!await init()) return null;
    return _db.export();
  }

  /* ─────────────────────────────────────────────────────────────────
     IMPORT — load from a .db file buffer
  ───────────────────────────────────────────────────────────────── */
  async function importDB(arrayBuffer) {
    if (!_SQL) await _loadSqlJs().then(() => window.initSqlJs({ locateFile: f => WASM_BASE + f }).then(s => { _SQL = s; }));
    _db    = new _SQL.Database(new Uint8Array(arrayBuffer));
    _ready = true;
    await _persist();
    return true;
  }

  /* ─────────────────────────────────────────────────────────────────
     EXPOSE
  ───────────────────────────────────────────────────────────────── */
  window.AppSQLite = {
    init,
    upsert,
    remove,
    addImages,
    logSearch,
    bulkImport,
    query,
    getStats,
    exportDB,
    importDB,
  };

})();
