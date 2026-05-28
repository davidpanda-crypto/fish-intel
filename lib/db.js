/**
 * Server-side SQLite — better-sqlite3
 * Synchronous, fast, no WASM overhead. Used only in API routes (server).
 * The database file lives at SQLITE_PATH (default: ./data/fish-intel.db).
 */

import Database from 'better-sqlite3';
import path     from 'path';
import fs       from 'fs';

// On Vercel (and any read-only deploy) process.cwd() is not writable.
// Default to /tmp which is always writable (note: ephemeral on serverless —
// data survives warm invocations but is cleared on cold start / new deploy).
// Set SQLITE_PATH to an absolute persistent path on self-hosted servers.
const DB_PATH = process.env.SQLITE_PATH
  ? path.resolve(process.env.SQLITE_PATH)
  : '/tmp/fish-intel.db';

// Ensure the data directory exists (no-op for /tmp)
try { fs.mkdirSync(path.dirname(DB_PATH), { recursive: true }); } catch {}

/* ── Schema — mirrors client-side sqlite.js exactly ────────────────────────── */
const SCHEMA = `
  PRAGMA foreign_keys = ON;
  PRAGMA journal_mode = WAL;

  CREATE TABLE IF NOT EXISTS entities (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    local_id              TEXT    UNIQUE NOT NULL,
    directus_id           TEXT,
    name                  TEXT,
    farm_name             TEXT,
    vessel_name           TEXT,
    entity_type           TEXT,
    category              TEXT,
    operator              TEXT,
    owner                 TEXT,
    manager               TEXT,
    country               TEXT,
    flag                  TEXT,
    region                TEXT,
    latitude              REAL,
    longitude             REAL,
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
    processing_capacity   TEXT,
    input_species         TEXT,
    output_products       TEXT,
    fishmeal_pct          TEXT,
    fishoil_pct           TEXT,
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
    species               TEXT,
    certification         TEXT,
    license               TEXT,
    employees             TEXT,
    description           TEXT,
    notes                 TEXT,
    verified              INTEGER  DEFAULT 0,
    saved_at              TEXT,
    created_at            TEXT     DEFAULT (datetime('now')),
    updated_at            TEXT     DEFAULT (datetime('now'))
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

  CREATE VIEW IF NOT EXISTS v_entities_full AS
  SELECT
    e.*,
    (SELECT json_group_array(s.species_name)
     FROM entity_species s WHERE s.entity_id = e.id) AS species_list,
    (SELECT COUNT(*) FROM entity_images i WHERE i.entity_id = e.id) AS image_count
  FROM entities e;
`;

/* ── Singleton instance (safe in Next.js — API routes share the process) ── */
let _instance   = null;
let _initFailed = false;

export function getDB() {
  if (_initFailed) return null;
  if (_instance)   return _instance;
  try {
    _instance = new Database(DB_PATH, { verbose: null });
    _instance.exec(SCHEMA);
    return _instance;
  } catch (e) {
    console.error('[db] Failed to open SQLite:', e.message);
    _initFailed = true;
    return null;
  }
}

/* ── Helpers ─────────────────────────────────────────────────────────────── */

/** Upsert one entity record (insert or replace on local_id conflict). */
export function upsertEntity(record) {
  const db = getDB();

  const stmt = db.prepare(`
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
      @local_id, @name, @farm_name, @vessel_name, @entity_type, @category,
      @operator, @owner, @manager,
      @country, @flag, @region, @latitude, @longitude,
      @water_type, @production_method, @capacity, @total_area,
      @stocking_density, @harvest_cycles, @water_temp, @salinity,
      @dissolved_oxygen, @ph, @fcr, @feed_type,
      @processing_capacity, @input_species, @output_products, @fishmeal_pct, @fishoil_pct,
      @imo, @mmsi, @call_sign, @vessel_type, @gross_tonnage, @dwt, @year_built,
      @port_of_registry, @vessel_length, @beam, @nav_status, @class_soc,
      @species, @certification, @license, @employees, @description,
      @notes, @verified, @saved_at
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
  `);

  const result = stmt.run({
    local_id:             record._id  || record.id  || null,
    name:                 record.name || null,
    farm_name:            record.farm_name   || null,
    vessel_name:          record.vessel_name || null,
    entity_type:          record._facilityType || null,
    category:             record._category    || null,
    operator:             record.operator  || null,
    owner:                record.owner     || null,
    manager:              record.manager   || null,
    country:              record.country   || null,
    flag:                 record.flag      || null,
    region:               record.region    || null,
    latitude:             parseFloat(record.latitude)  || null,
    longitude:            parseFloat(record.longitude) || null,
    water_type:           record.water_type           || null,
    production_method:    record.production_method    || null,
    capacity:             record.capacity             || null,
    total_area:           record.total_area           || null,
    stocking_density:     record.stocking_density     || null,
    harvest_cycles:       record.harvest_cycles       || null,
    water_temp:           record.water_temp           || null,
    salinity:             record.salinity             || null,
    dissolved_oxygen:     record.dissolved_oxygen     || null,
    ph:                   record.ph                   || null,
    fcr:                  record.fcr                  || null,
    feed_type:            record.feed_type            || null,
    processing_capacity:  record.processing_capacity  || null,
    input_species:        record.input_species        || null,
    output_products:      record.output_products      || null,
    fishmeal_pct:         record.fishmeal_pct         || null,
    fishoil_pct:          record.fishoil_pct          || null,
    imo:                  record.imo || record._imo   || null,
    mmsi:                 record.mmsi                 || null,
    call_sign:            record.call_sign            || null,
    vessel_type:          record.vessel_type          || null,
    gross_tonnage:        record.gross_tonnage        || null,
    dwt:                  record.dwt                  || null,
    year_built:           parseInt(record.year_built, 10) || null,
    port_of_registry:     record.port_of_registry     || null,
    vessel_length:        record.length               || null,
    beam:                 record.beam                 || null,
    nav_status:           record.nav_status           || null,
    class_soc:            record.class_soc            || null,
    species:              record.species              || null,
    certification:        record.certification        || null,
    license:              record.license              || null,
    employees:            record.employees            || null,
    description:          record.description          || null,
    notes:                record._notes               || null,
    verified:             record._verified ? 1 : 0,
    saved_at:             record._savedAt             || null,
  });

  // Sync normalized species
  const entity = db.prepare('SELECT id FROM entities WHERE local_id = ?')
    .get(record._id || record.id);
  if (entity) {
    db.prepare('DELETE FROM entity_species WHERE entity_id = ?').run(entity.id);
    const sp = record.species || record.input_species || '';
    const insertSp = db.prepare(
      'INSERT INTO entity_species (entity_id, species_name) VALUES (?, ?)'
    );
    sp.split(',').map(s => s.trim()).filter(Boolean)
      .forEach(name => insertSp.run(entity.id, name));
  }

  return result;
}

/** Batch upsert inside a single transaction. */
export function batchUpsertEntities(records) {
  const db = getDB();
  const run = db.transaction((recs) => {
    let count = 0;
    for (const r of recs) {
      try { upsertEntity(r); count++; } catch {}
    }
    return count;
  });
  return run(records);
}
