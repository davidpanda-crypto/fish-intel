/**
 * Website Extractor Tools — Directus sync client
 *
 * Exposed as window.Directus so app.js (classic script) can call it.
 *
 * Architecture — all calls route through the server proxy at /api/directus/.
 * The Directus instance URL and static token are NEVER sent to the browser;
 * set DIRECTUS_URL and DIRECTUS_TOKEN as Vercel / .env.local env vars.
 *
 * What IS stored client-side (IDB knowledge store):
 *   directus-settings  { key, collection }   — collection name chosen by user
 *   directus-idmap     { key, data: {...} }   — localId → Directus item id map
 *                                               (persisted so delete/update
 *                                                survive page reloads)
 *
 * Startup sequence (called from app.js):
 *   1. Directus.configure(collection, apiSecret)
 *   2. await Directus.loadIdMap()
 */
(function () {
  'use strict';

  const PROXY              = '/api/directus';
  const DEFAULT_COLLECTION = 'fish_entities';
  const FETCH_TIMEOUT_MS   = 10_000;

  let _collection = null;          // null = not configured; set via configure()
  let _apiSecret  = null;          // value of NEXT_PUBLIC_API_SECRET (from app.js)
  const _idMap    = {};            // localId → Directus item id (persisted in IDB)

  // ── Config ───────────────────────────────────────────────────────────────
  function configure(collection, apiSecret) {
    _collection = collection ? collection.trim() : null;
    _apiSecret  = apiSecret || null;
  }

  /** Returns true once configure() has been called with a non-empty collection name. */
  function isConfigured() {
    return Boolean(_collection);
  }

  // ── _idMap persistence ────────────────────────────────────────────────────
  /**
   * Restore the localId→directusId map from IDB.
   * Must be awaited once at startup before any delete/update calls.
   */
  async function loadIdMap() {
    try {
      const entry = window.AppIDB
        ? await AppIDB.get('knowledge', 'directus-idmap')
        : null;
      if (entry?.data && typeof entry.data === 'object') {
        Object.assign(_idMap, entry.data);
      }
    } catch { /* non-fatal */ }
  }

  async function _saveIdMap() {
    try {
      if (window.AppIDB) {
        await AppIDB.put('knowledge', { key: 'directus-idmap', data: { ..._idMap } });
      }
    } catch { /* non-fatal */ }
  }

  // ── Internal fetch helper (via server proxy) ──────────────────────────────
  async function dFetch(path, options = {}) {
    const headers = { 'Content-Type': 'application/json' };
    if (_apiSecret) headers['x-api-secret'] = _apiSecret;

    const controller = new AbortController();
    const tid = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

    let res;
    try {
      res = await fetch(`${PROXY}${path}`, {
        ...options,
        headers: { ...headers, ...(options.headers || {}) },
        signal: controller.signal,
      });
    } finally {
      clearTimeout(tid);
    }

    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      const msg  = body.errors?.[0]?.message || body.error || `HTTP ${res.status}`;
      throw new Error(`Directus: ${msg}`);
    }
    if (res.status === 204) return null;   // DELETE returns no body
    return res.json();
  }

  // ── Test connection ───────────────────────────────────────────────────────
  /**
   * Returns true if the proxy can reach Directus and the collection exists.
   * Uses a lightweight items fetch (limit=1, id field only) — no extra
   * endpoint needed beyond the existing proxy allowlist.
   */
  async function ping() {
    try {
      const params = new URLSearchParams({ limit: '1', fields: 'id' });
      await dFetch(`/items/${_collection}?${params}`);
      return true;
    } catch {
      return false;
    }
  }

  // ── Map extracted fields → Directus payload ───────────────────────────────
  /**
   * Field names match the Directus collection schema exactly.
   *
   * Collection fields (all nullable unless noted):
   *   local_id            string, unique  — links record back to the app
   *   name                string
   *   owner               string          — beneficial owner (may differ from operator)
   *   country             string
   *   flag                string          — flag state
   *   region              string
   *   latitude            decimal
   *   longitude           decimal
   *   entity_type         string          — farm | vessel | mill | general
   *   imo                 string
   *   mmsi                string
   *   vessel_type         string
   *   nav_status          string
   *   call_sign           string
   *   species             string          — plain string (not an array)
   *   certification       string
   *   capacity            string
   *   processing_capacity string
   *   verified            boolean         — reporter toggles in Directus (default false)
   *   notes               textarea        — reporter fills in Directus (left null here)
   *   description         textarea
   *   saved_at            datetime
   */
  function toPayload(mergedFields, query, searchType, localId) {
    const lat = parseFloat(mergedFields.latitude  || mergedFields.lat);
    const lon = parseFloat(mergedFields.longitude || mergedFields.lon || mergedFields.lng);

    return {
      local_id:            localId  || null,
      name:                query    || mergedFields.farm_name || mergedFields.vessel_name || mergedFields.name || null,
      owner:               mergedFields.owner      || mergedFields.operator   || null,
      country:             mergedFields.country    || null,
      flag:                mergedFields.flag       || null,
      region:              mergedFields.region     || null,
      latitude:            isFinite(lat) ? lat : null,
      longitude:           isFinite(lon) ? lon : null,
      entity_type:         searchType || mergedFields.entity_type || null,
      imo:                 mergedFields._imo       || mergedFields.imo        || null,
      mmsi:                mergedFields.mmsi       || null,
      vessel_type:         mergedFields.vessel_type || null,
      nav_status:          mergedFields.nav_status || mergedFields.navigation_status || null,
      call_sign:           mergedFields.call_sign  || mergedFields.callsign   || null,
      species:             mergedFields.species    || mergedFields.input_species || null,
      certification:       mergedFields.certification || null,
      capacity:            mergedFields.capacity   || null,
      processing_capacity: mergedFields.processing_capacity || null,
      verified:            false,              // reporter toggles this in Directus
      notes:               null,               // reporter fills this in Directus
      description:         mergedFields.description || null,
      saved_at:            new Date().toISOString(),
    };
  }

  // ── Save a new entity ─────────────────────────────────────────────────────
  async function saveEntity(mergedFields, query, searchType, localId) {
    if (!isConfigured()) return null;
    try {
      const r = await dFetch(`/items/${_collection}`, {
        method: 'POST',
        body:   JSON.stringify(toPayload(mergedFields, query, searchType, localId)),
      });
      const directusId = r?.data?.id;
      if (directusId && localId) {
        _idMap[localId] = directusId;
        await _saveIdMap();   // persist so reload doesn't break delete/update
      }
      return r?.data || null;
    } catch (e) {
      console.warn('[Directus] saveEntity failed:', e.message);
      return null;
    }
  }

  // ── Patch an existing entity ──────────────────────────────────────────────
  async function updateEntity(localId, patch) {
    if (!isConfigured()) return null;
    const directusId = _idMap[localId];
    if (!directusId) {
      console.warn('[Directus] updateEntity: no Directus id for localId', localId, '(was the record saved before this session?)');
      return null;
    }
    try {
      const r = await dFetch(`/items/${_collection}/${directusId}`, {
        method: 'PATCH',
        body:   JSON.stringify(patch),
      });
      return r?.data || null;
    } catch (e) {
      console.warn('[Directus] updateEntity failed:', e.message);
      return null;
    }
  }

  // ── Delete an entity ──────────────────────────────────────────────────────
  async function deleteEntity(localId) {
    if (!isConfigured()) return false;
    const directusId = _idMap[localId];
    if (!directusId) {
      // No Directus record for this local id — not an error, just not synced
      return false;
    }
    try {
      await dFetch(`/items/${_collection}/${directusId}`, { method: 'DELETE' });
      delete _idMap[localId];
      await _saveIdMap();   // remove from IDB too
      return true;
    } catch (e) {
      console.warn('[Directus] deleteEntity failed:', e.message);
      return false;
    }
  }

  // ── Fetch all entities ────────────────────────────────────────────────────
  async function fetchEntities({ limit = 100, search = '' } = {}) {
    if (!isConfigured()) return [];
    try {
      const params = new URLSearchParams({ limit, sort: '-date_created' });
      if (search) params.set('filter[name][_icontains]', search);
      const r = await dFetch(`/items/${_collection}?${params}`);
      return r?.data || [];
    } catch (e) {
      console.warn('[Directus] fetchEntities failed:', e.message);
      return [];
    }
  }

  // ── Public API ────────────────────────────────────────────────────────────
  window.Directus = {
    configure,
    isConfigured,
    loadIdMap,       // call once at startup after configure()
    ping,
    saveEntity,
    updateEntity,
    deleteEntity,
    fetchEntities,
  };

})();
