/**
 * fish-intel — Directus REST client
 *
 * Exposed as window.Directus so app.js (classic script) can call it.
 * Credentials are stored in IndexedDB (knowledge store), never hardcoded.
 * Call Directus.configure(url, token) at startup after loading from IDB.
 * All methods return null / false gracefully if not configured.
 */
(function () {
  'use strict';

  const COLLECTION = 'fish_entities';

  let _url   = null;   // e.g. "https://your-directus.io"
  let _token = null;
  const _idMap = {};   // localRecordId → directus item id

  // ── Config ──────────────────────────────────────────────────────
  function configure(baseUrl, token) {
    _url   = baseUrl ? baseUrl.replace(/\/$/, '') : null;
    _token = token   || null;
  }

  function isConfigured() {
    return Boolean(_url && _token);
  }

  function getBaseUrl() { return _url; }

  // ── Internal fetch helper ──────────────────────────────────────
  async function dFetch(path, options = {}) {
    if (!isConfigured()) throw new Error('Directus not configured');
    const res = await fetch(`${_url}${path}`, {
      ...options,
      headers: {
        'Authorization': `Bearer ${_token}`,
        'Content-Type':  'application/json',
        ...(options.headers || {}),
      },
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      const msg  = body.errors?.[0]?.message || `HTTP ${res.status}`;
      throw new Error(`Directus: ${msg}`);
    }
    if (res.status === 204) return null;  // DELETE returns no body
    return res.json();
  }

  // ── Test connection ────────────────────────────────────────────
  async function ping() {
    try {
      const r = await dFetch('/server/ping');
      return r?.data === 'pong';
    } catch {
      return false;
    }
  }

  // ── Map fish-intel merged fields → Directus payload ───────────
  function toPayload(mergedFields, query, searchType) {
    const speciesRaw = mergedFields.species || mergedFields.input_species || '';
    const species = speciesRaw
      ? speciesRaw.split(',').map(s => s.trim()).filter(Boolean)
      : [];

    return {
      name:            query || mergedFields.farm_name || mergedFields.vessel_name || null,
      entity_type:     searchType || null,
      country:         mergedFields.country || mergedFields.flag || null,
      region:          mergedFields.region  || null,
      species,
      annual_capacity: mergedFields.capacity || mergedFields.processing_capacity || null,
      certifications:  mergedFields.certification || null,
      imo_number:      mergedFields._imo   || mergedFields.imo   || null,
      flag_state:      mergedFields.flag   || null,
      vessel_type:     mergedFields.vessel_type  || null,
      operator:        mergedFields.operator || mergedFields.owner || null,
      description:     mergedFields.description  || null,
      raw_fields:      mergedFields,
    };
  }

  // ── Save a new entity ──────────────────────────────────────────
  async function saveEntity(mergedFields, query, searchType, localId) {
    if (!isConfigured()) return null;
    try {
      const r = await dFetch(`/items/${COLLECTION}`, {
        method: 'POST',
        body:   JSON.stringify(toPayload(mergedFields, query, searchType)),
      });
      const directusId = r?.data?.id;
      if (directusId && localId) _idMap[localId] = directusId;
      return r?.data || null;
    } catch (e) {
      console.warn('[Directus] saveEntity failed:', e.message);
      return null;
    }
  }

  // ── Patch an existing entity ───────────────────────────────────
  async function updateEntity(localId, patch) {
    if (!isConfigured()) return null;
    const directusId = _idMap[localId];
    if (!directusId) return null;
    try {
      const r = await dFetch(`/items/${COLLECTION}/${directusId}`, {
        method: 'PATCH',
        body:   JSON.stringify(patch),
      });
      return r?.data || null;
    } catch (e) {
      console.warn('[Directus] updateEntity failed:', e.message);
      return null;
    }
  }

  // ── Delete an entity ───────────────────────────────────────────
  async function deleteEntity(localId) {
    if (!isConfigured()) return false;
    const directusId = _idMap[localId];
    if (!directusId) return false;
    try {
      await dFetch(`/items/${COLLECTION}/${directusId}`, { method: 'DELETE' });
      delete _idMap[localId];
      return true;
    } catch (e) {
      console.warn('[Directus] deleteEntity failed:', e.message);
      return false;
    }
  }

  // ── Fetch all entities ─────────────────────────────────────────
  async function fetchEntities({ limit = 100, search = '' } = {}) {
    if (!isConfigured()) return [];
    try {
      const params = new URLSearchParams({ limit, sort: '-date_created' });
      if (search) params.set('filter[name][_icontains]', search);
      const r = await dFetch(`/items/${COLLECTION}?${params}`);
      return r?.data || [];
    } catch (e) {
      console.warn('[Directus] fetchEntities failed:', e.message);
      return [];
    }
  }

  // ── Expose on window ───────────────────────────────────────────
  window.Directus = {
    configure,
    isConfigured,
    getBaseUrl,
    ping,
    saveEntity,
    updateEntity,
    deleteEntity,
    fetchEntities,
  };

})();
