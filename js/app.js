'use strict';

/* ═══════════════════════════════════════════
   SECURITY HELPERS
═══════════════════════════════════════════ */

/** Escape string for safe HTML insertion */
function esc(s) {
  return String(s ?? '')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#x27;').replace(/\//g,'&#x2F;');
}

/** Sanitize full HTML with DOMPurify (removes scripts, event handlers, etc.) */
function sanitize(html) {
  if (typeof DOMPurify !== 'undefined') {
    return DOMPurify.sanitize(html, {
      ALLOWED_TAGS: ['b','i','em','strong','span','div','p','br','a'],
      ALLOWED_ATTR: ['class','style','href','target','rel'],
      ALLOW_DATA_ATTR: false,
    });
  }
  // Fallback: strip all tags
  return html.replace(/<[^>]*>/g,'');
}

/** Validate URL — reject non-HTTPS, localhost, private IPs */
function isValidURL(url) {
  try {
    const u = new URL(url);
    if (!['https:','http:'].includes(u.protocol)) return false;
    const h = u.hostname;
    if (/^(localhost|127\.|0\.|::1|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/i.test(h)) return false;
    if (h.length < 3 || h.length > 253) return false;
    return true;
  } catch { return false; }
}

/** Sanitize a field value — strip HTML, remove noise, limit length */
function cleanField(v) {
  if (!v) return '';
  let s = String(v)
    .replace(/<[^>]*>/g, '')         // strip HTML tags
    .replace(/&[a-z#0-9]+;/gi, ' ') // decode entities to space
    .replace(/[\x00-\x1f\x7f]/g, '')// strip control chars
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 1500);
  // Reject placeholder / noise values
  if (/^(n\/?a|none|not\s+available|unknown|undefined|null|—|–|-|\.{2,}|tbd|n\/a|na|yes|no|true|false)$/i.test(s)) return '';
  // Reject single characters
  if (s.length < 2) return '';
  // Reject UI / navigation boilerplate
  if (/^(login|log\s*in|sign\s*in|sign\s*up|register|home|about\s*us?|contact\s*us?|menu|click\s*here|read\s*more|learn\s*more|more\s*info|back|next|previous|submit|cancel|close|loading|share|print|download|privacy\s*policy|terms\s*(of\s*(use|service)|and\s*conditions)|cookie\s*policy|all\s*rights)$/i.test(s)) return '';
  // Reject copyright / legal boilerplate
  if (/©|\bcopyright\b|\ball\s+rights\s+reserved\b/i.test(s)) return '';
  return s;
}

/** Per-field precision validators — return cleaned value or '' if invalid */
function validateFieldValue(key, val) {
  if (!val) return '';
  const v = val.trim();
  if (!v) return '';

  switch (key) {
    case 'latitude': {
      const n = parseFloat(v.replace(/[°NS ]/gi,''));
      if (isNaN(n) || n < -90 || n > 90 || n === 0) return '';
      return parseFloat(n.toFixed(5)).toString(); // max 5 decimal places (~1 m precision)
    }
    case 'longitude': {
      const n = parseFloat(v.replace(/[°EW ]/gi,''));
      if (isNaN(n) || n < -180 || n > 180 || n === 0) return '';
      return parseFloat(n.toFixed(5)).toString();
    }
    case 'year_built': {
      const m = v.match(/\b(1[89]\d{2}|20[0-2]\d)\b/);
      return m ? m[1] : '';
    }
    case '_imo': case 'imo': {
      const m = v.match(/\b(\d{7})\b/);
      return (m && validIMO(m[1])) ? m[1] : '';
    }
    case 'mmsi': {
      return /^\d{9}$/.test(v.replace(/\s/g,'')) ? v.replace(/\s/g,'') : '';
    }
    case 'capacity': case 'gross_tonnage': case 'dwt':
    case 'processing_capacity': case 'total_area': case 'employees': {
      // Must contain at least one digit
      return /\d/.test(v) ? v.slice(0, 80) : '';
    }
    case 'fcr': {
      // FCR is a small decimal, typically 1.0–3.5
      const n = parseFloat(v);
      return (!isNaN(n) && n > 0.5 && n < 10) ? String(n) : '';
    }
    case 'description': {
      // Must be at least 30 chars to be meaningful
      return v.length >= 30 ? v.slice(0, 1200) : '';
    }
    case 'species': case 'input_species': {
      // Reject UI / nav boilerplate that leaks through scraping
      if (/outside\s*fish\s*in|inside\s*fish|view\s*all|see\s*more|learn\s*more|read\s*more|shop\s*now|click\s*here/i.test(v)) return '';
      // Title-case, deduplicate quick pass, reject bare generic nouns
      const norm = v.replace(/\b\w/g, c => c.toUpperCase()).trim();
      if (/^(Fish|Seafood|Animal|Marine|Aquatic|Product|Species|Other|Various|Mixed|All|None)$/i.test(norm)) return '';
      return norm.slice(0, 120);
    }
    case 'certification': {
      const uc = v.toUpperCase();
      if (/\bASC\b/.test(uc)) return 'ASC Certified';
      if (/\bMSC\b/.test(uc)) return 'MSC Certified';
      if (/\bBAP\b/.test(uc)) return 'BAP Certified';
      if (/global\s*g\.?a\.?p/i.test(v)) return 'GlobalG.A.P. Certified';
      if (/\bhalal\b/i.test(v)) return 'Halal Certified';
      const isoM = v.match(/iso\s*(\d{4,5})/i);
      if (isoM) return `ISO ${isoM[1]} Certified`;
      // Reject bare generic words that aren't real certification names
      if (/^(certified|yes|true|accredited|approved|compliant)$/i.test(v.trim())) return '';
      return v.slice(0, 80);
    }
    case 'country': case 'flag': {
      // Reject org/foundation names masquerading as countries
      if (/\b(asc|fao|msc|bap|ices|imo|wwf|international|foundation|organization|association|institute|certified|standard)\b/i.test(v)) return '';
      // Map ISO-3, ISO-2, and common abbreviations to full country names
      const ISO_MAP = {
        UK:'United Kingdom', GB:'United Kingdom', US:'United States', USA:'United States',
        UAE:'United Arab Emirates', NOR:'Norway', NO:'Norway', SWE:'Sweden', SE:'Sweden',
        DNK:'Denmark', DK:'Denmark', FIN:'Finland', FI:'Finland', NLD:'Netherlands', NL:'Netherlands',
        DEU:'Germany', DE:'Germany', FRA:'France', FR:'France', ESP:'Spain', ES:'Spain',
        PRT:'Portugal', PT:'Portugal', CHL:'Chile', CL:'Chile', NZL:'New Zealand', AUS:'Australia',
        AU:'Australia', CAN:'Canada', CA:'Canada', PER:'Peru', PE:'Peru', IDN:'Indonesia',
        PHL:'Philippines', VNM:'Vietnam', BGD:'Bangladesh', IND:'India', IN:'India',
        CHN:'China', CN:'China', JPN:'Japan', JP:'Japan', KOR:'South Korea', TUR:'Turkey',
        ISL:'Iceland', IS:'Iceland', RUS:'Russia', BRA:'Brazil', ARG:'Argentina', NG:'Nigeria',
        NGA:'Nigeria', MAR:'Morocco', LBR:'Liberia', PAN:'Panama', BHS:'Bahamas', MRT:'Mauritania',
        PRC:'China', ROC:'Taiwan', TWN:'Taiwan',
      };
      const up = v.trim().toUpperCase().replace(/[^A-Z]/g, '');
      if (ISO_MAP[up]) return ISO_MAP[up];
      return v.replace(/\b\w/g, c => c.toUpperCase()).slice(0, 60);
    }
    case 'production_method': {
      const lc = v.toLowerCase();
      if (/net.?pen|sea.?cage|open.?net|\bcage\b/.test(lc)) return 'Sea cage / Net pen';
      if (/\bras\b|recirculat/.test(lc)) return 'RAS (Recirculating)';
      if (/\bpond\b/.test(lc)) return 'Pond culture';
      if (/\btank\b/.test(lc)) return 'Tank culture';
      if (/raft|long.?line/.test(lc)) return 'Longline / Raft';
      if (/flow.?through/.test(lc)) return 'Flow-through';
      if (/integrat/.test(lc)) return 'Integrated system';
      return v.slice(0, 80);
    }
    case 'water_type': {
      const lc = v.toLowerCase();
      if (/fresh|river|lake/.test(lc)) return 'Freshwater';
      if (/salt|marine|ocean|\bsea\b/.test(lc)) return 'Saltwater / Marine';
      if (/brackish|estuar/.test(lc)) return 'Brackish water';
      return v.slice(0, 40);
    }
    default:
      // Generic: reject if too long or looks like a URL/code block
      if (v.length > 150) return v.slice(0, 150);
      if (/^https?:\/\//.test(v)) return '';
      return v;
  }
}

/** Relevance score — how many times does the query appear in the text? */
function relevanceScore(text, q) {
  if (!text || !q) return 0;
  const terms = q.toLowerCase().split(/\s+/).filter(t => t.length > 2);
  const tl = text.toLowerCase();
  return terms.reduce((n, t) => n + (tl.split(t).length - 1), 0);
}

// Returns true if page text is topically compatible with the requested search type.
// Prevents e.g. random vessel pages appearing in farm results and vice-versa.
function topicMatch(text, searchType) {
  if (!text || !searchType || searchType === 'general') return true;
  const tl = text.toLowerCase();
  const FARM_KW   = /aquaculture|fish farm|fish cage|net pen|hatchery|salmon farm|shrimp farm|trout farm|tilapia|sea bass|seabass|bream|fcr|stocking density|harvest cycle|asc certified|bap certified|bap star|certified producer|certified facility|seafood source|global salmon|species farmed/;
  const MILL_KW   = /fishmeal|fish meal|fish oil|fishoil|processing plant|feed mill|reduction plant|feed factory|skretting|biomar|tasa fishmeal|omega-3|marine ingredients|iffo|eumofa|menhaden|anchoveta|reduction|fishmeal content/;
  const VESSEL_KW = /\bimo\b|mmsi|flag state|call sign|gross tonnage|deadweight|port of registry|marinetraffic|vesselfinder|fleetmon|ais|nav status|fishing vessel|cargo vessel|bulk carrier|tanker|container ship|year built|fao global record|ship registry|vessel registry/;
  if (searchType === 'farm')   return FARM_KW.test(tl)   || !VESSEL_KW.test(tl);
  if (searchType === 'mill')   return MILL_KW.test(tl)   || !VESSEL_KW.test(tl);
  if (searchType === 'vessel') return VESSEL_KW.test(tl) || !FARM_KW.test(tl);
  return true;
}

// Returns only the fields appropriate for a given search type.
function filterFieldsByType(fields, searchType) {
  if (!searchType || searchType === 'general') return fields;
  const VESSEL_ONLY = new Set(['vessel_type','call_sign','gross_tonnage','dwt','year_built','mmsi','port_of_registry','length','beam','nav_status','class_soc','_imo','flag']);
  const FARM_ONLY   = new Set(['species','water_type','production_method','certification','water_temp','salinity','dissolved_oxygen','ph','fcr','stocking_density','harvest_cycles','total_area','license']);
  const MILL_ONLY   = new Set(['processing_capacity','input_species','output_products','fishmeal_pct','fishoil_pct','feed_type','certification']);
  const out = {};
  for (const [k, v] of Object.entries(fields)) {
    if (searchType === 'vessel' && FARM_ONLY.has(k)) continue;
    if (searchType === 'vessel' && MILL_ONLY.has(k)) continue;
    if (searchType === 'farm'   && VESSEL_ONLY.has(k)) continue;
    if (searchType === 'mill'   && VESSEL_ONLY.has(k)) continue;
    out[k] = v;
  }
  return out;
}

/** Post-merge field normalizer — deduplicates species lists, standardizes units,
 *  trims runaway values, and enforces consistent country / certification names.
 *  Called from mergeFields() after all sources have been ranked and combined. */
function normalizeFields(merged) {
  // ── Species / input_species: split comma-list, title-case, deduplicate, reject noise
  ['species', 'input_species'].forEach(k => {
    if (!merged[k]) return;
    const parts = merged[k].split(/[,;\/]+/).map(s =>
      s.trim().replace(/\b\w/g, c => c.toUpperCase())
    ).filter(t =>
      t.length > 2 &&
      !/^(Fish|Seafood|Animal|Marine|Aquatic|Product|Species|Other|Various|Mixed|And|Or|The)$/.test(t)
    );
    const deduped = [...new Set(parts)].slice(0, 6).join(', ');
    if (deduped) merged[k] = deduped; else delete merged[k];
  });

  // ── Certification: deduplicate / merge multiple mentions into a clean list
  if (merged.certification) {
    const CERTS = ['ASC Certified','MSC Certified','BAP Certified','GlobalG.A.P. Certified','Halal Certified'];
    const hits = CERTS.filter(c => merged.certification.toUpperCase().includes(c.split(' ')[0]));
    if (hits.length) merged.certification = hits.join(', ');
    else merged.certification = merged.certification.slice(0, 100);
  }

  // ── Capacity / processing_capacity: normalize units and trim
  ['capacity', 'processing_capacity'].forEach(k => {
    if (!merged[k]) return;
    merged[k] = merged[k]
      .replace(/\b(per\s*year|annually|p\.a\.)\b/gi, '/yr')
      .replace(/\b(per\s*day|daily)\b/gi,            '/day')
      .replace(/\bmetric\s*ton(?:ne)?s?\b/gi,         't')
      .replace(/\s{2,}/g, ' ').trim().slice(0, 80);
  });

  // ── Country: canonical title-case; promote flag → country if needed
  if (merged.country) merged.country = merged.country.replace(/\b\w/g, c => c.toUpperCase()).slice(0, 60);
  if (!merged.country && merged.flag) merged.country = merged.flag;

  // ── Description: trim to ≤1000 chars, always ending on a full sentence
  if (merged.description && merged.description.length > 1000) {
    const chunk = merged.description.slice(0, 1000);
    // Find the last sentence-ending punctuation (. ! ?) within the chunk
    const lastSentEnd = Math.max(chunk.lastIndexOf('.'), chunk.lastIndexOf('!'), chunk.lastIndexOf('?'));
    merged.description = lastSentEnd > 50 ? chunk.slice(0, lastSentEnd + 1) : chunk.replace(/\s+\S+$/, '') + '…';
  }

  // ── Remove runaway strings in non-description fields (likely scraped boilerplate)
  for (const [k, v] of Object.entries(merged)) {
    if (k === 'description' || k.startsWith('_') || typeof v !== 'string') continue;
    if (v.length > 150) merged[k] = v.slice(0, 150).replace(/\s+\S*$/, '').trim();
  }

  return merged;
}

/** Rate limiter — min ms between requests per domain */
const _lastReq = {};
async function rateLimit(domain, ms = 800) {
  const now = Date.now();
  const last = _lastReq[domain] || 0;
  const wait = ms - (now - last);
  if (wait > 0) await sleep(wait);
  _lastReq[domain] = Date.now();
}

/* ═══════════════════════════════════════════
   STATE & CONFIG
═══════════════════════════════════════════ */
const PROXIES = [
  'https://api.allorigins.win/raw?url=',
  'https://corsproxy.io/?url=',
  'https://api.codetabs.com/v1/proxy?quest=',
  'https://thingproxy.freeboard.io/fetch/',
  'https://api.allorigins.win/get?url=',          // JSON wrapper fallback
  'https://corsproxy.io/?',
  'https://proxy.cors.sh/',
  'https://cors.deno.dev/',
  'https://corsproxy.org/?url=',
  'https://openproxy.space/get/',
];

// Proxy health: tracks consecutive failures — skip proxies that consistently fail
// Persisted across sessions so bad proxies aren't retried on every reload
const proxyFails = new Map();
const PROXY_MAX_FAILS = 2; // mark proxy dead after 2 failures in this session
try {
  const pf = JSON.parse(localStorage.getItem('ship_pfails1') || '{}');
  Object.entries(pf).forEach(([k,v]) => { if (v > 0) proxyFails.set(k, v); });
} catch {}

/* Rotating user-agent pool — looks like organic browser traffic */
const UA_POOL = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
  'Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0',
];
const REFERERS = [
  'https://www.google.com/',
  'https://www.bing.com/',
  'https://duckduckgo.com/',
  'https://www.google.co.uk/',
  'https://www.google.no/',
  'https://www.google.es/',
  'https://www.google.fr/',
  'https://www.google.com.br/',
  'https://www.google.co.jp/',
  'https://www.google.cn/',
];

// Multi-language Accept-Language header — signals willingness to receive any language
const ACCEPT_LANG = 'en,en-US;q=0.9,no;q=0.8,es;q=0.8,fr;q=0.7,pt;q=0.7,zh;q=0.6,ja;q=0.5,ar;q=0.5,ru;q=0.4,*;q=0.3';
function randUA()  { return UA_POOL[Math.floor(Math.random() * UA_POOL.length)]; }
function randRef() { return REFERERS[Math.floor(Math.random() * REFERERS.length)]; }
function jitter(ms) { return new Promise(r => setTimeout(r, ms + Math.random() * ms)); }

const MAX_FILE_BYTES = 25 * 1024 * 1024; // 25 MB
let stats    = { searches:0, ships:0, images:0 };
let saved    = [];
let bulkRes  = [];
let lastFileText = '';
let pendingFile  = null;  // File selected but not yet extracted
let logEl    = null;
let currentAC = null;   // AbortController for active search
let enrichAC  = null;   // AbortController for modal enrichment
let fileRawAC = null;   // AbortController for handleFileRaw web enrichment
let isRunning = false;  // Lock: prevent double-submit

// Knowledge base: persistent learning across sessions
let learned     = {};  // normalizedName → { fields, sources, hitCount, confidence, lastSeen }
let domainStats = {};  // hostname → { hits, successes, totalFields }

/** Session-level cache: url → html text */
const reqCache = new Map();

/* ═══════════════════════════════════════════
   LAZY LIBRARY LOADER
   pdf.js · xlsx · mammoth loaded on first file upload — not on page load
═══════════════════════════════════════════ */
const LIB_URLS = {
  pdf:     'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js',
  xlsx:    'https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js',
  mammoth: 'https://cdnjs.cloudflare.com/ajax/libs/mammoth/1.6.0/mammoth.browser.min.js',
};
const _libLoaded = {};
function loadLib(key) {
  if (_libLoaded[key]) return _libLoaded[key];
  _libLoaded[key] = new Promise((resolve, reject) => {
    const existing = document.querySelector(`script[data-lib="${key}"]`);
    if (existing) { resolve(); return; }
    const s = document.createElement('script');
    s.src           = LIB_URLS[key];
    s.dataset.lib   = key;
    s.crossOrigin   = 'anonymous';
    s.referrerPolicy = 'no-referrer';
    s.onload  = resolve;
    s.onerror = () => reject(new Error(`Failed to load ${key}`));
    document.head.appendChild(s);
  });
  return _libLoaded[key];
}
async function ensureFileLibs() {
  await Promise.all([
    loadLib('pdf'),
    loadLib('xlsx'),
    loadLib('mammoth'),
  ]);
  // Configure pdfjs worker after load
  if (typeof pdfjsLib !== 'undefined' && !pdfjsLib.GlobalWorkerOptions.workerSrc) {
    pdfjsLib.GlobalWorkerOptions.workerSrc =
      'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';
  }
}

/* ═══════════════════════════════════════════
   STORAGE — IDB-first, localStorage fallback
═══════════════════════════════════════════ */
async function loadPersistedData() {
  try {
    // Migrate any existing localStorage data on first run
    if (window.AppIDB) await AppIDB.migrateFromLocalStorage();

    // Load saved records from IDB
    const records = window.AppIDB ? await AppIDB.getAll('records') : [];
    if (records.length) {
      saved = records.sort((a, b) => (b._ts || 0) - (a._ts || 0));
    } else {
      // IDB empty — check localStorage fallback
      try { saved = JSON.parse(localStorage.getItem('ship_saved3') || '[]'); } catch {}
    }
    // Ensure every record has id (IDB keyPath) — backfill from _id for old records
    saved = saved.map(r => (r.id ? r : { ...r, id: r._id }));

    // Load knowledge base from IDB
    const kEntry = window.AppIDB ? await AppIDB.get('knowledge', 'learned') : null;
    if (kEntry && kEntry.data) {
      learned     = kEntry.data.learned     || {};
      domainStats = kEntry.data.domainStats || {};
    } else {
      try {
        const ld = JSON.parse(localStorage.getItem('ship_learned1') || '{}');
        learned = ld.learned || {}; domainStats = ld.domainStats || {};
      } catch {}
    }

    // Load proxy health from IDB
    const pfEntry = window.AppIDB ? await AppIDB.get('knowledge', 'pfails') : null;
    if (pfEntry && pfEntry.data) {
      Object.entries(pfEntry.data).forEach(([k, v]) => proxyFails.set(k, v));
    } else {
      try {
        const pf = JSON.parse(localStorage.getItem('ship_pfails1') || '{}');
        Object.entries(pf).forEach(([k, v]) => proxyFails.set(k, v));
      } catch {}
    }
  } catch (e) {
    console.warn('[Storage] Load error, using defaults:', e);
    // Hard fallback to localStorage
    try { saved = JSON.parse(localStorage.getItem('ship_saved3') || '[]'); } catch {}
  }
}

/* ═══════════════════════════════════════════
   INIT
═══════════════════════════════════════════ */
window.addEventListener('load', async () => {
  // 1. Hydrate data from IDB (async, non-blocking for render)
  await loadPersistedData();

  document.getElementById('main-search').addEventListener('keydown', e => {
    if (e.key === 'Enter' && !isRunning) runBot();
  });
  // URL inputs use inline onkeydown handlers in HTML

  populateYearSelects();
  renderSaved();
  updateStats();
  updateSavedBadge();

  // Category options per facility type
  const CAT_OPTIONS = {
    farm: [
      ['', 'All Species'],
      ['salmon',             'Salmon'],
      ['trout',              'Trout'],
      ['shrimp',             'Shrimp / Prawn'],
      ['tilapia',            'Tilapia'],
      ['catfish',            'Catfish'],
      ['tuna',               'Tuna'],
      ['cod',                'Cod'],
      ['sea bass sea bream', 'Sea Bass / Sea Bream'],
      ['carp',               'Carp'],
      ['oyster shellfish',   'Oyster / Shellfish'],
    ],
    mill: [
      ['', 'All Products'],
      ['fishmeal',           'Fishmeal'],
      ['fish oil',           'Fish Oil'],
      ['surimi',             'Surimi'],
      ['canned fish',        'Canned Fish'],
      ['frozen fish',        'Frozen Fish / Fillets'],
      ['dried fish',         'Dried / Salted Fish'],
      ['fish pellets',       'Fish Feed Pellets'],
      ['fish byproducts',    'By-products / Offal'],
    ],
    vessel: [
      ['', 'All Vessel Types'],
      ['trawler',                    'Trawler'],
      ['longliner',                  'Longliner'],
      ['purse seiner',               'Purse Seiner'],
      ['gillnetter',                 'Gillnetter'],
      ['factory vessel',             'Factory / Processing Vessel'],
      ['reefer carrier',             'Reefer / Fish Carrier'],
      ['crab lobster vessel',        'Crab / Lobster Vessel'],
      ['squid jigger',               'Squid Jigger'],
      ['pole liner',                 'Pole & Line Vessel'],
      ['aquaculture support vessel', 'Aquaculture Support Vessel'],
    ],
    general: [
      ['', 'All Types'],
      ['salmon','Salmon'], ['trout','Trout'], ['shrimp','Shrimp / Prawn'],
      ['tilapia','Tilapia'], ['tuna','Tuna'], ['cod','Cod'],
      ['oyster shellfish','Oyster / Shellfish'],
      ['fishmeal','Fishmeal'], ['fish oil','Fish Oil'],
      ['trawler','Trawler'], ['longliner','Longliner'],
      ['purse seiner','Purse Seiner'], ['factory vessel','Factory Vessel'],
    ],
  };

  function updateCategoryOptions() {
    const t  = document.getElementById('search-type')?.value || 'farm';
    const el = document.getElementById('cat-filter');
    if (!el) return;
    const opts = CAT_OPTIONS[t] || CAT_OPTIONS.general;
    el.innerHTML = opts.map(([v, l]) => `<option value="${v}">${l}</option>`).join('');
  }

  // Update hero text when facility type changes
  const typeEl = document.getElementById('search-type');
  const searchEl = document.getElementById('main-search');
  function updateHero() {
    const t = typeEl?.value || 'farm';
    const title = document.getElementById('hero-title');
    const desc  = document.getElementById('hero-desc');
    const ph    = { farm:'Farm or mill name (e.g. Leroy Seafood, Mowi, Skretting)',
                    mill:'Mill or processing plant name (e.g. Skretting, BioMar, TASA)',
                    vessel:'Vessel name or IMO number (e.g. Atlantic Dawn, 1234567)',
                    general:'Name, IMO, or URL to search' };
    const titles = { farm:'Fish Farm Intelligence Bot', mill:'Fish Mill Intelligence Bot',
                     vessel:'Ship & Vessel Scraper', general:'Fish Farm & Ship Scraper' };
    const descs  = {
      farm:   'Enter the name of a fish farm or aquaculture facility. The bot searches OpenStreetMap, Wikipedia, FAO, ASC producer lists, and live web pages to extract location coordinates, species farmed, annual production capacity, water type, certification status (ASC, BAP, GlobalG.A.P.), stocking density, FCR, harvest cycles, and operator details. Only aquaculture-relevant data is returned — vessel or processing-plant fields are excluded.',
      mill:   'Enter the name of a fishmeal or fish oil processing plant. The bot queries industry registries, trade databases, Wikipedia, and web sources to retrieve input species, output products, fishmeal and fish oil percentages, annual processing capacity, feed type, certifications, and country of operation. Results are filtered strictly to processing-plant information.',
      vessel: 'Enter a vessel name or its 7-digit IMO number. The bot queries MarineTraffic, VesselFinder, FleetMon, Equasis, the ITU ship-station registry, OpenStreetMap, and Wikipedia to compile a full ship profile — flag state, call sign, gross tonnage, DWT, year built, vessel type, port of registry, current AIS nav status, and owner / operator. Only vessel-specific fields are included in the result.',
      general:'Enter any name or IMO number and the bot will auto-detect whether the target is a fish farm, fish mill, or vessel, then query all relevant sources. Location, species or cargo type, capacity, certifications, ownership, and photos are gathered from OpenStreetMap, Wikipedia, maritime registries, and live web pages.'
    };
    if (title) title.textContent = titles[t] || titles.general;
    if (desc)  desc.textContent  = descs[t]  || descs.general;
    if (searchEl) searchEl.placeholder = ph[t] || ph.general;
    updateCategoryOptions();
  }
  typeEl?.addEventListener('change', updateHero);
  updateHero();

  // 2. Boot hash router — auto-runs search if URL has #search?q=...
  if (window.AppRouter) AppRouter.init();

  // 3. Light up AI dot if key is already configured
  updateClaudeHeaderDot();

  // 3. Register service worker for offline + asset caching
  if ('serviceWorker' in navigator) {
    // Use relative path so it works on any base (localhost, GitHub Pages /fish-intel/, etc.)
    navigator.serviceWorker.register('sw.js', { scope: './' }).catch(e =>
      console.warn('[SW] Registration failed:', e)
    );
  }
});

function setMode(mode) {
  document.querySelectorAll('.mode-body').forEach(b => { b.hidden = true; });
  document.querySelectorAll('.mode-btn').forEach(b => {
    b.classList.remove('active');
    b.setAttribute('aria-selected', 'false');
  });
  const body = document.getElementById('mode-' + mode);
  const btn  = document.getElementById('mbtn-' + mode);
  if (body) body.hidden = false;
  if (btn)  {
    btn.classList.add('active');
    btn.setAttribute('aria-selected', 'true');
    btn.scrollIntoView({ behavior: 'smooth', inline: 'nearest', block: 'nearest' });
  }
  // Clear route when switching away from search
  if (mode !== 'search' && window.AppRouter) AppRouter.clear();
}

function fillSearch(q) {
  const input = document.getElementById('main-search');
  if (input) { input.value = q; input.focus(); }
  runBot();
}

/* ═══════════════════════════════════════════════════════════════════
   CLAUDE API INTEGRATION
   Direct browser calls via anthropic-dangerous-direct-browser-access.
   Key stored in IDB — never leaves the browser except to api.anthropic.com.
═══════════════════════════════════════════════════════════════════ */
const CLAUDE_API  = 'https://api.anthropic.com/v1/messages';
const CLAUDE_VER  = '2023-06-01';

// ── Key + model storage ────────────────────────────────────────────────────
async function getClaudeKey() {
  try {
    const entry = window.AppIDB ? await AppIDB.get('knowledge', 'claude-settings') : null;
    return entry?.apiKey || null;  // apiKey ≠ key (IDB record key)
  } catch { return null; }
}
async function getClaudeModel() {
  try {
    const entry = window.AppIDB ? await AppIDB.get('knowledge', 'claude-settings') : null;
    return entry?.model || 'claude-3-5-haiku-20241022';
  } catch { return 'claude-3-5-haiku-20241022'; }
}
// ── Settings modal ─────────────────────────────────────────────────────────
async function openSettings() {
  const modal = document.getElementById('settings-modal');
  if (!modal) return;
  // Pre-fill saved key (masked) + model
  const savedKey   = await getClaudeKey();
  const savedModel = await getClaudeModel();
  const keyInput   = document.getElementById('claude-key-input');
  const modelSel   = document.getElementById('claude-model-sel');
  if (keyInput) keyInput.value = savedKey ? '••••••••' + savedKey.slice(-6) : '';
  if (modelSel) modelSel.value = savedModel;
  updateClaudeStatus(!!savedKey);
  modal.classList.add('show');
}
function closeSettings() {
  document.getElementById('settings-modal')?.classList.remove('show');
}
async function saveClaudeKey() {
  const keyInput = document.getElementById('claude-key-input');
  const modelSel = document.getElementById('claude-model-sel');
  const raw = keyInput?.value?.trim() || '';
  // If user typed the masked version back, don't overwrite
  if (raw.startsWith('••••')) { toast('Key unchanged'); closeSettings(); return; }
  if (raw && !raw.startsWith('sk-ant-')) {
    toast('API key should start with sk-ant-'); return;
  }
  const model = modelSel?.value || 'claude-3-5-haiku-20241022';
  try {
    if (window.AppIDB) {
      await AppIDB.put('knowledge', { key: 'claude-settings', apiKey: raw || null, model });
    }
    updateClaudeStatus(!!raw);
    updateClaudeHeaderDot();
    toast(raw ? '✓ Claude API key saved' : 'API key cleared');
    closeSettings();
  } catch (e) { toast('Failed to save key'); }
}
async function clearClaudeKey() {
  if (!confirm('Remove the saved API key?')) return;
  try {
    if (window.AppIDB) await AppIDB.put('knowledge', { key: 'claude-settings', apiKey: null, model: 'claude-3-5-haiku-20241022' });
    document.getElementById('claude-key-input').value = '';
    updateClaudeStatus(false);
    updateClaudeHeaderDot();
    toast('API key cleared');
  } catch {}
}
function updateClaudeStatus(active) {
  const el = document.getElementById('claude-status');
  if (!el) return;
  el.innerHTML = active
    ? `<div class="claude-status-ok">✓ Claude AI active — searches will be AI-enhanced</div>`
    : `<div class="claude-status-off">No API key — scraping uses regex extraction only. <a href="https://console.anthropic.com" target="_blank" rel="noopener">Get a key →</a></div>`;
}
async function updateClaudeHeaderDot() {
  const dot = document.getElementById('claude-dot');
  if (!dot) return;
  const key = await getClaudeKey();
  dot.style.display = key ? 'inline-flex' : 'none';
}

// ── Core Claude API call ───────────────────────────────────────────────────
async function callClaude(system, user, maxTokens = 800, signal = null) {
  const [key, model] = await Promise.all([getClaudeKey(), getClaudeModel()]);
  if (!key) return null;
  const res = await fetch(CLAUDE_API, {
    method: 'POST',
    signal: timedSignal(signal, 30000), // 30 s hard cap — API can be slow on long contexts
    headers: {
      'x-api-key': key,
      'anthropic-version': CLAUDE_VER,
      'anthropic-dangerous-direct-browser-access': 'true',
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      model,
      max_tokens: maxTokens,
      system,
      messages: [{ role: 'user', content: user }],
    }),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Claude ${res.status}: ${err.slice(0, 120)}`);
  }
  const data = await res.json();
  return data.content?.[0]?.text || '';
}

// ── Field schema by type ───────────────────────────────────────────────────
function claudeFieldSchema(searchType) {
  const base = {
    name:        'Full facility name',
    operator:    'Operating company or owner',
    country:     'Full country name (not ISO code)',
    location:    'City, region or address',
    latitude:    'Decimal degrees (number)',
    longitude:   'Decimal degrees (number)',
    description: 'Write an investigative-grade paragraph (200–600 words) as if you are a journalist. Cover: what the entity does, where it operates, its scale and capacity, ownership structure, certifications, notable incidents or controversies, and any financial or environmental context found in the text. Only use facts explicitly stated in the provided content — never infer or hallucinate.',
  };
  if (searchType === 'vessel') return {
    vessel_name: 'Full vessel name', imo: '7-digit IMO number',
    flag:        'Flag state — full country name', call_sign: 'Radio call sign',
    vessel_type: 'e.g. Trawler, Longliner, Purse Seiner, Reefer',
    gross_tonnage:'GT figure', dwt: 'Deadweight tonnage',
    length:      'LOA in metres', beam: 'Beam in metres',
    built_year:  '4-digit year', engine: 'Engine type / kW',
    speed:       'Service speed in knots', port_of_registry: 'Home port',
    owner:       'Registered owner', operator: 'Commercial operator',
    mmsi:        '9-digit MMSI',
    description: 'Investigative summary paragraph covering vessel history, ownership chain, flag changes, trading routes, any detentions or port-state control findings, and notable incidents. Facts only.',
  };
  if (searchType === 'mill') return {
    ...base,
    input_species:       'Raw fish species used, comma-separated',
    products:            'Output products e.g. fishmeal, fish oil',
    processing_capacity: 'Annual throughput with units e.g. 50,000 t/yr',
    certification:       'Certifications held',
  };
  return { // farm / general
    ...base,
    species:             'Species farmed, comma-separated',
    production_capacity: 'Annual output with units e.g. 12,000 t/yr',
    water_type:          'Freshwater | Saltwater / Marine | Brackish water',
    production_method:   'e.g. Sea cage / Net pen, RAS, Pond culture',
    certification:       'e.g. ASC Certified, BAP Certified',
    area_hectares:       'Farm area in hectares',
    stocking_density:    'Stocking density with units',
    fcr:                 'Feed Conversion Ratio (number)',
    harvest_cycle:       'Duration e.g. 24 months',
    established_year:    '4-digit year the facility was established',
  };
}

// ── Smart extraction: runs concurrently with the scraping loop ────────────
async function claudeExtract(pageTexts, query, searchType, signal = null) {
  const schema = claudeFieldSchema(searchType);
  const system = [
    `You are a precision data extraction engine for an aquaculture and maritime intelligence platform.`,
    `Extract structured data about "${query}" from the following web content.`,
    `Return ONLY a raw JSON object — no markdown, no explanation, no fences.`,
    `Rules:`,
    `• Include only fields with values EXPLICITLY stated in the text`,
    `• Return {} if the page is clearly not about the searched entity`,
    `• Never hallucinate or infer values not in the text`,
    `• Country codes → full names; abbreviations → full units`,
    `• Coordinates must be decimal degrees`,
  ].join('\n');

  const corpus = pageTexts
    .slice(0, 5)
    .map((p, i) => `=== Source ${i + 1} (${p.source}) ===\n${p.text.slice(0, 4000)}`)
    .join('\n\n');

  const user = `Entity: "${query}" | Type: ${searchType}\n\nFields to extract (use exact key names):\n${JSON.stringify(schema, null, 2)}\n\nContent:\n${corpus}`;

  try {
    const raw = await callClaude(system, user, 2000, signal);
    if (!raw) return {};
    const match = raw.match(/\{[\s\S]*\}/);
    if (!match) return {};
    const parsed = JSON.parse(match[0]);
    // Validate + clean every Claude-returned field
    const clean = {};
    for (const [k, v] of Object.entries(parsed)) {
      if (typeof v === 'string' && v.trim()) clean[k] = validateFieldValue(k, v.trim());
      else if (typeof v === 'number')        clean[k] = String(v);
    }
    return clean;
  } catch (e) {
    console.warn('[Claude] Extract failed:', e.message);
    return {};
  }
}

// ── Smart description: investigative journalist polish pass ──────────────────
async function claudePolishDescription(merged, query, searchType, signal = null) {
  const fields = Object.entries(merged)
    .filter(([k, v]) => !k.startsWith('_') && v && k !== 'description')
    .map(([k, v]) => `${k}: ${v}`)
    .join('\n');

  const existingDesc = merged.description || '';

  const system = `You are an investigative journalist writing for a seafood industry intelligence platform.
Write a thorough, factual profile paragraph about the entity using ONLY the data provided — never invent facts.
Cover: what the entity is and does, its location and scale, species or vessel type, production method, capacity, certifications, and any other significant facts present in the data.
Write in plain, direct English. No marketing language. No fluff. Active voice preferred.
If the provided data is sparse, write a shorter accurate paragraph rather than padding with guesses.
Return ONLY the description paragraph — no JSON, no quotes, no label, no heading.`;

  const user = `Entity: "${query}" (${searchType})
${existingDesc ? `Existing description to improve:\n${existingDesc}\n\n` : ''}Structured data:\n${fields || '(none)'}`;

  try {
    const desc = await callClaude(system, user, 600, signal);
    if (!desc) return null;
    const trimmed = desc.trim();
    if (trimmed.length <= 1000) return trimmed;
    const chunk = trimmed.slice(0, 1000);
    const lastSentEnd = Math.max(chunk.lastIndexOf('.'), chunk.lastIndexOf('!'), chunk.lastIndexOf('?'));
    return lastSentEnd > 50 ? chunk.slice(0, lastSentEnd + 1) : chunk.replace(/\s+\S+$/, '');
  } catch { return null; }
}

function toggleFilters() {
  const row = document.getElementById('filter-row');
  const btn = document.getElementById('filter-toggle');
  if (!row || !btn) return;
  const opening = row.hidden;
  row.hidden = !opening;
  btn.classList.toggle('open', opening);
  btn.textContent = opening ? 'Filters ▴' : 'Filters ▾';
}

function updateStats() {
  document.getElementById('s-searches').textContent = stats.searches;
  document.getElementById('s-ships').textContent    = stats.ships;
  document.getElementById('s-images').textContent   = stats.images;
}

/* ═══════════════════════════════════════════
   IMO VALIDATION
═══════════════════════════════════════════ */
function validIMO(imo) {
  if (!/^\d{7}$/.test(imo)) return false;
  const d = imo.split('').map(Number);
  return (d[0]*7 + d[1]*6 + d[2]*5 + d[3]*4 + d[4]*3 + d[5]*2) % 10 === d[6];
}

function extractIMOs(text) {
  const found = new Set();
  let m;
  const r1 = /\bIMO[\s:.\-#]*(\d{7})\b/gi;
  while ((m = r1.exec(text)) !== null) found.add(m[1]);
  const r2 = /\b(\d{7})\b/g;
  while ((m = r2.exec(text)) !== null) if (validIMO(m[1])) found.add(m[1]);
  return [...found].sort();
}

function highlightIMO(text) {
  // Escape first, then highlight — prevents XSS in raw scraped text
  return esc(text)
    .replace(/\bIMO[\s:.\-#]*(\d{7})\b/gi, (_, n) =>
      `IMO <span class="ih">${esc(n)}</span>`)
    .replace(/\b(\d{7})\b/g, m =>
      validIMO(m) ? `<span class="ih">${esc(m)}</span>` : esc(m));
}

/* ═══════════════════════════════════════════
   PROXY FETCH — with fallback chain & cache
═══════════════════════════════════════════ */
async function fetchViaProxy(url, signal) {
  if (!isValidURL(url)) throw new Error('Blocked: invalid or private URL');

  // Check cache first
  if (reqCache.has(url)) { log('Cache hit ✓', 'ok'); return reqCache.get(url); }

  // Rate limit per domain
  try { await rateLimit(new URL(url).hostname, 400); } catch {}

  const MAX_RETRIES = 2; // 2 attempts per proxy: first try + one retry with backoff
  let lastErr;
  let attempt = 0;

  // Skip proxies that have repeatedly failed this session
  const activeProxies = PROXIES.filter(p => (proxyFails.get(p) || 0) < PROXY_MAX_FAILS);
  const proxiesToUse  = activeProxies.length ? activeProxies : PROXIES;

  for (const proxy of proxiesToUse) {
    let wasKicked = false; // reset per proxy: tracks block/403/429
    for (let retry = 0; retry < MAX_RETRIES; retry++) {
      try {
        if (retry > 0) {
          if (wasKicked) {
            // Site kicked us — wait exactly 3 s before retrying
            log(`Kicked by site — waiting 3s before retry ${retry}/${MAX_RETRIES - 1}…`, 'warn');
            await sleep(3000);
            wasKicked = false;
          } else {
            // Generic error — exponential backoff + jitter
            await jitter(400 * Math.pow(2, retry));
            log(`Retry ${retry}/${MAX_RETRIES - 1} via ${proxy.split('/')[2]}…`, 'warn');
          }
        }

        // Cache-bust on retries so proxy doesn't serve cached blocked response
        const bustUrl = retry > 0
          ? url + (url.includes('?') ? (url.endsWith('?') ? '' : '&') : '?') + '_cb=' + Date.now()
          : url;

        const ua  = randUA();
        const ref = randRef();

        const resp = await fetch(proxy + encodeURIComponent(bustUrl), {
          signal: timedSignal(signal, 5000), // 5 s hard cap per proxy attempt, always applied
          headers: {
            'X-Requested-With': 'XMLHttpRequest',
            'User-Agent':       ua,
            'Referer':          ref,
            'Accept':           'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language':  ACCEPT_LANG,
            'Cache-Control':    retry > 0 ? 'no-cache' : 'default',
          },
        });

        // 429 Rate-limit and 403 Forbidden are explicit kicks — flag for 3s wait
        if (resp.status === 429 || resp.status === 403) {
          wasKicked = true;
          throw new Error(`HTTP ${resp.status} — site blocked request`);
        }
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

        let text = await resp.text();

        // allorigins /get returns JSON wrapper — unwrap it
        if (proxy.includes('/get?url=')) {
          try { text = JSON.parse(text).contents || text; } catch {}
        }

        if (text.length < 50) throw new Error('Empty response');

        // Detect block pages (Cloudflare, CAPTCHA, etc.) — flag for 3s wait
        const lc = text.toLowerCase();
        const blocked = ['access denied','403 forbidden','cloudflare','just a moment',
          'enable javascript','captcha','robot','are you human','blocked','rate limit']
          .some(kw => lc.includes(kw) && text.length < 8000);
        if (blocked) {
          wasKicked = true;
          throw new Error('Block page detected');
        }

        if (reqCache.size >= 100) reqCache.delete(reqCache.keys().next().value); // evict oldest
        reqCache.set(url, text);
        proxyFails.set(proxy, 0); // reset health on success
        saveProxyHealth();
        if (attempt > 0) log(`Bypassed after ${attempt} attempt(s) ✓`, 'ok');
        return text;

      } catch (e) {
        lastErr = e;
        attempt++;
        if (e.name === 'AbortError') throw e;
        if (retry === MAX_RETRIES - 1) {
          proxyFails.set(proxy, (proxyFails.get(proxy) || 0) + 1);
          saveProxyHealth();
          log(`Proxy ${proxy.split('/')[2]} exhausted — trying next…`, 'warn');
        }
      }
    }
    // Small gap between switching proxies
    await jitter(200);
  }
  throw lastErr || new Error('All proxies exhausted after retries');
}

function parseHTML(html) {
  const doc = new DOMParser().parseFromString(html, 'text/html');
  // noscript is intentionally kept — extractImages reads it for lazy-load fallbacks.
  // Only executable elements and navigation chrome are stripped here.
  doc.querySelectorAll('script,style,nav,footer,iframe,form,header,aside,[class*="cookie"],[class*="consent"],[class*="banner"],[class*="popup"],[id*="cookie"],[id*="gdpr"]').forEach(e => e.remove());
  return doc;
}

/* ═══════════════════════════════════════════
   TRANSLATION (chunked, with abort)
═══════════════════════════════════════════ */
/** Detect page language from HTML lang attribute or common script patterns */
function detectLang(doc, text) {
  const htmlLang = doc?.documentElement?.getAttribute('lang') || '';
  if (htmlLang) return htmlLang.slice(0, 2).toLowerCase();
  // Script-based heuristics for undeclared languages
  if (/[一-鿿]/.test(text)) return 'zh';
  if (/[぀-ゟ゠-ヿ]/.test(text)) return 'ja';
  if (/[가-힯]/.test(text)) return 'ko';
  if (/[؀-ۿ]/.test(text)) return 'ar';
  if (/[Ѐ-ӿ]/.test(text)) return 'ru';
  return 'en';
}

/** Combine caller's abort signal with a per-call timeout */
function timedSignal(outer, ms) {
  const timeout = AbortSignal.timeout(ms);
  if (!outer) return timeout;
  return AbortSignal.any ? AbortSignal.any([outer, timeout]) : outer;
}

/** Translate a chunk via multiple free APIs — tries each until one succeeds */
async function translateChunk(text, signal) {
  const enc = encodeURIComponent(text);
  const apis = [
    // MyMemory — autodetect → English
    async () => {
      const r = await fetch(
        `https://api.mymemory.translated.net/get?q=${enc}&langpair=autodetect|en`,
        { signal: timedSignal(signal, 8000) }
      );
      const d = await r.json();
      const t = d.responseData?.translatedText;
      if (!t || t === text) throw new Error('no translation');
      return t;
    },
    // Lingva (community-hosted LibreTranslate mirror) — auto → en
    async () => {
      const r = await fetch(
        `https://lingva.ml/api/v1/auto/en/${enc}`,
        { signal: timedSignal(signal, 8000) }
      );
      const d = await r.json();
      if (!d.translation) throw new Error('no translation');
      return d.translation;
    },
    // Sentinel — return original if all APIs fail
    async () => { throw new Error('all APIs failed'); },
  ];
  for (const api of apis) {
    try { return await api(); } catch {}
  }
  return text; // fallback: return original
}

async function translate(text, signal) {
  if (!text?.trim()) return text;
  const chunks = [];
  for (let i = 0; i < text.length; i += 450) chunks.push(text.slice(i, i + 450));
  if (signal?.aborted) throw new DOMException('Aborted', 'AbortError');
  const results = await Promise.all(chunks.map(c => translateChunk(c, signal)));
  return results.join(' ');
}


/* ═══════════════════════════════════════════
   IMAGE EXTRACTION (safe — no innerHTML)
═══════════════════════════════════════════ */
function extractImages(doc, baseURL) {
  const imgs = [];
  const seen = new Set();

  const add = (src, label) => {
    if (!src || src.startsWith('data:') || src.length < 12) return;
    try {
      const abs = new URL(src, baseURL || 'https://x.com').href;
      if (!isValidURL(abs) || seen.has(abs)) return;
      // Reject tracking pixels, UI chrome, and decorative assets
      if (/\/(?:icon|logo|sprite|pixel|avatar|placeholder|blank|loading|spinner|arrow|badge|star|rating|flag)\b[^/]*\.(?:png|gif|svg|webp)/i.test(abs)) return;
      if (/\/(?:beacon|track|pixel)\.(?:gif|png)|\b1x1\b|\bspacer\b/i.test(abs)) return;
      if (/\.(?:svg|ico)$/i.test(abs)) return;
      seen.add(abs);
      imgs.push({ src: abs, label: cleanField(label) || 'Photo' });
    } catch {}
  };

  const sizeOk = img => {
    // Only reject images with explicitly declared small dimensions.
    // Absent dimensions mean lazy-loaded — let them through.
    const w = img.getAttribute('width');
    const h = img.getAttribute('height');
    if (w && !isNaN(parseInt(w)) && parseInt(w) < 80) return false;
    if (h && !isNaN(parseInt(h)) && parseInt(h) < 50) return false;
    return true;
  };

  // og:image / twitter:image — highest-quality editorial image
  const og = doc.querySelector('meta[property="og:image"],meta[property="og:image:url"]');
  if (og?.content) add(og.content, 'Primary photo');
  const tw = doc.querySelector('meta[name="twitter:image"],meta[name="twitter:image:src"]');
  if (tw?.content) add(tw.content, 'Social card');

  // JSON-LD image — supports arrays and nested image objects
  doc.querySelectorAll('script[type="application/ld+json"]').forEach(s => {
    try {
      const items = [].concat(JSON.parse(s.textContent));
      items.forEach(d => {
        const url = d.image?.url || d.image?.[0]?.url || (typeof d.image === 'string' ? d.image : null);
        if (url) add(url, d.name || 'Photo');
      });
    } catch {}
  });

  const processImg = img => {
    if (!sizeOk(img)) return;
    // Prefer lazy-load attributes over the placeholder src
    const src =
      img.getAttribute('data-src') ||
      img.getAttribute('data-lazy') ||
      img.getAttribute('data-lazy-src') ||
      img.getAttribute('data-original') ||
      img.getAttribute('data-img') ||
      img.getAttribute('data-full') ||
      img.getAttribute('data-zoom-src') ||
      img.getAttribute('data-hi-res-src') ||
      img.getAttribute('src') || '';

    // Srcset — pick highest-resolution candidate
    const ss = img.getAttribute('srcset') || img.getAttribute('data-srcset') || '';
    if (ss) {
      const best = ss.split(',')
        .map(e => { const p = e.trim().split(/\s+/); return { url: p[0], w: parseFloat(p[1]) || 0 }; })
        .sort((a, b) => b.w - a.w)[0];
      if (best?.url) add(best.url, img.alt || 'Photo');
    }

    if (src && !src.startsWith('data:')) add(src, img.alt || img.title || 'Photo');
  };

  doc.querySelectorAll('img').forEach(processImg);

  // noscript fallbacks — lazy-loading sites often place the real <img> inside <noscript>
  doc.querySelectorAll('noscript').forEach(ns => {
    const tmp = document.createElement('div');
    tmp.innerHTML = ns.textContent || '';
    tmp.querySelectorAll('img[src]').forEach(img => {
      if (!sizeOk(img)) return;
      const src = img.getAttribute('src') || '';
      if (src && !src.startsWith('data:')) add(src, img.alt || 'Photo');
    });
  });

  // <picture> sources
  doc.querySelectorAll('picture source').forEach(s => {
    const ss = s.getAttribute('srcset') || '';
    const first = ss.split(',')[0]?.trim().split(/\s+/)[0];
    if (first) add(first, 'Photo');
  });

  return imgs.slice(0, 12);
}

function safeAbsURL(src, base) {
  try {
    const u = new URL(src, base);
    return isValidURL(u.href) ? u.href : null;
  } catch { return null; }
}

async function fetchBingImages(query, signal) {
  const imgs = [];
  const seen = new Set();

  const addImg = (raw, label) => {
    try {
      const url = raw
        .replace(/\\u([\da-f]{4})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
        .replace(/\\\//g, '/')
        .replace(/&amp;/g, '&')
        .split('?')[0];
      if (isValidURL(url) && !seen.has(url)) { seen.add(url); imgs.push({ src: url, label }); }
    } catch {}
  };

  try {
    const html = await fetchViaProxy(
      `https://www.bing.com/images/search?q=${encodeURIComponent(query)}&form=HDRSC2&first=1&count=20`,
      signal
    );

    // Bing embeds image data in multiple JSON key formats — try all known variants
    const jsonPatterns = [
      [/"murl"\s*:\s*"(https?[^"]{10,500})"/g,      s => s.replace(/^"murl"\s*:\s*"/, '').replace(/"$/, '')],
      [/"MediaUrl"\s*:\s*"(https?[^"]{10,500})"/g,  s => s.replace(/^"MediaUrl"\s*:\s*"/, '').replace(/"$/, '')],
      [/"imgurl"\s*:\s*"(https?[^"]{10,500})"/g,    s => s.replace(/^"imgurl"\s*:\s*"/, '').replace(/"$/, '')],
      [/"iurl"\s*:\s*"(https?[^"]{10,500})"/g,      s => s.replace(/^"iurl"\s*:\s*"/, '').replace(/"$/, '')],
    ];
    for (const [re, extract] of jsonPatterns) {
      for (const m of (html.match(re) || []).slice(0, 12)) addImg(extract(m), query);
      if (imgs.length >= 8) break;
    }

    // URL-encoded murl in anchor data attributes (alternate Bing encoding)
    for (const m of (html.match(/murl%3[aA](https?[^&"'\s]{10,400})/g) || []).slice(0, 8))
      addImg(decodeURIComponent(m.replace(/^murl%3[aA]/i, '')), query);

  } catch(e) { if (e.name === 'AbortError') throw e; }

  return imgs.slice(0, 8);
}

/**
 * DuckDuckGo image search via the structured i.js JSON API.
 * Requires a two-step fetch: first get a vqd session token from the
 * search page, then use it to call the image API endpoint.
 */
async function fetchDDGImages(query, signal) {
  const imgs = [];
  const seen = new Set();
  try {
    // Step 1: load the image search page to extract the vqd token
    const pageHtml = await fetchViaProxy(
      `https://duckduckgo.com/?q=${encodeURIComponent(query)}&iax=images&ia=images`,
      signal
    );
    const vqdMatch = pageHtml.match(/vqd[='":\s]+([\d-]+)/);
    if (!vqdMatch) return imgs;
    const vqd = vqdMatch[1];

    // Step 2: call the image JSON API with the token
    const apiText = await fetchViaProxy(
      `https://duckduckgo.com/i.js?q=${encodeURIComponent(query)}&o=json&p=1&s=0&u=bing&f=,,,,,&l=us-en&vqd=${vqd}`,
      signal
    );

    let data;
    try { data = JSON.parse(apiText); } catch {
      // i.js sometimes has a non-JSON prefix or wrapper — extract the object
      const m = apiText.match(/\{[\s\S]*\}/);
      if (m) try { data = JSON.parse(m[0]); } catch {}
    }

    for (const r of (data?.results || []).slice(0, 12)) {
      const url = r.image;
      if (url && isValidURL(url) && !seen.has(url)) {
        seen.add(url);
        imgs.push({ src: url, label: r.title || query });
      }
    }
  } catch(e) { if (e.name === 'AbortError') throw e; }
  return imgs.slice(0, 8);
}

/**
 * Fetch the main image(s) for an entity from Wikipedia's REST API.
 * No proxy needed — Wikipedia has open CORS headers.
 * Returns up to 3 images: article thumbnail + any infobox images.
 */
async function fetchWikipediaImages(query, signal) {
  const imgs = [];
  try {
    // 1. Search Wikipedia for the best article title
    const searchUrl = `https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch=${encodeURIComponent(query)}&srlimit=1&format=json&origin=*`;
    const searchRes = await fetch(searchUrl, { signal: timedSignal(signal, 6000) });
    if (!searchRes.ok) return imgs;
    const searchData = await searchRes.json();
    const title = searchData?.query?.search?.[0]?.title;
    if (!title) return imgs;

    // 2. Fetch summary (includes thumbnail of the article's lead image)
    const summaryUrl = `https://en.wikipedia.org/api/rest_v1/page/summary/${encodeURIComponent(title)}`;
    const summaryRes = await fetch(summaryUrl, { signal: timedSignal(signal, 6000) });
    if (!summaryRes.ok) return imgs;
    const summary = await summaryRes.json();

    const thumb = summary.originalimage?.source || summary.thumbnail?.source;
    if (thumb && isValidURL(thumb)) {
      imgs.push({ src: thumb, label: `${title} (Wikipedia)` });
    }

    // 3. Fetch additional page images (infobox photos, facility images)
    const imgUrl = `https://en.wikipedia.org/w/api.php?action=query&titles=${encodeURIComponent(title)}&prop=images&imlimit=10&format=json&origin=*`;
    const imgRes = await fetch(imgUrl, { signal: timedSignal(signal, 5000) });
    if (!imgRes.ok) return imgs;
    const imgData = await imgRes.json();
    const page = Object.values(imgData?.query?.pages || {})[0];
    const wikiImgs = (page?.images || [])
      .map(i => i.title)
      .filter(t => t && !/flag|icon|logo|symbol|blank|commons-logo|question|edit|arrow/i.test(t))
      .slice(0, 4);

    // Resolve each image to a direct URL via imageinfo API
    if (wikiImgs.length) {
      const infoUrl = `https://en.wikipedia.org/w/api.php?action=query&titles=${encodeURIComponent(wikiImgs.join('|'))}&prop=imageinfo&iiprop=url&iiurlwidth=800&format=json&origin=*`;
      const infoRes = await fetch(infoUrl, { signal: timedSignal(signal, 5000) });
      if (infoRes.ok) {
        const infoData = await infoRes.json();
        Object.values(infoData?.query?.pages || {}).forEach(p => {
          const url = p?.imageinfo?.[0]?.thumburl || p?.imageinfo?.[0]?.url;
          if (url && isValidURL(url) && !imgs.some(i => i.src === url)) {
            imgs.push({ src: url, label: (p.title || '').replace(/^File:/i, '').replace(/_/g, ' ').replace(/\.[a-z]+$/i, '') });
          }
        });
      }
    }
  } catch (e) {
    if (e.name === 'AbortError') throw e;
  }
  return imgs.slice(0, 4);
}

/**
 * Fetch the full article extract from Wikipedia's REST summary API.
 * Returns { title, text } or null. No proxy needed.
 */
async function fetchWikipediaText(query, signal) {
  try {
    const searchUrl = `https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch=${encodeURIComponent(query)}&srlimit=1&format=json&origin=*`;
    const searchRes = await fetch(searchUrl, { signal: timedSignal(signal, 6000) });
    if (!searchRes.ok) return null;
    const searchData = await searchRes.json();
    const title = searchData?.query?.search?.[0]?.title;
    if (!title) return null;

    // REST summary endpoint returns the full introductory extract
    const summaryUrl = `https://en.wikipedia.org/api/rest_v1/page/summary/${encodeURIComponent(title)}`;
    const summaryRes = await fetch(summaryUrl, { signal: timedSignal(signal, 6000) });
    if (!summaryRes.ok) return null;
    const summary = await summaryRes.json();

    const extract = summary.extract || '';
    if (extract.length < 50) return null;
    return { title: summary.title || title, text: extract, source: 'Wikipedia' };
  } catch (e) {
    if (e.name === 'AbortError') throw e;
    return null;
  }
}

/* ═══════════════════════════════════════════
   FIELD EXTRACTION (all values sanitized)
═══════════════════════════════════════════ */
function extractFields(doc, text) {
  const f = {};

  // Meta tags — description, keywords, og:title
  const metaDesc = doc.querySelector('meta[name="description"],meta[property="og:description"]');
  if (metaDesc?.content) { const d = cleanField(metaDesc.content); if (d.length >= 30) f.description = d.slice(0, 1200); }
  const ogt = doc.querySelector('meta[property="og:title"]');
  if (ogt?.content) f._ogtitle = cleanField(ogt.content);
  const metaKW = doc.querySelector('meta[name="keywords"]');
  if (metaKW?.content) f._keywords = cleanField(metaKW.content).slice(0, 200);

  // h1 + title → page heading (don't assume vessel vs farm yet)
  const h1 = doc.querySelector('h1');
  const rawH1 = h1 ? cleanField(h1.textContent.split(/[|–—]/)[0]).trim() : '';
  if (rawH1 && rawH1.length > 1 && rawH1.length < 100) f._heading = rawH1;
  if (!f._heading) {
    const title = doc.querySelector('title');
    if (title) {
      const t = cleanField(title.textContent.replace(/\s*[-|].*$/,''));
      if (t.length > 1 && t.length < 80) f._heading = t;
    }
  }

  // Tables — 2-column AND 4-column (label|value|label|value)
  doc.querySelectorAll('tr').forEach(row => {
    const cells = [...row.querySelectorAll('th,td')];
    if (cells.length >= 2) {
      assignField(f, cleanField(cells[0].textContent).toLowerCase(), cleanField(cells[1].textContent));
      if (cells.length >= 4)
        assignField(f, cleanField(cells[2].textContent).toLowerCase(), cleanField(cells[3].textContent));
    }
  });

  // DL/DD
  doc.querySelectorAll('dl').forEach(dl => {
    const dts = [...dl.querySelectorAll('dt')];
    const dds = [...dl.querySelectorAll('dd')];
    dts.forEach((dt,i) => {
      if (dds[i]) assignField(f, cleanField(dt.textContent).toLowerCase(), cleanField(dds[i].textContent));
    });
  });

  // JSON-LD — deep parse: arrays, GeoCoordinates, address, offers
  doc.querySelectorAll('script[type="application/ld+json"]').forEach(s => {
    try {
      const raw = JSON.parse(s.textContent);
      const items = Array.isArray(raw) ? raw : [raw];
      items.forEach(d => {
        if (!d || typeof d !== 'object') return;
        if (d.name && !f.vessel_name) f.vessel_name = cleanField(d.name);
        if (d.description && !f.description) f.description = cleanField(d.description).slice(0,1200);
        if (d.geo && typeof d.geo === 'object') {
          if (d.geo.latitude  && !f.latitude)  f.latitude  = String(d.geo.latitude);
          if (d.geo.longitude && !f.longitude) f.longitude = String(d.geo.longitude);
        }
        if (d.address) {
          if (d.address.addressCountry && !f.country) f.country = cleanField(d.address.addressCountry);
          if (d.address.addressRegion  && !f.region)  f.region  = cleanField(d.address.addressRegion);
        }
        if (d.containedInPlace?.name && !f.region) f.region = cleanField(d.containedInPlace.name);
        if (d.founder?.name && !f.operator) f.operator = cleanField(d.founder.name);
        if (d.legalName && !f.operator) f.operator = cleanField(d.legalName);
      });
    } catch {}
  });

  // Data-attribute key/value elements
  doc.querySelectorAll('[data-label],[data-key],[data-field]').forEach(el => {
    const k = (el.getAttribute('data-label') || el.getAttribute('data-key') || el.getAttribute('data-field') || '').toLowerCase().trim();
    const v = cleanField(el.textContent);
    if (k && v) assignField(f, k, v);
  });

  // .label/.field-label sibling patterns (common in maritime sites)
  doc.querySelectorAll('.label,.field-label,.prop-label,.detail-label,.info-label').forEach(lbl => {
    const k = cleanField(lbl.textContent).toLowerCase();
    const nxt = lbl.nextElementSibling;
    if (nxt) assignField(f, k, cleanField(nxt.textContent));
  });

  // Definition-pair rows: first child is key, second is value
  doc.querySelectorAll('.vessel-detail,.ship-detail,.detail-row,.info-row,.property-row,.data-row').forEach(row => {
    const ch = [...row.children];
    if (ch.length >= 2) assignField(f, cleanField(ch[0].textContent).toLowerCase(), cleanField(ch[1].textContent));
  });

  // ── Coordinate extraction — multiple DOM sources ──────────────────────────
  // 1. Google Maps iframes (embedded maps with lat/lon in src)
  if (!f.latitude) {
    doc.querySelectorAll('iframe[src*="google.com/maps"],iframe[src*="maps.google"]').forEach(iframe => {
      if (f.latitude) return;
      const src = iframe.getAttribute('src') || '';
      const m = src.match(/[?&](?:q|ll|center)=(-?\d{1,3}\.\d{4,8}),(-?\d{1,3}\.\d{4,8})/) ||
                src.match(/@(-?\d{1,3}\.\d{4,8}),(-?\d{1,3}\.\d{4,8})/);
      if (m) {
        const lat = validateFieldValue('latitude',  m[1]);
        const lon = validateFieldValue('longitude', m[2]);
        if (lat && lon) { f.latitude = lat; f.longitude = lon; }
      }
    });
  }

  // 2. Google Maps links (href contains lat/lon)
  if (!f.latitude) {
    doc.querySelectorAll('a[href*="google.com/maps"],a[href*="maps.google"]').forEach(a => {
      if (f.latitude) return;
      const href = a.getAttribute('href') || '';
      const m = href.match(/[?&](?:q|ll)=(-?\d{1,3}\.\d{4,8}),(-?\d{1,3}\.\d{4,8})/) ||
                href.match(/@(-?\d{1,3}\.\d{4,8}),(-?\d{1,3}\.\d{4,8})/);
      if (m) {
        const lat = validateFieldValue('latitude',  m[1]);
        const lon = validateFieldValue('longitude', m[2]);
        if (lat && lon) { f.latitude = lat; f.longitude = lon; }
      }
    });
  }

  // 3. data-lat / data-lng / data-latitude / data-longitude attributes (Leaflet, custom maps)
  if (!f.latitude) {
    doc.querySelectorAll('[data-lat],[data-latitude],[data-loc]').forEach(el => {
      if (f.latitude) return;
      const lat = el.getAttribute('data-lat') || el.getAttribute('data-latitude') || '';
      const lon = el.getAttribute('data-lng') || el.getAttribute('data-lon') ||
                  el.getAttribute('data-longitude') || el.getAttribute('data-long') || '';
      const vLat = validateFieldValue('latitude',  lat.trim());
      const vLon = validateFieldValue('longitude', lon.trim());
      if (vLat && vLon) { f.latitude = vLat; f.longitude = vLon; }
    });
  }

  // 4. Schema.org microdata itemprop (GeoCoordinates on page)
  if (!f.latitude) {
    const mpLat = doc.querySelector('[itemprop="latitude"]');
    const mpLon = doc.querySelector('[itemprop="longitude"]');
    if (mpLat && mpLon) {
      const lat = validateFieldValue('latitude',  (mpLat.getAttribute('content') || mpLat.textContent).trim());
      const lon = validateFieldValue('longitude', (mpLon.getAttribute('content') || mpLon.textContent).trim());
      if (lat && lon) { f.latitude = lat; f.longitude = lon; }
    }
  }

  // 5. Leaflet / OpenLayers JS map init in page source: setView([lat, lon]) or center: [lat, lon]
  if (!f.latitude) {
    const leafM = text.match(/setView\(\[(-?\d{1,3}\.\d{4,8}),\s*(-?\d{1,3}\.\d{4,8})\]/) ||
                  text.match(/center['":\s]+\[(-?\d{1,3}\.\d{4,8}),\s*(-?\d{1,3}\.\d{4,8})\]/);
    if (leafM) {
      const lat = validateFieldValue('latitude',  leafM[1]);
      const lon = validateFieldValue('longitude', leafM[2]);
      if (lat && lon) { f.latitude = lat; f.longitude = lon; }
    }
  }

  // 6. JSON-format lat/lon in page scripts: {"lat":60.12,"lng":5.34} or lat: 60.12, lon: 5.34
  if (!f.latitude) {
    const jM = text.match(/["']?lat(?:itude)?["']?\s*:\s*([-]?\d{1,3}\.\d{4,8})/) ;
    const jL = text.match(/["']?l(?:ng|on|ong|ongitude)["']?\s*:\s*([-]?\d{1,3}\.\d{4,8})/);
    if (jM && jL) {
      const lat = validateFieldValue('latitude',  jM[1]);
      const lon = validateFieldValue('longitude', jL[1]);
      if (lat && lon) { f.latitude = lat; f.longitude = lon; }
    }
  }

  // Regex fallback on plain text
  const pairs = [
    // Maritime — vessel identity
    [/\bIMO[\s#:]*(\d{7})\b/i,                                                        '_imo'],
    [/MMSI[:\s]+(\d{9})/i,                                                            'mmsi'],
    [/[Vv]essel\s*[Tt]ype[:\s]+([A-Za-z /\-]{3,50})/,                               'vessel_type'],
    [/[Ss]hip\s*[Tt]ype[:\s]+([A-Za-z /\-]{3,50})/,                                 'vessel_type'],
    [/[Ff]lag[:\s]+([A-Za-z ]{2,40})/i,                                              'flag'],
    [/[Gg]ross\s*[Tt]onnage[:\s]+([\d,. ]+)/i,                                      'gross_tonnage'],
    [/\bGRT[:\s]+([\d,. ]+)/i,                                                       'gross_tonnage'],
    [/\bDWT[:\s]+([\d,]{1,12})/i,                                                    'dwt'],
    [/(?:Year\s*)?[Bb]uilt[:\s]+(\d{4})/,                                            'year_built'],
    [/[Cc]all\s*[Ss]ign[:\s]+([A-Z0-9]{3,10})/i,                                    'call_sign'],
    [/[Pp]ort\s*of\s*[Rr]egist(?:ry|ration)[:\s]+([A-Za-z ,]{2,60})/,               'port_of_registry'],
    [/[Hh]ome\s*[Pp]ort[:\s]+([A-Za-z ,]{2,60})/,                                   'port_of_registry'],
    [/[Oo]wner[:\s]+([A-Za-z0-9 &,.\-]{3,80})/,                                     'owner'],
    [/[Mm]anager[:\s]+([A-Za-z0-9 &,.\-]{3,80})/,                                   'manager'],
    [/[Oo]perator[:\s]+([A-Za-z0-9 &,.\-]{3,80})/,                                  'operator'],
    // Coordinates — decimal, DMS, and JSON-key formats
    [/[Ll]at(?:itude)?[:\s]+(-?\d{1,3}\.\d{2,8})/,                                  'latitude'],
    [/[Ll]on(?:gitude)?[:\s]+(-?\d{1,3}\.\d{2,8})/,                                 'longitude'],
    [/\blng[:\s]+([-]?\d{1,3}\.\d{4,8})/i,                                          'longitude'],
    [/Coordinates?[:\s]+(-?\d{1,3}\.\d+)[,\s]+(-?\d{1,3}\.\d+)/,                    '_coords'],
    [/(-?\d{1,3}\.\d{4,8})°?\s*[Nn][,\s]+(-?\d{1,3}\.\d{4,8})°?\s*[Ee]/,           '_coords'],
    // DMS format: 60°12'34"N, 005°19'22"E
    [/(\d{1,3})°\s*(\d{1,2})['′]\s*(\d{1,2}(?:\.\d+)?)["″]?\s*[Nn].*?(\d{1,3})°\s*(\d{1,2})['′]\s*(\d{1,2}(?:\.\d+)?)["″]?\s*[Ee]/i, '_dms'],
    // Position: LAT, LON plain text (high-precision only, 4+ decimal places)
    [/\bPosition[:\s]+(-?\d{1,3}\.\d{4,8})[°,\s]+(-?\d{1,3}\.\d{4,8})/i,           '_coords'],
    [/\bLocation[:\s]+(-?\d{1,3}\.\d{4,8})[°,\s]+(-?\d{1,3}\.\d{4,8})/i,           '_coords'],
    // Country / region
    [/[Cc]ountry[:\s]+([A-Za-z ]{2,50})/,                                            'country'],
    [/[Rr]egion[:\s]+([A-Za-z ,]{2,60})/,                                            'region'],
    // Fish farm / aquaculture
    [/[Ss]pecies[:\s]+([A-Za-z ,()]{3,80})/,                                         'species'],
    [/[Ww]ater\s*[Tt]ype[:\s]+([A-Za-z /]{3,40})/,                                  'water_type'],
    [/[Cc]apacity[:\s]+([\d,.]+\s*(?:t(?:on(?:nes?)?)?(?:\/yr|\/year)?|MT(?:\/yr)?|kg(?:\/yr)?|tonnes?)?)/i, 'capacity'],
    [/[Aa]nnual\s*[Pp]rod(?:uction)?[:\s]+([\d,.]+\s*(?:t(?:on(?:nes?)?)?|MT)?)/i,  'capacity'],
    [/[Ll]icen(?:ce|se)\s*(?:[Nn]o\.?|[Nn]umber)?[:\s#]*([A-Z0-9\-/]{3,40})/i,     'license'],
    [/[Cc]ertif(?:ication|ied\s*by)?[:\s]+([A-Za-z ,\-]{3,60})/,                    'certification'],
    [/\bASC[:\s-]+([Cc]ertified|[Aa]pproved|[Ll]abelled)/,                           'certification'],
    [/\bBAP[:\s-]+([Cc]ertified|[Ss]tar|[Aa]ccredited)/,                             'certification'],
    [/[Pp]roduction\s*[Mm]ethod[:\s]+([A-Za-z \-/]{3,50})/,                          'production_method'],
    [/[Ff]arming\s*[Ss]ystem[:\s]+([A-Za-z \-/]{3,50})/,                             'production_method'],
    [/[Ww]ater\s*[Tt]emp(?:erature)?[:\s]+([\d.\-–°CcFf ]+)/,                        'water_temp'],
    [/[Ss]alin(?:ity)?[:\s]+([\d.\-–]+ ?(?:ppt|ppm|g\/L|‰)?)/i,                     'salinity'],
    [/[Dd]issolv(?:ed)?\s*[Oo]xygen[:\s]+([\d.\-–]+ ?(?:mg\/L|ppm)?)/i,             'dissolved_oxygen'],
    [/\bpH[:\s]+([\d.\-–]{1,8})/,                                                    'ph'],
    [/\bFCR[:\s]+([\d.]{1,6})/i,                                                     'fcr'],
    [/[Ss]tocking\s*[Dd]ensity[:\s]+([\d.\-–]+ ?(?:fish\/m[³3]|kg\/m[²2])?)/i,      'stocking_density'],
    [/[Hh]arvest\s*[Cc]ycles?[:\s]+(\d+ ?(?:per year|\/yr|\/year|times)?)/i,         'harvest_cycles'],
    [/[Tt]otal\s*[Aa]rea[:\s]+([\d.,]+ ?(?:ha|hectares?|m[²2]|acres?)?)/i,           'total_area'],
    [/[Ff]eed\s*[Tt]ype[:\s]+([A-Za-z ,\-]{3,50})/,                                  'feed_type'],
    [/[Ee]mployee[s]?[:\s]+(\d{1,6})/i,                                              'employees'],
    // Fish mill / processing
    [/[Pp]rocessing\s*[Cc]apacity[:\s]+([\d.,]+ ?(?:t(?:on(?:nes?)?)?\/(?:day|yr)|MT\/(?:day|yr))?)/i, 'processing_capacity'],
    [/[Ii]nput\s*[Ss]pecies[:\s]+([A-Za-z ,()]{3,80})/,                              'input_species'],
    [/[Oo]utput\s*[Pp]roducts?[:\s]+([A-Za-z ,()]{3,80})/,                           'output_products'],
    [/[Ff]ish\s*[Mm]eal\s*(?:%|percentage|content)?[:\s]+([\d.]+\s*%?)/i,            'fishmeal_pct'],
    [/[Ff]ish\s*[Oo]il\s*(?:%|percentage|content)?[:\s]+([\d.]+\s*%?)/i,             'fishoil_pct'],
  ];

  pairs.forEach(([re, key]) => {
    if (key === '_coords') {
      const m = text.match(re);
      if (m) {
        const lat = validateFieldValue('latitude',  cleanField(m[1]));
        const lon = validateFieldValue('longitude', cleanField(m[2]));
        if (!f.latitude  && lat) f.latitude  = lat;
        if (!f.longitude && lon) f.longitude = lon;
      }
    } else if (key === '_dms') {
      // Convert degrees°minutes'seconds"N/E to decimal
      const m = text.match(re);
      if (m && !f.latitude) {
        const toDec = (d, mn, s) => parseFloat(d) + parseFloat(mn) / 60 + parseFloat(s) / 3600;
        const lat = toDec(m[1], m[2], m[3]);
        const lon = toDec(m[4], m[5], m[6]);
        const vLat = validateFieldValue('latitude',  String(lat.toFixed(6)));
        const vLon = validateFieldValue('longitude', String(lon.toFixed(6)));
        if (vLat && vLon) { f.latitude = vLat; f.longitude = vLon; }
      }
    } else {
      if (!f[key]) {
        const m = text.match(re);
        if (m) {
          const val = validateFieldValue(key, cleanField(m[1]));
          if (val) f[key] = val;
        }
      }
    }
  });

  return f;
}

function assignField(f, k, v) {
  if (!v) return;
  v = cleanField(v);
  // Allow longer values for prose fields; reject oversized values for structured fields
  const isProseField = /description/.test(k);
  if (!v || v.length > (isProseField ? 1200 : 200)) return;
  // ── Maritime / vessel fields (EN + multilingual) ──
  // Flag/country: bandera(ES), pavillon(FR), flagge(DE), flagg(NO), bandeira(PT), 旗(ZH)
  if (/flag|country.*reg|bandera|pavillon|flagge|flagg|bandeira/.test(k))
                                                 f.flag             = f.flag             || v;
  // Vessel type: tipo de buque(ES), type de navire(FR), schiffstyp(DE), fartøystype(NO)
  else if (/vessel.?type|ship.?type|tipo.?buque|tipo.?nave|type.?navire|schiffstyp|fart.?ystype|tipo.?emb/.test(k))
                                                 f.vessel_type      = f.vessel_type      || v;
  // Gross tonnage: tonelaje bruto(ES), jauge brute(FR), bruttoraumzahl(DE), bruttotonn(NO)
  else if (/gross.?ton|grt|gt\b|tonelaje.?bruto|jauge.?brute|bruttoraumzahl|bruttotonn/.test(k))
                                                 f.gross_tonnage    = f.gross_tonnage    || v;
  else if (/dead.?weight|dwt|peso.?muerto|port.?en.?lourd/.test(k))
                                                 f.dwt              = f.dwt              || v;
  // Year built: año de construcción(ES), année de construction(FR), baujahr(DE), byggeår(NO)
  else if (/year.?built|built|keel|a.o.?construcci|ann.e.?constr|baujahr|bygge.?r/.test(k))
                                                 f.year_built       = f.year_built       || v;
  else if (/\bmmsi\b/.test(k))                  f.mmsi             = f.mmsi             || v;
  // Call sign: indicativo(ES), indicatif(FR), rufzeichen(DE), kallesignal(NO)
  else if (/call.?sign|indicativo|indicatif|rufzeichen|kallesignal/.test(k))
                                                 f.call_sign        = f.call_sign        || v;
  // Length: longitud(ES), longueur(FR), länge(DE), lengde(NO)
  else if (/length|loa\b|longitud|longueur|l.nge|lengde/.test(k))
                                                 f.length           = f.length           || v;
  // Beam: manga(ES), largeur(FR), breite(DE), bredde(NO)
  else if (/beam|breadth|manga|largeur|breite|bredde/.test(k))
                                                 f.beam             = f.beam             || v;
  else if (/nav.?status|estado.?nav|statut.?nav/.test(k))
                                                 f.nav_status       = f.nav_status       || v;
  // Port of registry: puerto de matrícula(ES), port d'attache(FR), heimathafen(DE), hjemmehavn(NO)
  else if (/home.?port|port.?of.?reg|puerto.?matr|port.?attache|heimathafen|hjemmehavn/.test(k))
                                                 f.port_of_registry = f.port_of_registry || v;
  else if (/\bclass\b|society|sociedad.?clasif|soci.t.?.?class/.test(k))
                                                 f.class_soc        = f.class_soc        || v;
  // Owner: propietario(ES), propriétaire(FR), eigentümer(DE), eier(NO), 船东(ZH)
  else if (/owner|beneficial|propietario|propri.taire|eigent.mer|reder\b|eier\b/.test(k))
                                                 f.owner            = f.owner            || v;
  // Manager: gestor(ES), gestionnaire(FR), betreiber(DE), drifter(NO)
  else if (/manager|technical.?mgr|gestor|gestionnaire|betreiber|drifter/.test(k))
                                                 f.manager          = f.manager          || v;
  else if (/\bimo\b|imo.?number|imo.?no/.test(k) && /\d{7}/.test(v))
                                                 f._imo             = f._imo             || v.match(/\d{7}/)?.[0];
  // Vessel name: ship name, vessel name, nave(ES), navire(FR)
  else if (/vessel.?name|ship.?name|ship.?s.?name|nombre.?buque|nom.?navire|nome.?nave|schiffsname/.test(k))
                                                 f.vessel_name      = f.vessel_name      || v;
  // Farm/facility name
  else if (/\bname\b|facility|site.?name|farm.?name|nombre|nom\b/.test(k) && v.length < 80)
                                                 f.vessel_name      = f.vessel_name      || v; // mergeFields will sort by type

  // ── Location ──
  else if (/^lat(?:itude)?$|^latitud$|^latitude$/.test(k))   f.latitude  = f.latitude  || v;
  else if (/^lon(?:gitude)?$|^lng$|^longitud$|^longitude$/.test(k)) f.longitude = f.longitude || v;
  // Country: país(ES), pays(FR), land(DE/NO), paese(IT), 国(ZH)
  else if (/\bcountry\b|pa.s\b|pays\b|paese\b|\bland\b/.test(k))  f.country  = f.country  || v;
  // Region: región(ES), région(FR), region(NO/DE), regione(IT)
  else if (/\bregion|r.gion|provincia|province|district|fylke|bundesland/.test(k)) f.region = f.region || v;

  // ── Fish farm / aquaculture (EN + NO + ES + FR + PT + ZH) ──
  // Farm name: nombre de granja(ES), nom de la ferme(FR), oppdrettsanlegg(NO)
  else if (/farm.?name|facility|site.?name|aquaculture.?name|nombre.?granja|nom.?ferme|anlegg.?navn|nome.?fazenda/.test(k))
                                                 f.farm_name        = f.farm_name        || v;
  // Species: especie(ES), espèce(FR), art(NO/DE), espécie(PT), 鱼种(ZH)
  else if (/\bspecies\b|especie|esp.ce|fiskeart|\bart\b|organismo|kultiviert|espécie/.test(k))
                                                 f.species          = f.species          || v;
  // Water type: tipo de agua(ES), type d'eau(FR), vanntype(NO), tipo de água(PT)
  else if (/water.?type|tipo.?agua|type.?eau|vanntype|tipo.?água/.test(k))
                                                 f.water_type       = f.water_type       || v;
  // Capacity: capacidad(ES), capacité(FR), kapasitet(NO), capacidade(PT)
  else if (/\bcapaci|kapasitet|capacidad|capacit.|capacidade|annual.?prod|produksjon/.test(k))
                                                 f.capacity         = f.capacity         || v;
  // License: licencia(ES), licence(FR), tillatelse(NO), licença(PT)
  else if (/\blicen|tillatelse|licencia|licen.e|licença|permit.?no|registr.?no/.test(k))
                                                 f.license          = f.license          || v;
  // Certification: certificación(ES), certification(FR), sertifisering(NO)
  else if (/certif|sertifisering|certificaci|asc.?cert|bap.?cert|global.?g\.?a\.?p/.test(k))
                                                 f.certification    = f.certification    || v;
  // Operator: operador(ES), opérateur(FR), betreiber(DE), operatør(NO)
  else if (/\boperator\b|operatør|operador|op.rateur|betreiber|company.?name|farm.?owner/.test(k))
                                                 f.operator         = f.operator         || v;
  // Production method: método de producción(ES), méthode(FR), driftsform(NO)
  else if (/prod.?method|driftsform|m.todo.?prod|m.thode.?prod|farming.?system/.test(k))
                                                 f.production_method = f.production_method || v;

  // ── Water quality ──
  // Temperature: temperatura(ES/PT), température(FR), temperatur(NO/DE)
  else if (/water.?temp|temperatur|temperatura|temp.rature/.test(k))
                                                 f.water_temp       = f.water_temp       || v;
  // Salinity: salinidad(ES), salinité(FR), saltholdighet(NO), salinidade(PT)
  else if (/\bsalin|saltholdighet|salinidad|salinit.|salinidade|\bppt\b|\bppm\b/.test(k))
                                                 f.salinity         = f.salinity         || v;
  // Dissolved oxygen: oxígeno disuelto(ES), oxygène dissous(FR), oksygen(NO)
  else if (/dissolv.?oxy|oksygen|ox.geno.?disuelto|oxyg.ne.?dissous|do.?level/.test(k))
                                                 f.dissolved_oxygen = f.dissolved_oxygen || v;
  else if (/\bph\b|acidity|acidez|acidité/.test(k))
                                                 f.ph               = f.ph               || v;

  // ── Fish mill / processing ──
  // Processing capacity: capacidad de procesamiento(ES), capacité de traitement(FR)
  else if (/process.?capac|throughput|daily.?cap|kapasitet.?produksjon|cap.?traitement/.test(k))
                                                 f.processing_capacity = f.processing_capacity || v;
  else if (/input.?species|raw.?material.?spec|r.?stoff.?art|mati.re.?premi.re/.test(k))
                                                 f.input_species    = f.input_species    || v;
  else if (/output.?prod|products.?produced|fishmeal.?output|fish.?oil.?output|produits.?issus/.test(k))
                                                 f.output_products  = f.output_products  || v;
  else if (/fish.?meal.?(?:%|pct|percent|content)|fishmeal.?ratio/.test(k))
                                                 f.fishmeal_pct     = f.fishmeal_pct     || v;
  else if (/fish.?oil.?(?:%|pct|percent|content)|fishoil.?ratio/.test(k))
                                                 f.fishoil_pct      = f.fishoil_pct      || v;
  // Feed type: tipo de alimento(ES), type d'aliment(FR), fôrtype(NO)
  else if (/feed.?type|f.rtype|tipo.?alimento|type.?aliment/.test(k))
                                                 f.feed_type        = f.feed_type        || v;
  else if (/\bfcr\b|feed.?conv|fôrfaktor/.test(k))
                                                 f.fcr              = f.fcr              || v;
  // Stocking density: densidad de siembra(ES), densité d'élevage(FR), tetthet(NO)
  else if (/stock.?density|tetthet|densidad.?siembra|densit..?.levage/.test(k))
                                                 f.stocking_density = f.stocking_density || v;
  // Harvest cycles: ciclos de cosecha(ES), cycles de récolte(FR), høstesykluser(NO)
  else if (/harvest.?cycle|h.stesyklus|ciclos.?cosecha|cycles.?r.colte/.test(k))
                                                 f.harvest_cycles   = f.harvest_cycles   || v;
  // Total area: área total(ES), superficie totale(FR), totalt areal(NO)
  else if (/total.?area|farm.?area|areal|.rea.?total|superficie.?tot|hectar/.test(k))
                                                 f.total_area       = f.total_area       || v;
  // Employees: empleados(ES), employés(FR), ansatte(NO), funcionários(PT)
  else if (/employee|ansatte|empleados|employ.s|funcion.rios|staff|workforce/.test(k))
                                                 f.employees        = f.employees        || v;
}

// Source trust order — higher index = more trusted when merging fields
const SOURCE_RANK = [
  'Broad-Search','Intl-Search',                                         // lowest — broad fallbacks
  'Web-Discovery','DDG-Search','Google-Search',                         // web search result pages
  'Wikipedia','AIS-Registry',                                           // encyclopedic / AIS
  'SeafoodSource','EUMOFA','MarineIngredients','GlobalSalmonIndex',      // trade & market databases
  'FIS','IFFO','BAP',                                                   // sector-specific registries
  'FAO','ASC',                                                          // UN / certification bodies
  'OpenStreetMap','OSM',                                                // verified structured geo data
  'FAO-Global-Record','ITU',                                            // authoritative vessel registries
  'Equasis','MarineTraffic','VesselFinder','FleetMon',                  // highest for vessel data
];
function sourceRank(id) {
  const i = SOURCE_RANK.findIndex(s => id && id.toLowerCase().includes(s.toLowerCase()));
  return i >= 0 ? i : 0;
}

function mergeFields(results, query) {
  // Sort results: higher-ranked sources first, then by relevance to query
  const ranked = [...results]
    .filter(r => r.ok)
    .map(r => ({ ...r, _score: sourceRank(r.id) * 10 + relevanceScore(r.text || '', query || '') }))
    .sort((a, b) => b._score - a._score);

  const m = {};
  const keys = [
    'farm_name','vessel_name','operator','owner','manager','country','flag','region',
    'latitude','longitude','total_area','employees','description',
    'species','water_type','capacity','production_method','license','certification',
    'water_temp','salinity','dissolved_oxygen','ph','fcr','stocking_density','harvest_cycles','feed_type',
    'processing_capacity','input_species','output_products','fishmeal_pct','fishoil_pct',
    'vessel_type','call_sign','gross_tonnage','dwt','year_built','mmsi','port_of_registry',
    'length','beam','nav_status','class_soc','_imo',
  ];

  for (const k of keys) {
    for (const r of ranked) {
      const raw = r.fields?.[k];
      if (!raw) continue;
      const validated = validateFieldValue(k, raw);
      if (validated) { m[k] = validated; break; }
    }
  }

  // Use _heading as name fallback if no structured name found
  if (!m.farm_name && !m.vessel_name) {
    for (const r of ranked) {
      const h = r.fields?._heading;
      if (h && h.length > 2 && h.length < 80) { m.vessel_name = h; break; }
    }
  }

  // Standardize, deduplicate, and trim all merged field values
  normalizeFields(m);
  return m;
}

/* ═══════════════════════════════════════════
   BOT LOG
═══════════════════════════════════════════ */
function log(msg, type = 'info') {
  if (!logEl) return;
  const t = new Date().toLocaleTimeString('en', {hour12:false});
  const line = document.createElement('div');
  line.className = 'll';
  const time = document.createElement('span');
  time.className = 'lt';
  time.textContent = '[' + t + ']';
  const text = document.createElement('span');
  text.className = 'l' + type;
  text.textContent = msg;  // textContent — no XSS
  line.appendChild(time);
  line.appendChild(text);
  logEl.appendChild(line);
  logEl.scrollTop = logEl.scrollHeight;
}

/* ═══════════════════════════════════════════
   RENDER VESSEL CARD (all output escaped)
═══════════════════════════════════════════ */
function renderCard(name, imo, info, sources, imgs, savedIdOrAI, aiEnhancedFlag) {
  // Handle both call signatures: renderCard(..., savedId) and renderCard(..., aiEnhanced)
  const savedId   = typeof savedIdOrAI === 'string' ? savedIdOrAI : null;
  const aiEnhanced = typeof savedIdOrAI === 'boolean' ? savedIdOrAI : (aiEnhancedFlag || false);

  const uid = 'vc' + Date.now() + Math.random().toString(36).slice(2);
  const safeName = esc(name || 'Unknown');
  const safeIMO  = esc(imo || '');

  // Resolve vessel vs farm/mill before field selection
  const isVesselCard = !!(imo || info._imo || info.mmsi || info.vessel_type ||
                          info._facilityType === 'vessel');

  // Build type-aware field grid — required fields always shown, missing ones labelled N/A
  const facilityType = info._facilityType ||
    (isVesselCard ? 'vessel' : (info.processing_capacity || info.fishmeal_pct ? 'mill' : 'farm'));

  // [label, value, required]
  const FARM_FIELDS = [
    ['Name',              info.farm_name || info.vessel_name,          true],
    ['Operator / Owner',  info.operator  || info.owner,                true],
    ['Country',           info.country   || info.flag,                 true],
    ['Region',            info.region,                                 false],
    ['Latitude',          info.latitude,                               true],
    ['Longitude',         info.longitude,                              true],
    ['Species',           info.species,                                true],
    ['Water Type',        info.water_type,                             true],
    ['Production Method', info.production_method,                      true],
    ['Annual Capacity',   info.capacity,                               true],
    ['Certification',     info.certification,                          true],
    ['License / Permit',  info.license,                                false],
    ['Stocking Density',  info.stocking_density,                       false],
    ['Harvest Cycles/yr', info.harvest_cycles,                         false],
    ['Feed Type',         info.feed_type,                              false],
    ['FCR',               info.fcr,                                    false],
    ['Water Temp',        info.water_temp,                             false],
    ['Salinity',          info.salinity,                               false],
    ['Dissolved Oxygen',  info.dissolved_oxygen,                       false],
    ['pH',                info.ph,                                     false],
    ['Total Area',        info.total_area,                             false],
    ['Employees',         info.employees,                              false],
  ];
  const VESSEL_FIELDS = [
    ['Vessel Name',       info.vessel_name || info.farm_name,          true],
    ['Operator / Owner',  info.operator || info.owner || info.manager, true],
    ['Flag State',        info.flag || info.country,                   true],
    ['Port of Registry',  info.port_of_registry,                       true],
    ['IMO Number',        info.imo || info._imo,                       true],
    ['MMSI',              info.mmsi,                                   false],
    ['Call Sign',         info.call_sign,                              true],
    ['Vessel Type',       info.vessel_type,                            true],
    ['Year Built',        info.year_built,                             true],
    ['Gross Tonnage',     info.gross_tonnage,                          true],
    ['DWT',               info.dwt,                                    false],
    ['Length (m)',        info.length,                                 false],
    ['Beam (m)',          info.beam,                                   false],
    ['Nav Status',        info.nav_status,                             false],
    ['Class / Society',   info.class_soc,                              false],
    ['Manager',           info.manager,                                false],
  ];
  const MILL_FIELDS = [
    ['Name',              info.farm_name || info.vessel_name,          true],
    ['Operator / Owner',  info.operator  || info.owner,                true],
    ['Country',           info.country   || info.flag,                 true],
    ['Region',            info.region,                                 false],
    ['Latitude',          info.latitude,                               false],
    ['Longitude',         info.longitude,                              false],
    ['Processing Capacity', info.processing_capacity,                  true],
    ['Input Species',     info.input_species,                          true],
    ['Output Products',   info.output_products,                        true],
    ['Fishmeal %',        info.fishmeal_pct,                           true],
    ['Fish Oil %',        info.fishoil_pct,                            true],
    ['Feed Type',         info.feed_type,                              false],
    ['Certification',     info.certification,                          false],
    ['Employees',         info.employees,                              false],
  ];

  const rawFields = facilityType === 'vessel' ? VESSEL_FIELDS
                  : facilityType === 'mill'   ? MILL_FIELDS
                  : FARM_FIELDS;

  // Only show fields where a value was actually found — no N/A rows
  const fieldDefs = rawFields.filter(([,v]) => v);

  // Source badges
  const okSrcs = sources.filter(s => s.ok).map(s => esc(s.id)).join(' · ');

  // Reference links — vessel links when maritime data present, farm links otherwise
  const encName = encodeURIComponent(name);
  const imoVal  = esc(imo || info._imo || '');
  const mmsiVal = esc(info.mmsi || '');

  const vesselLinks = `
    ${imoVal  ? `<a class="sl sl-mt" href="https://www.marinetraffic.com/en/ais/details/ships/imo:${imoVal}" target="_blank" rel="noopener noreferrer">MarineTraffic (IMO) ↗</a>` : ''}
    ${mmsiVal ? `<a class="sl sl-mt" href="https://www.marinetraffic.com/en/ais/details/ships/mmsi:${mmsiVal}" target="_blank" rel="noopener noreferrer">MarineTraffic (MMSI) ↗</a>` : ''}
    ${imoVal  ? `<a class="sl sl-vf" href="https://www.vesselfinder.com/vessels/details/${imoVal}" target="_blank" rel="noopener noreferrer">VesselFinder ↗</a>` : ''}
    ${mmsiVal ? `<a class="sl sl-vf" href="https://www.vesselfinder.com/vessels?name=&mmsi=${mmsiVal}" target="_blank" rel="noopener noreferrer">VesselFinder (MMSI) ↗</a>` : ''}
    ${imoVal  ? `<a class="sl sl-fm" href="https://www.fleetmon.com/vessels/?search_vessel=${imoVal}" target="_blank" rel="noopener noreferrer">FleetMon ↗</a>` : ''}
    ${imoVal  ? `<a class="sl sl-eq" href="https://www.equasis.org/EquasisWeb/restricted/ShipInfo?fs=Search&P_IMO=${imoVal}" target="_blank" rel="noopener noreferrer">Equasis ↗</a>` : ''}
    <a class="sl sl-ss" href="https://en.wikipedia.org/w/index.php?search=${encName}+vessel+ship" target="_blank" rel="noopener noreferrer">Wikipedia ↗</a>
    <a class="sl sl-ss" href="https://www.openstreetmap.org/search?query=${encName}" target="_blank" rel="noopener noreferrer">OpenStreetMap ↗</a>
    ${info.latitude && info.longitude ? `<a class="sl sl-gi" href="https://maps.google.com/?q=${encodeURIComponent(info.latitude)},${encodeURIComponent(info.longitude)}" target="_blank" rel="noopener noreferrer">Google Maps ↗</a>` : ''}`;

  const farmLinks = `
    <a class="sl sl-vf" href="https://www.fao.org/fishery/en/search?query=${encName}" target="_blank" rel="noopener noreferrer">FAO Fishery ↗</a>
    <a class="sl sl-mt" href="https://asc-aqua.org/producers/?search=${encName}" target="_blank" rel="noopener noreferrer">ASC Producers ↗</a>
    <a class="sl sl-fm" href="https://www.bapcertification.org/Producers?search=${encName}" target="_blank" rel="noopener noreferrer">BAP/GAA ↗</a>
    <a class="sl sl-eq" href="https://en.wikipedia.org/w/index.php?search=${encName}+aquaculture" target="_blank" rel="noopener noreferrer">Wikipedia ↗</a>
    <a class="sl sl-ss" href="https://www.openstreetmap.org/search?query=${encName}" target="_blank" rel="noopener noreferrer">OpenStreetMap ↗</a>
    ${info.latitude && info.longitude ? `<a class="sl sl-gi" href="https://maps.google.com/?q=${encodeURIComponent(info.latitude)},${encodeURIComponent(info.longitude)}" target="_blank" rel="noopener noreferrer">Google Maps ↗</a>` : ''}`;

  const linkHTML = isVesselCard ? vesselLinks : farmLinks;

  // Saved-record action buttons (only shown when rendered from saved list)
  const savedActions = savedId ? `
    <button class="btn-exp${info._verified ? ' btn-verified' : ''}" onclick="toggleVerified('${esc(savedId)}')" title="${info._verified ? 'Remove verification' : 'Mark as verified'}">${info._verified ? '✓ Verified' : 'Verify'}</button>
    <button class="btn-exp" onclick="editNote('${esc(savedId)}')">Add Note</button>
    <button class="btn-exp" onclick="exportRecord('${esc(savedId)}','json')">JSON</button>
    <button class="btn-exp" onclick="exportRecord('${esc(savedId)}','csv')">CSV</button>
    <button class="btn-exp" onclick="printRecord('${esc(savedId)}')">Print</button>
    <button class="btn-del" onclick="deleteSaved('${esc(savedId)}')">Delete</button>` : '';

  const noteText = info._notes ? `<div class="vc-note" onclick="editNote('${esc(savedId||'')}')">${esc(info._notes)}</div>` : '';

  // Category / facility / species badges
  const facilityLabel = info._facilityType === 'mill'   ? 'Fish Mill / Processing'
    : info._facilityType === 'vessel' ? 'Shipping / Fishing Vessel'
    : info._facilityType === 'farm'   ? 'Fish Farm / Aquaculture' : 'General';
  const catBadge  = info._category     ? `<span class="chip chip-b">${esc(info._category)}</span>` : '';
  const typeBadge = info._facilityType ? `<span class="chip chip-o">${esc(facilityLabel)}</span>` : '';
  const specBadge = info.species       ? `<span class="chip chip-g">${esc(info.species)}</span>` : '';
  const watBadge  = info.water_type    ? `<span class="chip chip-b">${esc(info.water_type)}</span>` : '';
  const prodBadge = info.production_method ? `<span class="chip chip-o">${esc(info.production_method)}</span>` : '';
  const aiBadge   = aiEnhanced ? `<span class="chip chip-ai" title="Fields extracted by Claude AI">AI-verified</span>` : '';
  const verifBadge = info._verified    ? `<span class="chip" style="background:var(--grnlt);color:var(--grn);border-color:var(--grn)">✓ Verified</span>` : '';
  const badgeRow  = [catBadge,typeBadge,specBadge,watBadge,prodBadge,verifBadge,aiBadge].filter(Boolean).join('');

  // Dedicated description section (pulled out of field grid)
  const descHTML = info.description ? `
    <div class="vc-desc">
      <div class="vc-desc-lbl">Description</div>
      ${esc(info.description)}
    </div>` : '';

  // Identity block — shown for vessel results; includes all maritime fields
  const idItems = [
    info.imo || info._imo          ? ['IMO',             info.imo || info._imo]             : null,
    info.mmsi                      ? ['MMSI',            info.mmsi]                         : null,
    info.vessel_type               ? ['Vessel Type',     info.vessel_type]                  : null,
    info.call_sign                 ? ['Call Sign',       info.call_sign]                    : null,
    info.flag || info.country      ? ['Flag / Country',  info.flag || info.country]         : null,
    info.year_built                ? ['Year Built',      info.year_built]                   : null,
    info.gross_tonnage             ? ['Gross Tonnage',   info.gross_tonnage]                : null,
    info.dwt                       ? ['DWT',             info.dwt]                          : null,
    info.length                    ? ['Length',          info.length]                       : null,
    info.beam                      ? ['Beam',            info.beam]                         : null,
    info.port_of_registry          ? ['Port of Registry',info.port_of_registry]             : null,
    info.class_soc                 ? ['Class / Society', info.class_soc]                    : null,
    info.owner || info.operator    ? ['Owner / Operator',info.owner || info.operator]       : null,
    info.manager                   ? ['Manager',         info.manager]                      : null,
    info.nav_status                ? ['Nav Status',      info.nav_status]                   : null,
  ].filter(Boolean);
  const identityHTML = idItems.length ? `
    <div class="vc-identity">
      ${idItems.map(([l,v]) => `<div class="vc-id-item"><b>${esc(l)}</b>${esc(v)}</div>`).join('')}
    </div>` : '';

  // Scrape footer
  const scrapeHTML = `
    <div class="vc-scrape">
      ${okSrcs ? `<span>Sources: ${okSrcs}</span>` : ''}
      ${info._savedAt ? `<span>Retrieved ${new Date(info._savedAt).toLocaleDateString(undefined,{month:'short',day:'numeric',year:'numeric'})}</span>` : ''}
      ${info._category ? `<span>${esc(info._category)}</span>` : ''}
    </div>`;

  // Image gallery — hidden until loaded to prevent broken-image flash
  const imgHTML = imgs.length ? imgs.map(img =>
    `<div class="iw" style="display:none" onclick="openLightbox('${encodeURIComponent(img.src)}','${encodeURIComponent(img.label)}')">
      <img src="${esc(img.src)}" alt="${esc(img.label)}" loading="lazy"
           onload="this.parentElement.style.display=''"
           onerror="this.parentElement.remove()">
      <div class="isrc">${esc(img.label)}</div>
    </div>`).join('') : '';

  const fieldHTML = fieldDefs.map(([l,v]) =>
    `<div class="vf"><div class="vfl">${esc(l)}</div><div class="vfv">${esc(v)}</div></div>`
  ).join('') || `<div class="vf" style="grid-column:1/-1;color:var(--mut3);font-style:italic;font-size:12px">No structured data available for this record.</div>`;

  const rawHTML = sources.filter(s => s.ok && s.text).map(s =>
    `<div style="margin-bottom:10px">
      <div class="label" style="margin-bottom:5px">${esc(s.id)}</div>
      <div class="text-view">${highlightIMO(s.text)}</div>
    </div>`).join('');

  return `
  <hr>
  <div class="vessel-card" id="${uid}">
    <div class="vc-name">${safeName}</div>
    ${imo ? `<div class="vc-imo">IMO ${safeIMO}</div>` : ''}
    ${badgeRow ? `<div class="vc-badges">${badgeRow}</div>` : ''}
    ${identityHTML}
    ${descHTML}
    <div class="vc-grid">${fieldHTML}</div>
    ${imgs.length ? `<div class="label" style="margin-bottom:8px">Images (${imgs.length})</div><div class="img-gallery">${imgHTML}</div>` : ''}
    <div class="ship-links">${linkHTML}</div>
    ${noteText}
    ${scrapeHTML}
    <div class="btn-row">
      ${savedId ? savedActions : `<button class="btn btn-ghost btn-sm" id="savebtn-${uid}" data-info="${esc(JSON.stringify({name, imo, ...info}))}" onclick="showSavePreview(JSON.parse(this.dataset.info),this.id)">Save</button>`}
      <button class="btn btn-ghost btn-sm" onclick="toggleEl('raw-${uid}')">Raw data</button>
      <button class="btn btn-ghost btn-sm" onclick="copyText('${uid}')">Copy text</button>
      ${imo ? `<button class="btn btn-blue btn-sm" onclick="document.getElementById('main-search').value='${safeIMO}';runBot()">Re-scan</button>` : ''}
    </div>
    <div id="raw-${uid}" style="display:none;margin-top:12px">${rawHTML}</div>
  </div>`;
}

function toggleEl(id) {
  const el = document.getElementById(id);
  if (el) el.style.display = el.style.display === 'none' ? '' : 'none';
}

function copyText(uid) {
  const el = document.getElementById(uid);
  if (!el) return;
  navigator.clipboard?.writeText(el.innerText)
    .then(() => toast('Copied!'))
    .catch(() => toast('Copy failed — try manual selection'));
}

/* ═══════════════════════════════════════════
   THE BOT
═══════════════════════════════════════════ */
async function runBot() {
  if (isRunning) return;
  const raw = document.getElementById('main-search').value.trim();
  if (!raw) { toast('Enter a name or IMO number'); return; }

  // Sanitize input
  const q = raw.replace(/[<>"']/g,'').slice(0,200);
  const searchType = document.getElementById('search-type')?.value || 'farm';
  const isMill   = searchType === 'mill';
  const isVessel = searchType === 'vessel';
  const isFarm   = searchType === 'farm';
  const isIMO    = /^\d{7}$/.test(q) && validIMO(q);
  const isMMSI   = /^\d{9}$/.test(q.replace(/\s/g,''));
  let imo  = isIMO  ? q : '';
  let mmsi = isMMSI ? q.replace(/\s/g,'') : '';
  const yearFrom  = parseInt(document.getElementById('year-from')?.value  || '2020');
  const yearTo    = parseInt(document.getElementById('year-to')?.value || String(new Date().getFullYear()));
  const catFilter = (document.getElementById('cat-filter')?.value || '').trim();

  // Write shareable URL: #search?q=Mowi+ASA&t=farm
  if (window.AppRouter) AppRouter.write('search', { q, t: searchType });

  // TTL cache check — serve cached result instantly (30 min freshness)
  if (window.AppCache) {
    const cKey    = AppCache.key(q, searchType);
    const cached  = await AppCache.get(cKey);
    if (cached) {
      const out = document.getElementById('bot-output');
      if (out) out.innerHTML = cached;
      stats.searches++;
      updateStats();
      toast('Served from cache — search again to refresh');
      return;
    }
  }

  // Lock UI
  isRunning = true;
  currentAC = new AbortController();
  const { signal } = currentAC;
  document.getElementById('search-btn').disabled = true;
  document.getElementById('cancel-btn').classList.add('show');

  stats.searches++;
  updateStats();

  const out = document.getElementById('bot-output');
  out.innerHTML = `
    <div class="card">
      <div class="run-title"><span class="spin"></span> Searching for <em>${esc(q)}</em></div>
      <div class="bot-log" id="bot-log"></div>
      <div class="prog-bar"><div class="prog-fill" id="bprog" style="width:5%"></div></div>
      <div id="bot-res"></div>
    </div>`;

  logEl = document.getElementById('bot-log');
  const setProgress = p => { const el = document.getElementById('bprog'); if(el) el.style.width = p + '%'; };

  // Check knowledge base for prior results
  const priorKnowledge = checkLearned(q);
  if (priorKnowledge) {
    const fCount = Object.keys(priorKnowledge.fields).length;
    log(`Knowledge base hit: "${q}" searched ${priorKnowledge.hitCount}× — ${fCount} fields cached, fetching updates…`, 'ok');
  }

  try {
    log(`Query: "${q}" — type: ${searchType}`, 'info');
    setProgress(20);

    /* Step 2: Scrape farm / mill details */
    const scraperURLs = [];

    // Build queries based on facility type
    let farmAPIResults = [];
    if (document.getElementById('opt-fao')?.checked) {
      const catKW = catFilter ? ` ${catFilter}` : '';
      let bingQ;

      // Build a flexible query — wrap in quotes only for long specific names, not short/broad terms
      const words = q.trim().split(/\s+/);
      const isSpecific = words.length >= 3 || q.length >= 16;
      const qPhrase = isSpecific ? `"${q}"` : q;

      if (isVessel) {
        if (isIMO) {
          bingQ = `IMO ${q} vessel ship site:marinetraffic.com OR site:vesselfinder.com OR site:fleetmon.com OR site:equasis.org`;
        } else if (isMMSI) {
          bingQ = `MMSI ${mmsi} vessel ship site:marinetraffic.com OR site:vesselfinder.com OR site:myshiptracking.com`;
        }
        // vessel-by-name bingQ is set inside the scraperURLs else block below

        // Direct registry lookups — by IMO, MMSI, or name
        if (isIMO) {
          scraperURLs.push(
            { id:'MarineTraffic',    url:`https://www.marinetraffic.com/en/ais/details/ships/imo:${q}` },
            { id:'VesselFinder',     url:`https://www.vesselfinder.com/vessels/details/${q}` },
            { id:'FleetMon',         url:`https://www.fleetmon.com/vessels/?search_vessel=${q}` },
            { id:'Equasis',          url:`https://www.equasis.org/EquasisWeb/restricted/ShipInfo?fs=Search&P_IMO=${q}` },
            { id:'FAO-Global-Record',url:`https://www.fao.org/global-record/search?imo=${q}&lang=en` },
          );
        } else if (isMMSI) {
          scraperURLs.push(
            { id:'MarineTraffic', url:`https://www.marinetraffic.com/en/ais/details/ships/mmsi:${mmsi}` },
            { id:'VesselFinder',  url:`https://www.vesselfinder.com/vessels?name=&mmsi=${mmsi}` },
            { id:'MyShipTracking',url:`https://www.myshiptracking.com/vessels?mmsi=${mmsi}` },
          );
        } else {
          bingQ = `${qPhrase}${catKW} vessel ship IMO registry flag site:marinetraffic.com OR site:vesselfinder.com OR site:fleetmon.com OR site:equasis.org`;
          scraperURLs.push(
            { id:'MarineTraffic',    url:`https://www.marinetraffic.com/en/ais/details/ships/shipid:0/mmsi:0/vessel:${encodeURIComponent(q)}` },
            { id:'VesselFinder',     url:`https://www.vesselfinder.com/?name=${encodeURIComponent(q)}` },
            { id:'FleetMon',         url:`https://www.fleetmon.com/vessels/?search_vessel=${encodeURIComponent(q)}` },
            { id:'FAO-Global-Record',url:`https://www.fao.org/global-record/search?VesselName=${encodeURIComponent(q)}&lang=en` },
          );
        }

        const lookupKey = isIMO ? `IMO ${q}` : isMMSI ? `MMSI ${mmsi}` : `"${q}"`;
        log(`Vessel search: ${lookupKey}${catFilter ? ` · type: ${catFilter}` : ''}`, 'info');
        const vesselLookup = await queryVesselAPIs(q, imo, mmsi, signal).catch(() => ({ results:[], imo, mmsi }));
        farmAPIResults = vesselLookup.results;
        imo  = vesselLookup.imo  || imo;
        mmsi = vesselLookup.mmsi || mmsi;
      } else {
        if (isMill) {
          // Mill: site-targeted Bing query hitting authoritative industry registries
          bingQ = `${qPhrase}${catKW} fishmeal "fish oil" processing plant site:iffo.com OR site:fis.com OR site:seafoodsource.com OR site:eumofa.eu OR site:undercurrentnews.com OR site:allaboutfeed.net`;
          scraperURLs.push(
            { id:'IFFO',             url:`https://www.iffo.com/search?keyword=${encodeURIComponent(q)}` },
            { id:'MarineIngredients',url:`https://www.marineingredients.org/?s=${encodeURIComponent(q)}` },
            { id:'EUMOFA',           url:`https://www.eumofa.eu/en/search?text=${encodeURIComponent(q)}` },
            { id:'FIS',              url:`https://www.fis.com/fis/search/?search=${encodeURIComponent(q)}&type=companies` },
          );
        } else {
          // Farm: site-targeted Bing query hitting ASC, BAP, SeafoodSource, etc.
          bingQ = `${qPhrase}${catKW} aquaculture "fish farm" certified site:asc-aqua.org OR site:bapcertification.org OR site:seafoodsource.com OR site:fis.com OR site:undercurrentnews.com OR site:intrafish.com OR site:globefish.org`;
          scraperURLs.push(
            { id:'BAP',              url:`https://www.bapcertification.org/searchfacilities?name=${encodeURIComponent(q)}` },
            { id:'SeafoodSource',    url:`https://www.seafoodsource.com/search?q=${encodeURIComponent(q)}` },
            { id:'GlobalSalmonIndex',url:`https://salmonindex.org/search?query=${encodeURIComponent(q)}` },
            { id:'FIS',              url:`https://www.fis.com/fis/search/?search=${encodeURIComponent(q)}&type=companies` },
          );
        }
        log(`Date filter: ${yearFrom}–${yearTo}${catFilter ? ` · category: ${catFilter}` : ''}`, 'info');
        farmAPIResults = await queryFarmAPIs(q, signal, yearTo).catch(() => []);
      }

      scraperURLs.push({ id:'Web-Discovery', url:`https://www.bing.com/search?q=${encodeURIComponent(bingQ)}` });

      // DuckDuckGo — independent index, fewer ad-blocks than Bing; richer field keywords
      const ddgQ = isVessel
        ? `${qPhrase}${catKW} vessel ship IMO MMSI flag registry gross tonnage year built`
        : isMill
          ? `${qPhrase}${catKW} fishmeal "fish oil" processing plant IFFO certified capacity input species`
          : `${qPhrase}${catKW} aquaculture "fish farm" ASC BAP certified species production capacity`;
      scraperURLs.push({ id:'DDG-Search', url:`https://html.duckduckgo.com/html/?q=${encodeURIComponent(ddgQ)}` });

      // Google — wider crawl, especially for non-English pages
      const googleQ = isVessel
        ? `${qPhrase}${catKW} vessel ship IMO flag "call sign" "gross tonnage" "year built"`
        : isMill
          ? `${qPhrase}${catKW} fishmeal "fish oil" mill capacity "input species" certifications`
          : `${qPhrase}${catKW} fish farm aquaculture species certified production capacity operator`;
      scraperURLs.push({ id:'Google-Search', url:`https://www.google.com/search?q=${encodeURIComponent(googleQ)}&num=20&hl=en&gl=us` });

      // Broad fallback — no date, no exact phrase
      const fallbackQ = isVessel
        ? `${q} vessel ship registry`
        : isMill ? `${q} fishmeal fish processing` : `${q} fish farm aquaculture`;
      scraperURLs.push({ id:'Broad-Search', url:`https://www.bing.com/search?q=${encodeURIComponent(fallbackQ)}`, _fallback:true });

      // International fallback — search without English keywords to surface foreign-language sites
      const intlQ = isVessel
        ? `${q} nave barco buque vessel schiff navire 船 مركب`
        : isMill
          ? `${q} harina pescado fischmehl farine poisson`
          : `${q} acuicultura aquaculture aquacultura aquaculture élevage poisson`;
      scraperURLs.push({ id:'Intl-Search', url:`https://www.bing.com/search?q=${encodeURIComponent(intlQ)}&setlang=en`, _fallback:true });
    }

    // Knowledge-driven optimisation: sort by known domain success rate (best sources first)
    const cachedFieldCount = priorKnowledge ? Object.keys(priorKnowledge.fields).length : 0;
    const nonFallback = scraperURLs.filter(s => !s._fallback);
    const fallbacks   = scraperURLs.filter(s =>  s._fallback);
    // Sort: highest success rate first; unknown domains (0.5) go in the middle
    nonFallback.sort((a, b) => domainSuccessRate(b.url) - domainSuccessRate(a.url));
    // Skip chronically failing domains only when cached data already has decent coverage
    const prunedNonFallback = nonFallback.filter(s => {
      const rate = domainSuccessRate(s.url);
      if (rate < 0.05 && cachedFieldCount >= 4) {
        log(`Skipping ${new URL(s.url).hostname} (${Math.round(rate*100)}% success rate, using cache)`, 'warn');
        return false;
      }
      return true;
    });
    scraperURLs.splice(0, scraperURLs.length, ...prunedNonFallback, ...fallbacks);
    log(`Scraping ${scraperURLs.length} source(s)${farmAPIResults.length ? ` + ${farmAPIResults.length} API source(s)` : ''}${cachedFieldCount ? ` · ${cachedFieldCount} fields from cache` : ''}…`, 'info');

    // Progressive — render each source as it finishes
    const scrapeResults = [...farmAPIResults];
    const resEl = document.getElementById('bot-res');

    // ── Claude: accumulate promising page texts, fire API concurrently ──────
    const claudeTexts   = [];           // { source, text } objects for top pages
    let   claudePromise = null;         // resolves to {} if no key or on error
    const claudeKey     = await getClaudeKey();

    // Pre-seed claudeTexts with API results (Wikipedia, OSM) — they're already in scrapeResults
    if (claudeKey) {
      for (const r of farmAPIResults) {
        if (r.ok && r.text && r.text.length > 100) {
          claudeTexts.push({ source: r.id, text: r.text });
        }
      }
    }

    // ── Early-exit: cancel remaining scrapers once we have enough unique fields ──
    const exitAC = new AbortController();
    const scrapeSignal = typeof AbortSignal.any === 'function'
      ? AbortSignal.any([signal, exitAC.signal]) : signal;
    const FIELD_THRESHOLD = 6;
    function checkEarlyExit() {
      if (exitAC.signal.aborted) return;
      const unique = new Set(
        scrapeResults.filter(r => r.ok).flatMap(r => Object.keys(r.fields||{}).filter(k => !k.startsWith('_')))
      ).size;
      if (unique >= FIELD_THRESHOLD) {
        log(`${unique} fields found — stopping remaining sources early`, 'ok');
        exitAC.abort();
      }
    }

    // ── Image fetch runs in parallel with scraping — don't wait for scrape to finish ──
    // Three targeted queries per facility type to hit image-rich industry sources
    // Image queries: entity name + specific visual terms so results are OF the facility/vessel
    const imgQ1 = isVessel
      ? `"${q}" ship vessel photo site:marinetraffic.com OR site:vesselfinder.com OR site:fleetmon.com OR site:shipspotting.com`
      : isMill
        ? `"${q}" fishmeal processing plant facility photo`
        : `"${q}" fish farm aquaculture facility aerial photo`;
    const imgQ2 = isVessel
      ? `"${q}" vessel at sea photo shipspotting`
      : isMill
        ? `"${q}" feed mill plant site:seafoodsource.com OR site:undercurrentnews.com OR site:intrafish.com`
        : `"${q}" salmon farm net pen cage photo site:seafoodsource.com OR site:intrafish.com OR site:undercurrentnews.com`;
    const imgQ3 = isVessel
      ? `"${q}" ship IMO photo cargo tanker fishing`
      : isMill
        ? `"${q}" fishmeal production facility aerial`
        : `"${q}" aquaculture farm facility photo Norway Chile Canada`;

    const imgPromise = document.getElementById('opt-imgs').checked
      ? Promise.all([
          // Wikipedia — direct CORS API, most reliable and entity-specific
          fetchWikipediaImages(q, signal).catch(() => []),
          // Bing — targeted query for facility/vessel photos
          fetchBingImages(imgQ1, signal).catch(() => []),
          // DDG — structured JSON API (vqd-token), industry publication query
          fetchDDGImages(imgQ2, signal).catch(() => []),
          // Bing — broader visual query for additional angles
          fetchBingImages(imgQ3, signal).catch(() => []),
        ]).then(([wiki, a, b, c]) => [...wiki, ...a, ...b, ...c])
      : Promise.resolve([]);

    const DISCOVERY_IDS = ['Web-Discovery','DDG-Search','Google-Search','Broad-Search','Intl-Search'];

    // Sequential scrape — one site at a time so each result is seen before proceeding
    for (const s of scraperURLs) {
      if (scrapeSignal.aborted) break;
      try {
        log(`→ ${s.id}…`, 'info');
        const html = await fetchViaProxy(s.url, scrapeSignal);
        if (scrapeSignal.aborted) break;
        const doc  = parseHTML(html);
        let   text = doc.body?.innerText?.slice(0, 8000) || '';

        const pageLang = detectLang(doc, text);
        if (pageLang !== 'en') {
          log(`Language: ${pageLang} — translating…`, 'info');
          try { text = await translate(text.slice(0, 3000), scrapeSignal); } catch {}
        }

        const fields = extractFields(doc, text);
        const imgs   = extractImages(doc, s.url);
        if (!imo) { const f = extractIMOs(text); if(f.length) imo = f[0]; }

        // Discovery sources: follow top result URLs one at a time
        if (DISCOVERY_IDS.includes(s.id)) {
          const urlMatches = html.match(/href="(https?:\/\/(?!www\.bing\.com|www\.google\.com|html\.duckduckgo\.com|duckduckgo\.com)[^"]{12,300})"/g) || [];
          const topURLs = [...new Set(urlMatches.map(m => m.slice(6,-1)).filter(u => isValidURL(u) && !u.includes('duckduckgo.com')))].slice(0, s._fallback ? 3 : 5);
          for (const u of topURLs) {
            if (scrapeSignal.aborted) break;
            try {
              const ph = await fetchViaProxy(u, scrapeSignal);
              if (scrapeSignal.aborted) break;
              const pd = parseHTML(ph);
              let   pt = pd.body?.innerText?.slice(0, 8000) || '';
              const subLang = detectLang(pd, pt);
              if (subLang !== 'en') { try { pt = await translate(pt.slice(0, 3000), scrapeSignal); } catch {} }
              const rel = relevanceScore(pt, q);
              if (rel === 0 && !s._fallback) { log(`Skipped (off-topic): ${new URL(u).hostname}`, 'warn'); continue; }
              if (!topicMatch(pt, searchType)) { log(`Skipped (wrong topic): ${new URL(u).hostname}`, 'warn'); continue; }
              const pf = filterFieldsByType(extractFields(pd, pt), searchType);
              const fc = Object.keys(pf).filter(k => !k.startsWith('_')).length;
              if (fc >= 1) {
                log(`✓ ${s._fallback?'Fallback':'Found'}: ${new URL(u).hostname} — ${fc} field(s)${subLang!=='en'?` [${subLang}]`:''}`, 'ok');
                scrapeResults.push({ id:new URL(u).hostname, ok:true, url:u, fields:pf, imgs:extractImages(pd,u), text:pt });
                // Feed promising pages to Claude concurrently
                if (claudeKey && relevanceScore(pt, q) > 0.2 && pt.length > 300) {
                  claudeTexts.push({ source: new URL(u).hostname, text: pt });
                  if (!claudePromise && claudeTexts.length >= 2)
                    claudePromise = claudeExtract(claudeTexts, q, searchType, signal);
                }
                checkEarlyExit();
              }
            } catch {}
          }
        }

        if (scrapeSignal.aborted) break;
        const rel = relevanceScore(text, q);
        const filteredFields = filterFieldsByType(fields, searchType);
        const fc = Object.keys(filteredFields).filter(k=>!k.startsWith('_')).length;
        if ((rel === 0 && fc < 2 && s._fallback) || !topicMatch(text, searchType)) {
          log(`Skipped (off-topic): ${s.id}`, 'warn');
        } else {
          log(`✓ ${s.id} — ${fc} fields, ${imgs.length} imgs`, 'ok');
          scrapeResults.push({ id:s.id, ok:true, url:s.url, fields:filteredFields, imgs, text });
          // Feed promising pages to Claude concurrently
          if (claudeKey && relevanceScore(text, q) > 0.2 && text.length > 300) {
            claudeTexts.push({ source: s.id, text });
            if (!claudePromise && claudeTexts.length >= 2)
              claudePromise = claudeExtract(claudeTexts, q, searchType, signal);
          }
          checkEarlyExit();
        }
      } catch(e) {
        if (e.name !== 'AbortError') {
          log(`✗ ${s.id}: ${e.message}`, 'err');
          scrapeResults.push({ id:s.id, ok:false, url:s.url, error:e.message, fields:{}, imgs:[], text:'' });
        }
      }
    }

    if (signal.aborted) throw new DOMException('Search cancelled by user', 'AbortError');
    setProgress(70);

    /* Step 3: Images — parallel fetch already started above, just collect result */
    // Only take page images from sources that found at least 1 relevant field.
    // A source with 0 fields scraped an irrelevant/blocked page — its images are generic noise.
    const relevantPageImgs = scrapeResults
      .filter(r => r.ok && Object.keys(r.fields || {}).filter(k => !k.startsWith('_')).length >= 1)
      .flatMap(r => r.imgs || []);

    const targetedImgs = await imgPromise; // Wikipedia + Bing queries — entity-specific
    if (targetedImgs.length) log(`${targetedImgs.length} targeted image(s) collected`, 'img');

    // Targeted images first (Wikipedia, Bing), then relevant page images
    let allImgs = [...targetedImgs, ...relevantPageImgs];

    // Stock-photo / generic CDN domains — these are never photos OF a specific facility
    const STOCK_DOMAINS = /gettyimages|shutterstock|istockphoto|alamy|depositphotos|dreamstime|123rf|bigstockphoto|stock\.adobe|unsplash|pexels|freepik/i;

    // Deduplicate by URL and filename; reject stock-photo domains
    const seenImgs = new Set();
    const seenFilenames = new Set();
    allImgs = allImgs.filter(img => {
      if (!img?.src) return false;
      if (STOCK_DOMAINS.test(img.src)) return false;   // reject stock photos
      if (seenImgs.has(img.src)) return false;
      const fname = img.src.split('/').pop().split('?')[0].toLowerCase();
      if (fname.length > 6 && seenFilenames.has(fname)) return false;
      seenImgs.add(img.src);
      if (fname.length > 6) seenFilenames.add(fname);
      return true;
    }).slice(0, 12);

    stats.images += allImgs.length;
    stats.ships++;
    updateStats();
    setProgress(88);

    /* Step 4: Translate */
    if (document.getElementById('opt-trans').checked) {
      log('Translating content…', 'info');
      for (const r of scrapeResults) {
        if (r.ok && r.text) {
          try { r.text = await translate(r.text, signal); } catch {}
        }
      }
    }

    /* Step 5: Render */
    let merged = mergeFields(scrapeResults, q);
    if (imo) merged._imo = merged._imo || imo;

    // Backfill any gaps from cached knowledge — live data takes priority, cache fills what's missing
    if (priorKnowledge) {
      let cacheHits = 0;
      Object.entries(priorKnowledge.fields).forEach(([k, v]) => {
        if (v && !merged[k]) { merged[k] = v; cacheHits++; }
      });
      if (cacheHits > 0) log(`Cache filled ${cacheHits} missing field${cacheHits>1?'s':''}`, 'ok');
    }

    // Broad retry: if fewer than 3 real fields found AND no confident cache covers us
    const populatedCount = Object.keys(merged).filter(k => !k.startsWith('_') && merged[k]).length;
    const cacheCovers = priorKnowledge && priorKnowledge.confidence >= 0.75;
    if (populatedCount < 3 && !signal.aborted && !cacheCovers) {
      log(`Only ${populatedCount} field(s) found — running broad retry…`, 'warn');
      const retryQ = isVessel ? `${q} vessel ship` : isMill ? `${q} fishmeal plant` : `${q} aquaculture`;
      const retryURLs = [
        `https://www.bing.com/search?q=${encodeURIComponent(retryQ)}`,
        `https://html.duckduckgo.com/html/?q=${encodeURIComponent(retryQ)}`,
      ];
      for (const rUrl of retryURLs) {
        if (signal.aborted) break;
        try {
          const rHtml = await fetchViaProxy(rUrl, signal);
          const rUrls = [...new Set(
            (rHtml.match(/href="(https?:\/\/(?!www\.bing\.com|duckduckgo\.com)[^"]{12,300})"/g) || [])
              .map(m => m.slice(6,-1)).filter(isValidURL)
          )].slice(0, 8);
          for (const ru of rUrls) {
            if (signal.aborted) break;
            try {
              const rPh = await fetchViaProxy(ru, signal);
              const rPd = parseHTML(rPh);
              let rPt = rPd.body?.innerText?.slice(0, 8000) || '';
              if (relevanceScore(rPt, q) === 0) continue;
              const rPf = filterFieldsByType(extractFields(rPd, rPt), searchType);
              if (Object.keys(rPf).filter(k => !k.startsWith('_')).length >= 1) {
                scrapeResults.push({ id: new URL(ru).hostname, ok:true, url:ru, fields:rPf, imgs:extractImages(rPd, ru), text:rPt });
                log(`✓ Retry found: ${new URL(ru).hostname}`, 'ok');
              }
            } catch {}
          }
        } catch {}
      }
      merged = mergeFields(scrapeResults, q);
      if (imo) merged._imo = merged._imo || imo;
    }

    // ── Claude: fire on any remaining pages if not yet triggered ──────────
    if (claudeKey && claudeTexts.length >= 1 && !claudePromise)
      claudePromise = claudeExtract(claudeTexts, q, searchType, signal);

    let aiEnhanced = false;
    if (claudePromise) {
      log('Applying AI field extraction…', 'info');
      setProgress(92);
      const claudeFields = await claudePromise.catch(() => ({}));
      // Guard: user may have cancelled while Claude was running
      if (!signal.aborted && Object.keys(claudeFields).filter(k => claudeFields[k]).length > 0) {
        const aiFieldCount = Object.keys(claudeFields).filter(k => claudeFields[k]).length;
        Object.entries(claudeFields).forEach(([k, v]) => { if (v && v !== '') merged[k] = v; });
        if (Object.keys(merged).filter(k => !k.startsWith('_')).length >= 4) {
          const desc = await claudePolishDescription(merged, q, searchType, signal).catch(() => null);
          if (!signal.aborted && desc) merged.description = desc;
        }
        log(`AI verified ${aiFieldCount} field(s)`, 'ok');
        aiEnhanced = true;
      }
    }

    setProgress(100);
    log(`Complete — ${allImgs.length} image(s) collected${aiEnhanced ? ' · AI-enhanced ✓' : ''}`, 'ok');

    // Build card name — then sanity-check it matches the search query.
    // If the extracted name shares no token with q, the scraper grabbed a
    // competitor's name from a shared industry page; fall back to the query.
    const rawCardName = isVessel
      ? (merged.vessel_name || q)
      : (merged.farm_name || merged.vessel_name || merged.name || q);
    const qTokens = q.toLowerCase().replace(/[^a-z0-9 ]/g, '').split(/\s+/).filter(t => t.length > 2);
    const nameMatches = qTokens.length === 0 || qTokens.some(t => rawCardName.toLowerCase().includes(t));
    const cardName = nameMatches ? rawCardName : q;
    learnFromSearch(cardName, merged, scrapeResults);
    scrapeResults.forEach(s => {
      try { if (s.url) learnFromDomain(new URL(s.url).hostname, s.ok, Object.keys(s.fields||{}).filter(k=>!k.startsWith('_')).length); } catch {}
    });

    if (resEl) {
      const div = document.createElement('div');
      div.innerHTML = renderCard(cardName, imo, merged, scrapeResults, allImgs, aiEnhanced);
      resEl.appendChild(div);

      // Cache the rendered HTML for 30 minutes
      if (window.AppCache) {
        const cKey = AppCache.key(q, searchType);
        AppCache.set(cKey, resEl.innerHTML).catch(() => {});
      }
    }

  } catch (e) {
    if (e.name === 'AbortError') {
      log('Search cancelled by user', 'warn');
      const resEl = document.getElementById('bot-res');
      if (resEl) resEl.innerHTML = '<div class="status s-warn">Search cancelled.</div>';
    } else {
      log('Fatal error: ' + e.message, 'err');
    }
  } finally {
    isRunning = false;
    currentAC = null;
    document.getElementById('search-btn').disabled = false;
    document.getElementById('cancel-btn').classList.remove('show');
    logEl = null;
  }
}

function cancelSearch() {
  if (currentAC) { currentAC.abort(); currentAC = null; }
}

/* ═══════════════════════════════════════════
   FARM API QUERIES (direct — no proxy needed)
═══════════════════════════════════════════ */
async function queryFarmAPIs(q, signal, yearTo = 2020) {
  const results = [];
  const safeQ = q.replace(/[^\w\s\-]/g, '').trim().slice(0, 80);

  // Run OSM and Wikipedia in parallel (both are direct API calls, no proxy contention)
  const [osmSettled, wikiSettled] = await Promise.allSettled([

    /* ── 1. OpenStreetMap Overpass ── real lat/lon of aquaculture facilities */
    (async () => {
      log('OSM Overpass: searching aquaculture facilities…', 'info');
      const words = safeQ.trim().split(/\s+/);
      const isShort = words.length <= 2;
      const nameClause = isShort
        ? `(node[~"^(landuse|produce|species|name)$"~"${safeQ}","i"]["landuse"~"aquaculture|fish_farm|fishery","i"];` +
          ` way[~"^(landuse|produce|species|name)$"~"${safeQ}","i"]["landuse"~"aquaculture|fish_farm|fishery","i"];` +
          ` node["name"~"${safeQ}","i"]["water"="fish_farm"];` +
          ` node["name"~"${safeQ}","i"]["man_made"~"fish_pass|aquaculture"];)`
        : `(node["name"~"${safeQ}","i"][~"^(landuse|aquaculture|craft|industrial)$"~"aquaculture","i"];` +
          ` way["name"~"${safeQ}","i"][~"^(landuse|aquaculture|craft|industrial)$"~"aquaculture","i"];` +
          ` node["name"~"${safeQ}","i"]["man_made"="fish_pass"];` +
          ` node["name"~"${safeQ}","i"]["water"="fish_farm"];)`;
      const overpassQuery = `[out:json][timeout:7];${nameClause};out center 20;`;
      const resp = await fetch('https://overpass-api.de/api/interpreter', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'data=' + encodeURIComponent(overpassQuery),
        signal: timedSignal(signal, 8000),
      });
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      const data = await resp.json();
      const els = data.elements || [];
      if (els.length) {
        const primary = els[0];
        const center  = primary.center || primary;
        const tags    = primary.tags || {};
        const fields  = {};
        if (tags.name)                           fields.farm_name  = cleanField(tags.name);
        if (center.lat != null)                  fields.latitude   = String(center.lat);
        if (center.lon != null)                  fields.longitude  = String(center.lon);
        if (tags.operator)                       fields.operator   = cleanField(tags.operator);
        if (tags.produce || tags.species)        fields.species    = cleanField(tags.produce || tags.species);
        if (tags.water)                          fields.water_type = cleanField(tags.water);
        if (tags['addr:country'] || tags.country) fields.country   = cleanField(tags['addr:country'] || tags.country);
        if (tags['addr:state'] || tags['addr:province']) fields.region = cleanField(tags['addr:state'] || tags['addr:province']);
        if (tags.website)                        fields.website    = cleanField(tags.website);
        const summary = els.map(e => {
          const c = e.center || e; const t = e.tags || {};
          return `${t.name || '?'} — Lat ${c.lat}, Lon ${c.lon}${t.operator ? ' ('+t.operator+')' : ''}`;
        }).join('\n');
        log(`OSM: ${els.length} facility/ies found`, 'ok');
        return { id:'OpenStreetMap', ok:true, url:'https://www.openstreetmap.org', fields, imgs:[], text:summary };
      } else {
        log('OSM: no aquaculture facilities matched', 'warn');
        return null;
      }
    })(),

    /* ── 2. Wikipedia ── progressively broader queries */
    (async () => {
      log('Wikipedia: searching…', 'info');
      const wikiQueries = [
        q + ' aquaculture fish farm',
        q + ' fishery fishing',
        'fish farming ' + q,
        q,
      ];
      let hit = null;
      for (const wq of wikiQueries) {
        const r = await fetch(
          `https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch=${encodeURIComponent(wq)}&format=json&origin=*&srlimit=3`,
          { signal: timedSignal(signal, 10000) }
        );
        const d = await r.json();
        hit = d.query?.search?.[0];
        if (hit) break;
      }
      if (!hit) { log('Wikipedia: no match found', 'warn'); return null; }
      const summResp = await fetch(
        `https://en.wikipedia.org/api/rest_v1/page/summary/${encodeURIComponent(hit.title)}`,
        { signal: timedSignal(signal, 10000) }
      );
      if (!summResp.ok) { log('Wikipedia: summary fetch failed', 'warn'); return null; }
      const s = await summResp.json();
      const fields = {};
      if (s.title)                      fields.farm_name   = cleanField(s.title);
      if (s.extract)                    fields.description = clipToYear(cleanField(s.extract), yearTo).slice(0, 1200);
      if (s.coordinates?.lat != null)   fields.latitude    = String(s.coordinates.lat);
      if (s.coordinates?.lon != null)   fields.longitude   = String(s.coordinates.lon);
      const imgs = (s.thumbnail?.source && isValidURL(s.thumbnail.source))
        ? [{ src: s.thumbnail.source, label: 'Wikipedia' }] : [];
      const wikiURL = s.content_urls?.desktop?.page || 'https://en.wikipedia.org';
      log(`Wikipedia: "${s.title}"`, 'ok');
      return { id:'Wikipedia', ok:true, url:wikiURL, fields, imgs, text: cleanField(s.extract || '') };
    })(),
  ]);

  if (osmSettled.status === 'fulfilled' && osmSettled.value)   results.push(osmSettled.value);
  if (wikiSettled.status === 'fulfilled' && wikiSettled.value) results.push(wikiSettled.value);

  // Run FAO and ASC in parallel — both use fetchViaProxy (proxy layer handles concurrency)
  const [faoSettled, ascSettled] = await Promise.allSettled([

    /* ── 3. FAO Fisheries & Aquaculture ── */
    (async () => {
      log('FAO: searching fisheries & aquaculture records…', 'info');
      const faoHTML = await fetchViaProxy(
        `https://www.fao.org/fishery/en/search?query=${encodeURIComponent(safeQ)}&field=aquaculture`,
        signal
      );
      const faoDoc  = parseHTML(faoHTML);
      const faoText = faoDoc.body?.innerText?.slice(0, 6000) || '';
      if (relevanceScore(faoText, q) > 0) {
        const fields = extractFields(faoDoc, faoText);
        const fc = Object.keys(fields).filter(k => !k.startsWith('_')).length;
        if (fc > 0) {
          log(`FAO: ${fc} field(s) found`, 'ok');
          return { id:'FAO', ok:true, url:`https://www.fao.org/fishery/en/search?query=${encodeURIComponent(safeQ)}`, fields, imgs:[], text:faoText };
        }
        log('FAO: page fetched but no structured fields', 'warn');
      }
      return null;
    })(),

    /* ── 4. ASC (Aquaculture Stewardship Council) ── */
    (async () => {
      log('ASC: searching certified producers…', 'info');
      const ascHTML = await fetchViaProxy(
        `https://www.asc-aqua.org/find-a-farm/?q=${encodeURIComponent(safeQ)}`,
        signal
      );
      const ascDoc  = parseHTML(ascHTML);
      const ascText = ascDoc.body?.innerText?.slice(0, 4000) || '';
      if (relevanceScore(ascText, q) > 0) {
        const fields = extractFields(ascDoc, ascText);
        if (/certified|asc.?approved/i.test(ascText) && !fields.certification) fields.certification = 'ASC Certified';
        const fc = Object.keys(fields).filter(k => !k.startsWith('_')).length;
        if (fc > 0) {
          log(`ASC: ${fc} field(s) found`, 'ok');
          return { id:'ASC', ok:true, url:`https://www.asc-aqua.org/find-a-farm/?q=${encodeURIComponent(safeQ)}`, fields, imgs:[], text:ascText };
        }
      }
      return null;
    })(),
  ]);

  if (faoSettled.status === 'fulfilled' && faoSettled.value) results.push(faoSettled.value);
  if (ascSettled.status === 'fulfilled' && ascSettled.value) results.push(ascSettled.value);

  return results;
}

/* ═══════════════════════════════════════════
   VESSEL API QUERIES
═══════════════════════════════════════════ */
async function queryVesselAPIs(q, imo, mmsi, signal) {
  const results = [];
  const safeQ   = q.replace(/[^\w\s\-]/g, '').trim().slice(0, 80);

  // Phase 1: Wikipedia + OSM in parallel (both direct API calls)
  const [wikiV, osmV] = await Promise.allSettled([

    /* ── 1. Wikipedia — vessel article ── */
    (async () => {
      log('Wikipedia: searching for vessel…', 'info');
      const searchResp = await fetch(
        `https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch=${encodeURIComponent(safeQ + ' ship vessel')}&srlimit=3&format=json&origin=*`,
        { signal: timedSignal(signal, 10000) }
      );
      if (!searchResp.ok) return [];
      const searchData = await searchResp.json();
      const pages = searchData?.query?.search || [];
      const out = [];
      for (const p of pages.slice(0, 2)) {
        const summResp = await fetch(
          `https://en.wikipedia.org/api/rest_v1/page/summary/${encodeURIComponent(p.title)}`,
          { signal: timedSignal(signal, 10000) }
        );
        if (!summResp.ok) continue;
        const summ = await summResp.json();
        if (summ.extract) {
          const f = {};
          f.description = summ.extract.slice(0, 1200);
          if (summ.title)       f.vessel_name = summ.title;
          if (summ.coordinates) { f.latitude = String(summ.coordinates.lat); f.longitude = String(summ.coordinates.lon); }
          const imoM = summ.extract.match(/\bIMO[\s:]*(\d{7})\b/i);
          if (imoM) { f._imo = imoM[1]; if (!imo) imo = imoM[1]; }
          const flagM = summ.extract.match(/flag(?:ged)? (?:of |state )?([A-Z][a-z]+(?: [A-Z][a-z]+)?)/);
          if (flagM) f.flag = flagM[1];
          log(`✓ Wikipedia: "${p.title}"`, 'ok');
          out.push({ id:'Wikipedia', ok:true, url:`https://en.wikipedia.org/wiki/${encodeURIComponent(p.title)}`, fields:f, imgs:[], text:summ.extract });
        }
      }
      return out;
    })(),

    /* ── 2. OSM Overpass — named vessels / ports / fishing harbours ── */
    (async () => {
      log('OSM Overpass: searching vessel / harbour records…', 'info');
      const osmQ = safeQ.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/"/g, '\\"');
      const oq =
        `[out:json][timeout:7];` +
        `(node["name"~"${osmQ}","i"]["seamark:type"];` +
        ` node["name"~"${osmQ}","i"]["harbour"]; ` +
        ` node["name"~"${osmQ}","i"]["landuse"="harbour"];` +
        `);out center;`;
      const resp = await fetch('https://overpass-api.de/api/interpreter', {
        method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'},
        body:'data=' + encodeURIComponent(oq), signal: timedSignal(signal, 8000),
      });
      if (!resp.ok) return null;
      const data = await resp.json();
      const el   = data?.elements?.[0];
      if (!el) return null;
      const f = {};
      const lat = el.lat ?? el.center?.lat;
      const lon = el.lon ?? el.center?.lon;
      if (lat) f.latitude  = String(lat);
      if (lon) f.longitude = String(lon);
      if (el.tags?.name)             f.vessel_name = el.tags.name;
      if (el.tags?.operator)         f.operator    = el.tags.operator;
      if (el.tags?.country)          f.country     = el.tags.country;
      if (el.tags?.['seamark:type']) f.vessel_type = el.tags['seamark:type'];
      log(`✓ OSM: "${el.tags?.name || 'record found'}" — lat ${lat}, lon ${lon}`, 'ok');
      return { id:'OSM', ok:true, url:'https://www.openstreetmap.org', fields:f, imgs:[], text:'' };
    })(),
  ]);

  if (wikiV.status === 'fulfilled') results.push(...(wikiV.value || []));
  if (osmV.status === 'fulfilled' && osmV.value) results.push(osmV.value);

  // Phase 2: AIS (by IMO) + AIS (by MMSI) in parallel
  const midMap = {
    '211':'Germany','219':'Denmark','224':'Spain','226':'France','229':'Malta',
    '232':'United Kingdom','244':'Netherlands','248':'Italy','253':'Luxembourg',
    '257':'Norway','265':'Sweden','269':'Switzerland','273':'Russia',
    '303':'USA (Alaska)','338':'United States','366':'United States',
    '412':'China','431':'Japan','440':'South Korea','477':'Hong Kong',
    '503':'Australia','512':'New Zealand','525':'Indonesia','533':'Malaysia',
    '566':'Singapore','574':'Vietnam','636':'Liberia','710':'Brazil',
  };

  const [aisIMO, aisMMSI] = await Promise.allSettled([

    /* ── 3. AIS lookup by IMO ── */
    imo ? (async () => {
      log(`AIS lookup for IMO ${imo}…`, 'info');
      const r = await fetch(
        `https://api.vessel-tracking.net/AIS/Vessel/GetVesselDetailsByIMO?IMONumber=${imo}`,
        { signal: timedSignal(signal, 8000) }
      );
      if (!r.ok) return null;
      const d = await r.json();
      if (!d?.VesselName) return null;
      const f = {
        vessel_name:   d.VesselName,
        vessel_type:   d.VesselType   || '',
        flag:          d.Flag         || '',
        mmsi:          d.MMSI         || '',
        gross_tonnage: d.GrossTonnage || '',
        year_built:    d.YearBuilt    || '',
        _imo:          imo,
      };
      if (d.MMSI != null && d.MMSI !== '' && !mmsi) mmsi = String(d.MMSI);
      log(`✓ AIS (IMO): ${d.VesselName}`, 'ok');
      return { id:'AIS-Registry', ok:true, url:'', fields:f, imgs:[], text:d.VesselName };
    })() : Promise.resolve(null),

    /* ── 4. AIS lookup by MMSI ── */
    mmsi ? (async () => {
      log(`MMSI lookup for ${mmsi}…`, 'info');
      const flagFromMID = midMap[mmsi.slice(0, 3)] || '';
      const r = await fetch(
        `https://api.vessel-tracking.net/AIS/Vessel/GetVesselDetailsByMMSI?MMSI=${mmsi}`,
        { signal: timedSignal(signal, 8000) }
      );
      if (r.ok) {
        const d = await r.json();
        if (d?.VesselName) {
          const f = {
            vessel_name:   d.VesselName,
            vessel_type:   d.VesselType   || '',
            flag:          d.Flag || flagFromMID || '',
            mmsi,
            gross_tonnage: d.GrossTonnage || '',
            year_built:    d.YearBuilt    || '',
            _imo:          d.IMO          || '',
          };
          if (d.IMO != null && d.IMO !== '' && !imo) imo = String(d.IMO);
          log(`✓ AIS (MMSI): ${d.VesselName}`, 'ok');
          return { id:'AIS-Registry', ok:true, url:'', fields:f, imgs:[], text:d.VesselName };
        }
      }
      if (flagFromMID) {
        log(`MMSI ${mmsi} → flag country: ${flagFromMID} (from MID ${mmsi.slice(0,3)})`, 'ok');
        return { id:'MMSI-Decode', ok:true, url:'', fields:{ mmsi, flag: flagFromMID }, imgs:[], text:'' };
      }
      return null;
    })() : Promise.resolve(null),
  ]);

  if (aisIMO.status === 'fulfilled' && aisIMO.value)   results.push(aisIMO.value);
  if (aisMMSI.status === 'fulfilled' && aisMMSI.value) results.push(aisMMSI.value);

  return { results, imo, mmsi };
}

/* ═══════════════════════════════════════════
   DIRECT URL SCRAPE
═══════════════════════════════════════════ */
async function scrapeURL() {
  if (isRunning) return;

  const urls = [1,2,3]
    .map(i => document.getElementById('url-input-' + i)?.value.trim())
    .filter(Boolean);

  if (!urls.length) { toast('Paste at least one URL to scrape'); return; }
  const bad = urls.find(u => !isValidURL(u));
  if (bad) { toast('Invalid or unsafe URL (must be https): ' + bad.slice(0,50)); return; }

  isRunning = true;
  currentAC = new AbortController();
  const { signal } = currentAC;
  document.getElementById('cancel-btn').classList.add('show');
  stats.searches++;
  updateStats();

  const out = document.getElementById('bot-output');
  const urlLabel = urls.length > 1 ? `${urls.length} URLs` : esc(urls[0]);
  out.innerHTML = `
    <div class="card">
      <div class="run-title"><span class="spin"></span> Scraping ${urlLabel}</div>
      <div class="bot-log" id="bot-log"></div>
      <div class="prog-bar"><div class="prog-fill" id="bprog" style="width:5%"></div></div>
      <div id="bot-res"></div>
    </div>`;

  logEl = document.getElementById('bot-log');
  const setProgress = p => { const el = document.getElementById('bprog'); if(el) el.style.width = p + '%'; };

  try {
    // Scrape all URLs in parallel
    log(`Scraping ${urls.length} URL${urls.length>1?'s':''} in parallel…`, 'info');
    const settled = await Promise.allSettled(urls.map(async (urlRaw, i) => {
      const tag = urls.length > 1 ? `[${i+1}] ` : '';
      log(`${tag}Fetching ${new URL(urlRaw).hostname}…`, 'info');
      const html   = await fetchViaProxy(urlRaw, signal);
      const doc    = parseHTML(html);
      const text   = doc.body?.innerText?.slice(0, 5000) || '';
      const fields = extractFields(doc, text);
      const imgs   = extractImages(doc, urlRaw);
      const imos   = extractIMOs(text);
      if (imos.length && !fields._imo) fields._imo = imos[0];
      const fCount = Object.keys(fields).filter(k => !k.startsWith('_')).length;
      log(`${tag}✓ ${new URL(urlRaw).hostname} — ${fCount} fields, ${imgs.length} images`, 'ok');
      learnFromDomain(new URL(urlRaw).hostname, true, fCount);
      return { urlRaw, hostname: new URL(urlRaw).hostname, fields, imgs, text };
    }));

    setProgress(70);

    const successes = settled.filter(r => r.status === 'fulfilled').map(r => r.value);
    settled.forEach((r, i) => {
      if (r.status === 'rejected') {
        const host = urls[i] ? new URL(urls[i]).hostname : 'URL';
        log(`✗ ${host}: ${r.reason?.message || 'Failed'}`, 'err');
      }
    });

    if (!successes.length) throw new Error('All URLs failed to load');

    // Merge — first URL has highest priority, later fill gaps
    const merged = {};
    successes.forEach(({ fields }) => {
      Object.entries(fields).forEach(([k, v]) => { if (v && !merged[k]) merged[k] = v; });
    });
    // Run the same validation + normalization as the main search pipeline
    for (const [k, v] of Object.entries(merged)) {
      if (typeof v === 'string') {
        const clean = validateFieldValue(k, v);
        if (clean) merged[k] = clean; else delete merged[k];
      }
    }
    normalizeFields(merged);

    // Images from all sources combined — supplement with targeted searches
    let allImgs = successes.flatMap(s => s.imgs);
    const nameQ = merged.vessel_name || merged.farm_name || '';
    if (nameQ && document.getElementById('opt-imgs').checked) {
      const [bingImgs, ddgImgs] = await Promise.allSettled([
        fetchBingImages(nameQ, signal),
        fetchDDGImages(nameQ, signal),
      ]);
      if (bingImgs.status === 'fulfilled') allImgs = [...allImgs, ...bingImgs.value];
      if (ddgImgs.status  === 'fulfilled') allImgs = [...allImgs, ...ddgImgs.value];
    }

    // Translate if enabled (translate the primary source text)
    let primaryText = successes[0]?.text || '';
    if (document.getElementById('opt-trans').checked && primaryText) {
      log('Translating…', 'info');
      try { primaryText = await translate(primaryText, signal); } catch {}
    }

    setProgress(100);
    stats.ships++;
    stats.images += allImgs.length;
    updateStats();

    // Teach the knowledge base
    const cardName = merged.vessel_name || merged.farm_name || successes[0].hostname;
    learnFromSearch(cardName, merged, successes.map(s => ({ id: s.hostname, ok: true })));

    const resEl = document.getElementById('bot-res');
    if (resEl) {
      if (successes.length > 1) {
        // Show merged summary banner + one card per source
        const banner = document.createElement('div');
        banner.className = 'status s-info';
        banner.style.marginBottom = '10px';
        const fTotal = Object.keys(merged).filter(k => !k.startsWith('_')).length;
        banner.textContent = `Merged ${successes.length} sources — ${fTotal} unique fields extracted`;
        resEl.appendChild(banner);

        successes.forEach(({ urlRaw, hostname, fields, imgs, text }) => {
          const label = document.createElement('div');
          label.style.cssText = 'font-size:11px;color:var(--mut2);margin:12px 0 4px;font-weight:600';
          label.textContent = `Source: ${hostname}`;
          resEl.appendChild(label);
          const div = document.createElement('div');
          div.innerHTML = renderCard(
            fields.vessel_name || fields.farm_name || hostname,
            fields._imo || merged._imo || '',
            fields,
            [{ id: hostname, ok: true, url: urlRaw, text }],
            imgs
          );
          resEl.appendChild(div);
        });
      } else {
        const { urlRaw, hostname, fields } = successes[0];
        const div = document.createElement('div');
        div.innerHTML = renderCard(
          merged.vessel_name || merged.farm_name || hostname,
          merged._imo || '',
          merged,
          [{ id: hostname, ok: true, url: urlRaw, text: primaryText }],
          allImgs
        );
        resEl.appendChild(div);
      }
    }
  } catch(e) {
    if (e.name === 'AbortError') {
      log('Cancelled', 'warn');
    } else {
      log('Error: ' + e.message, 'err');
      const resEl = document.getElementById('bot-res');
      if (resEl) resEl.innerHTML = `<div class="status s-err">Failed: ${esc(e.message)}</div>`;
    }
  } finally {
    isRunning = false;
    currentAC = null;
    logEl = null;
    document.getElementById('cancel-btn').classList.remove('show');
  }
}

/* ═══════════════════════════════════════════
   LIGHTBOX (safe URL handling)
═══════════════════════════════════════════ */
function openLightbox(encodedSrc, encodedLabel) {
  const src = decodeURIComponent(encodedSrc);
  if (!isValidURL(src)) return;
  document.getElementById('lb-img').src = src;
  document.getElementById('lb-caption').textContent = decodeURIComponent(encodedLabel || '');
  document.getElementById('lightbox').classList.add('show');
}
function closeLightbox() { document.getElementById('lightbox').classList.remove('show'); }
document.addEventListener('keydown', e => { if (e.key === 'Escape') { closeLightbox(); closeSavePreview(); } });

/* ═══════════════════════════════════════════
   SAVE PREVIEW MODAL
═══════════════════════════════════════════ */
function showSavePreview(info, btnId) {
  if (typeof info === 'string') { try { info = JSON.parse(info); } catch { return; } }
  const key = info.imo || info._imo || info.farm_name || info.vessel_name || info.name || '';
  if (key && saved.find(s => (s.imo||s._imo||s.farm_name||s.vessel_name||s.name||'') === key)) {
    toast('Already saved'); return;
  }
  const modal = document.getElementById('sp-modal');
  modal.dataset.btnId = btnId || '';

  // Pull current dropdown defaults for category/type if not in info
  const defCat  = info._category     || document.getElementById('cat-filter')?.value  || '';
  const defType = info._facilityType || document.getElementById('search-type')?.value || 'farm';

  // Sections shown based on facility type: 'all' = always, array = only those types
  const sections = [
    { label: 'Identity', showFor: 'all', fields: [
      { key:'farm_name',        label:'Name',                 val: info.farm_name || info.vessel_name || info.name || '' },
      { key:'operator',         label:'Operator / Owner',     val: info.operator || info.owner || '' },
      { key:'country',          label:'Country / Flag',       val: info.country || info.flag || '' },
      { key:'region',           label:'Region',               val: info.region || '' },
      { key:'latitude',         label:'Latitude',             val: info.latitude || '' },
      { key:'longitude',        label:'Longitude',            val: info.longitude || '' },
      { key:'employees',        label:'Employees',            val: info.employees || '' },
    ]},
    { label: 'Classification', showFor: 'all', fields: [
      { key:'_facilityType', label:'Facility Type', val: defType, type:'select', opts:[
        ['farm','Fish Farm / Aquaculture'],['mill','Fish Mill / Processing'],
        ['vessel','Shipping / Fishing Vessel'],['general','General / Auto']] },
      { key:'_category', label:'Category / Species', val: defCat, type:'select', opts:[
        ['','— Select —'],
        ['salmon','Salmon'],['trout','Trout'],['shrimp','Shrimp / Prawn'],
        ['tilapia','Tilapia'],['catfish','Catfish'],['tuna','Tuna'],['cod','Cod'],
        ['sea bass sea bream','Sea Bass / Sea Bream'],['carp','Carp'],
        ['oyster shellfish','Oyster / Shellfish'],['fishmeal processing','Fish Mill / Processing'],
        ['trawler','Trawler'],['longliner','Longliner'],['purse seiner','Purse Seiner'],
        ['gillnetter','Gillnetter'],['factory vessel','Factory / Processing Vessel'],
        ['reefer carrier','Reefer / Fish Carrier'],['crab lobster vessel','Crab / Lobster Vessel'],
        ['squid jigger','Squid Jigger'],['pole liner','Pole & Line Vessel'],
        ['aquaculture support vessel','Aquaculture Support Vessel']] },
    ]},
    { label: 'Farm Details', showFor: ['farm','general'], fields: [
      { key:'species',          label:'Species',              val: info.species || '' },
      { key:'water_type',       label:'Water Type',           val: info.water_type || '' },
      { key:'production_method',label:'Production Method',    val: info.production_method || '' },
      { key:'capacity',         label:'Annual Capacity',      val: info.capacity || '' },
      { key:'total_area',       label:'Total Area',           val: info.total_area || '' },
      { key:'stocking_density', label:'Stocking Density',     val: info.stocking_density || '' },
      { key:'harvest_cycles',   label:'Harvest Cycles / yr',  val: info.harvest_cycles || '' },
      { key:'feed_type',        label:'Feed Type',            val: info.feed_type || '' },
      { key:'fcr',              label:'FCR',                  val: info.fcr || '' },
    ]},
    { label: 'Water Quality', showFor: ['farm','general'], fields: [
      { key:'water_temp',       label:'Water Temperature',    val: info.water_temp || '' },
      { key:'salinity',         label:'Salinity',             val: info.salinity || '' },
      { key:'dissolved_oxygen', label:'Dissolved Oxygen',     val: info.dissolved_oxygen || '' },
      { key:'ph',               label:'pH',                   val: info.ph || '' },
    ]},
    { label: 'Compliance', showFor: ['farm','mill','general'], fields: [
      { key:'license',          label:'License / Permit No.', val: info.license || '' },
      { key:'certification',    label:'Certification',        val: info.certification || '' },
    ]},
    { label: 'Fish Mill / Processing', showFor: ['mill','general'], fields: [
      { key:'processing_capacity',label:'Processing Capacity',val: info.processing_capacity || '' },
      { key:'input_species',    label:'Input Species',        val: info.input_species || '' },
      { key:'output_products',  label:'Output Products',      val: info.output_products || '' },
      { key:'fishmeal_pct',     label:'Fishmeal %',           val: info.fishmeal_pct || '' },
      { key:'fishoil_pct',      label:'Fish Oil %',           val: info.fishoil_pct || '' },
    ]},
    { label: 'Vessel Info', showFor: ['vessel','general'], fields: [
      { key:'imo',              label:'IMO Number',           val: info.imo || info._imo || '' },
      { key:'vessel_type',      label:'Vessel Type',          val: info.vessel_type || '' },
      { key:'call_sign',        label:'Call Sign',            val: info.call_sign || '' },
      { key:'mmsi',             label:'MMSI',                 val: info.mmsi || '' },
      { key:'flag',             label:'Flag State',           val: info.flag || '' },
      { key:'year_built',       label:'Year Built',           val: info.year_built || '' },
      { key:'gross_tonnage',    label:'Gross Tonnage',        val: info.gross_tonnage || '' },
      { key:'dwt',              label:'DWT',                  val: info.dwt || '' },
      { key:'length',           label:'Length (m)',           val: info.length || '' },
      { key:'beam',             label:'Beam (m)',             val: info.beam || '' },
      { key:'port_of_registry', label:'Port of Registry',     val: info.port_of_registry || '' },
      { key:'class_soc',        label:'Class / Society',      val: info.class_soc || '' },
      { key:'owner',            label:'Owner',                val: info.owner || '' },
      { key:'manager',          label:'Manager',              val: info.manager || '' },
      { key:'nav_status',       label:'Nav Status',           val: info.nav_status || '' },
    ]},
    { label: 'Notes & Description', showFor: 'all', full: true, fields: [
      { key:'description', label:'Description', val: info.description || '', type:'textarea', rows: 8 },
      { key:'_notes',      label:'Personal Notes (private)', val: info._notes || '', type:'textarea' },
    ]},
  ];

  const rowHTML = sections.map(sec => {
    // Show section if it matches the current facility type
    const visibleFor = sec.showFor === 'all' || sec.showFor.includes(defType);
    if (!visibleFor) return '';
    return `
      <div class="sp-section">${esc(sec.label)}</div>
      ${sec.fields.map(f => {
        const cls = 'sp-field' + (sec.full ? ' sp-full' : '');
        if (f.type === 'select') return `
          <div class="${cls}">
            <label class="sp-label">${esc(f.label)}</label>
            <select class="sp-input" data-key="${esc(f.key)}">
              ${f.opts.map(([v,t]) => `<option value="${esc(v)}"${f.val===v?' selected':''}>${esc(t)}</option>`).join('')}
            </select>
          </div>`;
        if (f.type === 'textarea') return `
          <div class="${cls} sp-full">
            <label class="sp-label">${esc(f.label)}</label>
            <textarea class="sp-input" data-key="${esc(f.key)}" rows="${f.rows || 3}">${esc(f.val)}</textarea>
          </div>`;
        return `
          <div class="${cls}">
            <label class="sp-label">${esc(f.label)}</label>
            <input type="text" class="sp-input" data-key="${esc(f.key)}" value="${esc(f.val)}" placeholder="—">
          </div>`;
      }).join('')}`;
  }).join('');

  document.getElementById('sp-content').innerHTML = `<div class="sp-grid">${rowHTML}</div>`;
  modal.classList.add('show');

  // ── Auto-enrich: always runs when we have a name ──────────────────────────
  const name = info.farm_name || info.vessel_name || info.name || '';
  const facilityType = defType;

  if (name) {
    if (enrichAC) enrichAC.abort();
    const ac = new AbortController();
    enrichAC = ac;
    const signal = ac.signal;

    // Banner with live phase label
    const enrichBanner = document.createElement('div');
    enrichBanner.id = 'sp-enrich-banner';
    enrichBanner.style.cssText = 'padding:8px 16px;font-size:11.5px;color:#555;background:#f5f5f0;border-bottom:1px solid #e2e2e2;display:flex;align-items:center;gap:8px;flex-wrap:wrap;';

    // Found-fields accumulator shown in the banner
    const foundFields = new Set();
    const FIELD_LABELS = {
      farm_name:'Name', vessel_name:'Name', operator:'Operator', country:'Country',
      region:'Region', latitude:'Lat', longitude:'Lng', species:'Species',
      water_type:'Water', capacity:'Capacity', production_method:'Method',
      certification:'Certification', license:'License', employees:'Employees',
      vessel_type:'Type', flag:'Flag', gross_tonnage:'Tonnage', year_built:'Built',
      port_of_registry:'Port', owner:'Owner', manager:'Manager', call_sign:'Call Sign',
      processing_capacity:'Capacity', input_species:'Input Species', description:'Description',
    };
    let _currentPhase = 'Looking up databases…';
    const setPhase = msg => {
      _currentPhase = msg;
      const b = document.getElementById('sp-enrich-banner');
      if (!b) return;
      const found = foundFields.size ? `<span style="color:#2a7a2a;font-weight:600"> · Found: ${[...foundFields].join(', ')}</span>` : '';
      b.innerHTML = `<span style="animation:spin 1s linear infinite;display:inline-block">⟳</span> <span style="font-weight:600">${esc(msg)}</span>${found}`;
    };
    setPhase('Looking up databases…');
    document.querySelector('.sp-inner').insertBefore(enrichBanner, document.getElementById('sp-content'));

    // Patch a single field into the modal (only if currently empty)
    const patchField = (k, v) => {
      if (!v || !modal.classList.contains('show')) return;
      const el = modal.querySelector(`.sp-input[data-key="${CSS.escape(k)}"]`);
      if (el && !el.value.trim()) {
        el.value = v;
        el.style.background = '#fffbe6';
        if (FIELD_LABELS[k]) { foundFields.add(FIELD_LABELS[k]); setPhase(_currentPhase); }
      }
    };
    // Patch all fields from a merged result object
    const patchAll = merged => {
      for (const [k, v] of Object.entries(merged)) { if (v) patchField(k, v); }
    };
    // Collect current modal values (for Claude)
    const currentData = () => {
      const d = {};
      modal.querySelectorAll('.sp-input').forEach(el => { if (el.value.trim()) d[el.dataset.key] = el.value.trim(); });
      return d;
    };

    (async () => {
      const enrichTexts = []; // text sources accumulated for Claude

      try {
        // ── Phase 1: Structured API sources ─────────────────────────────────
        setPhase('Querying databases…');
        let apiResults = [];
        if (facilityType === 'vessel') {
          const vl = await queryVesselAPIs(name, '', '', signal).catch(() => ({ results: [] }));
          apiResults = vl.results || [];
        } else {
          apiResults = await queryFarmAPIs(name, signal, new Date().getFullYear()).catch(() => []);
        }
        if (!modal.classList.contains('show')) return;
        patchAll(mergeFields(apiResults, name));
        apiResults.filter(r => r.ok && r.text && r.text.length > 80)
                  .forEach(r => enrichTexts.push({ source: r.id, text: r.text }));

        // ── Phase 2: Targeted web search + scrape ────────────────────────────
        setPhase('Searching the web for details…');
        const searchQ = facilityType === 'vessel'
          ? `"${name}" vessel ship IMO flag operator gross tonnage`
          : facilityType === 'mill'
            ? `"${name}" fishmeal processing plant capacity species country`
            : `"${name}" fish farm aquaculture species capacity production country`;

        const searchEngines = [
          `https://html.duckduckgo.com/html/?q=${encodeURIComponent(searchQ)}`,
          `https://www.bing.com/search?q=${encodeURIComponent(searchQ)}`,
        ];

        const scrapedURLs = new Set();
        for (const engine of searchEngines) {
          if (signal.aborted || !modal.classList.contains('show')) break;
          try {
            const html = await fetchViaProxy(engine, signal);
            const found = (html.match(/href="(https?:\/\/(?!(?:duckduckgo|bing|microsoft)\.com)[^"]{12,300})"/g) || [])
              .map(m => m.slice(6, -1)).filter(isValidURL);
            for (const u of found) { if (scrapedURLs.size < 8) scrapedURLs.add(u); }
          } catch(e) { if (e.name === 'AbortError') throw e; }
        }

        let webHits = 0;
        for (const url of scrapedURLs) {
          if (signal.aborted || !modal.classList.contains('show')) break;
          try {
            const html  = await fetchViaProxy(url, signal);
            const doc   = parseHTML(html);
            let   text  = doc.body?.innerText?.slice(0, 8000) || '';
            if (relevanceScore(text, name) === 0) continue;
            const fields = filterFieldsByType(extractFields(doc, text), facilityType);
            const fc = Object.keys(fields).filter(k => !k.startsWith('_')).length;
            if (fc >= 1) {
              patchAll(mergeFields([{ id: new URL(url).hostname, ok: true, fields, text }], name));
              enrichTexts.push({ source: new URL(url).hostname, text });
              webHits++;
            }
          } catch(e) { if (e.name === 'AbortError') throw e; }
        }

        if (!modal.classList.contains('show')) return;

        // ── Phase 3: Claude extraction + description ─────────────────────────
        const claudeKey = await getClaudeKey();
        if (claudeKey && enrichTexts.length >= 1) {
          setPhase('AI extracting fields…');
          const claudeFields = await claudeExtract(enrichTexts, name, facilityType, signal).catch(() => ({}));
          if (!modal.classList.contains('show')) return;
          for (const [k, v] of Object.entries(claudeFields)) { if (v) patchField(k, v); }

          // Polish / generate description with everything we now know
          const allData = currentData();
          const filledCount = Object.keys(allData).filter(k => !k.startsWith('_')).length;
          if (filledCount >= 3) {
            setPhase('Writing description…');
            const desc = await claudePolishDescription(allData, name, facilityType, signal).catch(() => null);
            if (desc && modal.classList.contains('show')) patchField('description', desc);
          }
        }
      } catch(e) {
        if (e.name !== 'AbortError') console.warn('[Enrich]', e);
      }

      enrichAC = null;
      const banner = document.getElementById('sp-enrich-banner');
      if (banner) {
        banner.innerHTML = '✓ Done';
        banner.style.color = '#2a7a2a';
        setTimeout(() => banner?.remove(), 1800);
      }
    })();
  }
}

function confirmSavePreview() {
  const modal = document.getElementById('sp-modal');
  const btnId = modal.dataset.btnId;
  const info  = {};
  modal.querySelectorAll('.sp-input').forEach(el => {
    const v = el.value.trim();
    if (v) info[el.dataset.key] = v;
  });
  closeSavePreview();
  doSave(info, btnId);
}

function closeSavePreview() {
  const m = document.getElementById('sp-modal');
  if (m) m.classList.remove('show');
  if (enrichAC) { enrichAC.abort(); enrichAC = null; }
}

/* ═══════════════════════════════════════════
   FILE READER
═══════════════════════════════════════════ */
function dzOver(e)  { e.preventDefault(); document.getElementById('dz').classList.add('drag'); }
function dzLeave()  { document.getElementById('dz').classList.remove('drag'); }
function dzDrop(e)  { e.preventDefault(); dzLeave(); if(e.dataTransfer.files[0]) { pendingFile=e.dataTransfer.files[0]; fileReady(pendingFile); } }
function handleFile(e) { if(e.target.files[0]) { pendingFile=e.target.files[0]; fileReady(pendingFile); } }
function fileReady(file) {
  const dz = document.getElementById('dz');
  if (dz) dz.innerHTML = `<span class="dz-icon">✅</span><div class="dz-title">${esc(file.name)}</div><div class="dz-sub">${(file.size/1024).toFixed(0)} KB · Click to change file</div>`;
  const btn = document.getElementById('file-extract-btn');
  if (btn) btn.disabled = false;
}
function extractFileData() {
  if (!pendingFile) { toast('Select a file first'); return; }
  handleFileRaw(pendingFile);
}
function clearFileSelection() {
  pendingFile = null;
  const dz = document.getElementById('dz');
  if (dz) dz.innerHTML = '<span class="dz-icon">📄</span><div class="dz-title">Drop a file here, or click to browse</div><div class="dz-sub">PDF · Word · Excel · CSV · TXT · JSON · XML</div>';
  const btn = document.getElementById('file-extract-btn');
  if (btn) btn.disabled = true;
  document.getElementById('file-out').innerHTML = '';
}

async function handleFileRaw(file) {
  // Validate file size (max 25MB)
  if (file.size > MAX_FILE_BYTES) { toast('File too large (max 25MB)'); return; }

  const out = document.getElementById('file-out');
  out.innerHTML = `<div class="status s-info"><span class="spin"></span> Reading ${esc(file.name)}…</div>`;

  // Lazy-load file parsing libraries on first use
  try { await ensureFileLibs(); } catch (e) { console.warn('[Lazy] lib load:', e); }

  const ext = file.name.split('.').pop().toLowerCase().replace(/[^a-z]/g,'');
  let text = '';
  try {
    if (ext==='pdf')          text = await readPDF(file);
    else if (ext==='docx')    text = await readDOCX(file);
    else if (ext==='xlsx'||ext==='xls'||ext==='xlsm') text = await readExcel(file);
    else                      text = await readTxt(file);
  } catch(e) {
    out.innerHTML = `<div class="status s-err">Error reading file: ${esc(e.message)}</div>`;
    return;
  }

  lastFileText = text;
  let display = text;
  if (document.getElementById('tgl-ft').classList.contains('on') && text) {
    out.innerHTML = '<div class="status s-info"><span class="spin"></span> Translating…</div>';
    try { display = await translate(text, null); } catch {}
  }

  // Extract fields directly from file text
  const dummy = new DOMParser().parseFromString('<pre>' + display.replace(/</g,'&lt;') + '</pre>', 'text/html');
  const fileFields = extractFields(dummy, display);
  const searchType = document.getElementById('search-type')?.value || 'farm';
  const filteredFileFields = filterFieldsByType(fileFields, searchType);
  const allKeys = Object.keys(filteredFileFields).filter(k => !k.startsWith('_'));

  const frag = document.createDocumentFragment();
  frag.appendChild(document.createElement('hr'));

  // File info chips
  const chips = document.createElement('div');
  chips.style.cssText = 'display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px';
  [
    ['chip-b', file.name],
    ['chip-g', allKeys.length + ' field(s) extracted from file'],
    ['chip-o', text.length.toLocaleString() + ' chars'],
  ].forEach(([cls, t]) => {
    const s = document.createElement('span'); s.className = 'chip ' + cls; s.textContent = t;
    chips.appendChild(s);
  });
  frag.appendChild(chips);

  // Inline extracted fields grid
  if (allKeys.length) {
    const flbl = document.createElement('div'); flbl.className = 'label';
    flbl.textContent = 'Fields found in document'; frag.appendChild(flbl);
    const grid = document.createElement('div'); grid.className = 'vc-grid'; grid.style.marginBottom = '12px';
    allKeys.forEach(k => {
      const cell = document.createElement('div'); cell.className = 'vf';
      const lbl  = document.createElement('div'); lbl.className = 'vfl'; lbl.textContent = k.replace(/_/g,' ').toUpperCase();
      const val  = document.createElement('div'); val.className = 'vfv'; val.textContent = filteredFileFields[k];
      cell.appendChild(lbl); cell.appendChild(val); grid.appendChild(cell);
    });
    frag.appendChild(grid);
  }

  // Download + text view
  const row = document.createElement('div'); row.className = 'btn-row';
  const dlBtn = document.createElement('button'); dlBtn.className = 'btn btn-ghost btn-sm';
  dlBtn.textContent = 'Download text'; dlBtn.onclick = downloadText;
  row.appendChild(dlBtn);
  frag.appendChild(row);

  const kwhdr = document.createElement('div'); kwhdr.className = 'label'; kwhdr.style.marginTop = '12px';
  kwhdr.textContent = 'Full document text'; frag.appendChild(kwhdr);
  const tv = document.createElement('div'); tv.className = 'text-view'; tv.id = 'ftv';
  tv.innerHTML = esc(display.slice(0, 8000)).replace(
    /\b(species|latitude|longitude|capacity|certification|FCR|salinity|pH|operator|country|region|license|harvest|stocking|temperature|fishmeal|fish\s*oil|processing|employees?|farm|aquaculture|vessel|IMO|flag|tonnage)\b/gi,
    '<mark style="background:#fff3cd;color:#333;padding:0 2px">$1</mark>'
  );
  frag.appendChild(tv);

  // Web enrichment section — scrape the internet for each entity found in the file
  const webHdr = document.createElement('div'); webHdr.className = 'label'; webHdr.style.marginTop = '16px';
  webHdr.textContent = 'Web intelligence'; frag.appendChild(webHdr);
  const webOut = document.createElement('div'); webOut.id = 'file-web-out'; frag.appendChild(webOut);

  out.innerHTML = '';
  out.appendChild(frag);

  // Identify entity names from the file to search the web for
  const entityNames = extractFileEntities(fileFields, display);
  if (entityNames.length) {
    webOut.innerHTML = `<div class="status s-info"><span class="spin"></span> Searching web for ${entityNames.length} entity(ies) found in file…</div>`;
    const yearTo = parseInt(document.getElementById('year-to')?.value || String(new Date().getFullYear()));
    const catFilter = document.getElementById('cat-filter')?.value || '';
    if (fileRawAC) fileRawAC.abort();
    fileRawAC = new AbortController();
    const ac = fileRawAC;

    (async () => {
      let cardCount = 0;
      webOut.innerHTML = '';
      for (const name of entityNames) {
        const status = document.createElement('div');
        status.className = 'status s-info';
        status.innerHTML = `<span class="spin"></span> Scanning web for: <b>${esc(name)}</b>…`;
        webOut.appendChild(status);

        try {
          const { scrapeResults, allImgs, imo, mmsi } =
            await bulkScrapeItem(name, searchType, yearTo, catFilter, ac.signal);

          // Merge web results with what was already in the file
          const webMerged = mergeFields(scrapeResults, name);
          // File fields take precedence over web for already-known values
          const merged = { ...webMerged, ...filteredFileFields };
          if (imo)  merged._imo = merged._imo || imo;
          if (mmsi) merged.mmsi = merged.mmsi || mmsi;

          const cardName = searchType === 'vessel'
            ? (merged.vessel_name || name)
            : (merged.farm_name || merged.vessel_name || merged.name || name);

          status.remove();
          const div = document.createElement('div');
          div.innerHTML = renderCard(cardName, imo, merged, scrapeResults, allImgs);
          webOut.appendChild(div);
          cardCount++;
          stats.searches++; stats.ships++; updateStats();
        } catch(e) {
          if (e.name === 'AbortError') break;
          status.className = 'status s-err';
          status.innerHTML = `✗ ${esc(name)}: ${esc(e.message)}`;
        }
        await sleep(1200);
      }
      if (cardCount === 0 && !ac.signal.aborted) {
        webOut.innerHTML = '<div class="status s-warn">No web results found. Try a more specific entity name in the file.</div>';
      }
      if (fileRawAC === ac) fileRawAC = null;
    })();
  } else {
    webOut.innerHTML = '<div class="status s-warn">No entity names detected in file — upload a document that mentions a specific farm, mill, or vessel name.</div>';
  }
}

// Extract entity names from file fields and raw text (up to 5 unique names)
function extractFileEntities(fields, text) {
  const names = new Set();
  // Prefer structured field names
  for (const k of ['farm_name','vessel_name','name','operator']) {
    const v = fields[k]; if (v && v.length > 2 && v.length < 80) names.add(v);
  }
  // Scan lines for patterns that look like proper entity names
  if (names.size < 3) {
    const lines = text.split(/[\n\r]+/).map(l => l.trim());
    for (const line of lines) {
      if (line.length < 4 || line.length > 80) continue;
      // Lines that are mostly title-case or ALL CAPS short phrases (likely headings/names)
      if (/^[A-Z][A-Za-z0-9\s&.,'\-()]{3,70}$/.test(line) &&
          !/^\d|^(page|date|version|ref|section|table|figure|annex)/i.test(line) &&
          line.split(' ').length <= 8) {
        names.add(line.replace(/[.,:;]+$/, '').trim());
      }
      if (names.size >= 5) break;
    }
  }
  return [...names].slice(0, 5);
}

async function readPDF(file) {
  if (typeof pdfjsLib === 'undefined') return '[PDF.js not loaded — check internet connection]';
  const ab = await file.arrayBuffer();
  const pdf = await pdfjsLib.getDocument({data:ab}).promise;
  const parts = [];
  for (let i = 1; i <= pdf.numPages; i++) {
    const pg = await pdf.getPage(i);
    const c  = await pg.getTextContent();
    parts.push(`--- Page ${i} ---\n` + c.items.map(x=>x.str).join(' '));
  }
  return parts.join('\n\n');
}
async function readDOCX(file) {
  if (typeof mammoth === 'undefined') return '[mammoth.js not loaded]';
  const ab = await file.arrayBuffer();
  const r  = await mammoth.extractRawText({arrayBuffer:ab});
  return r.value;
}
async function readExcel(file) {
  if (typeof XLSX === 'undefined') return '[SheetJS not loaded]';
  const ab = await file.arrayBuffer();
  const wb = XLSX.read(ab, {type:'array'});
  return wb.SheetNames.map(n => `=== ${n} ===\n` + XLSX.utils.sheet_to_csv(wb.Sheets[n])).join('\n\n');
}
async function readTxt(file) {
  for (const enc of ['utf-8','latin1']) {
    try {
      return await new Promise((res,rej) => {
        const r = new FileReader();
        r.onload  = e => res(e.target.result);
        r.onerror = rej;
        r.readAsText(file, enc);
      });
    } catch {}
  }
  return '[Could not decode file]';
}

function fileSearch() {
  const kw  = document.getElementById('file-kw').value.trim().toLowerCase().slice(0,100);
  const view = document.getElementById('ftv');
  if (!kw || !view) return;
  const hits = lastFileText.split('\n')
    .map((l,i) => ({n:i+1,l}))
    .filter(x => x.l.toLowerCase().includes(kw));
  if (!hits.length) { toast('No matches for "' + kw + '"'); return; }
  const safeKW = kw.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
  view.innerHTML = hits.slice(0,100).map(h =>
    `<div><span style="color:var(--mut2);margin-right:8px">L${h.n}</span>${
      esc(h.l).replace(new RegExp(`(${safeKW})`, 'gi'),
      '<mark style="background:#fff3cd;color:#333">$1</mark>')
    }</div>`).join('');
  toast(hits.length + ' match(es)');
}
function downloadText() {
  const blob = new Blob([lastFileText], {type:'text/plain'});
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = 'extracted.txt'; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 5000);  // clean up blob URL
}

/* ═══════════════════════════════════════════
   PASTE TEXT
═══════════════════════════════════════════ */
async function textExtract() {
  const raw = document.getElementById('txt-in').value.trim();
  const out = document.getElementById('txt-out');
  if (!raw) { toast('Paste some text first'); return; }

  let text = raw;
  if (document.getElementById('tgl-tt').classList.contains('on')) {
    out.innerHTML = '<div class="status s-info"><span class="spin"></span> Translating…</div>';
    try { text = await translate(raw, null); } catch {}
  }

  // Extract fish farm fields from the pasted text using a dummy doc
  const dummy = new DOMParser().parseFromString('<pre>' + text.replace(/</g,'&lt;') + '</pre>', 'text/html');
  const fields = extractFields(dummy, text);

  const frag = document.createDocumentFragment();
  const hr = document.createElement('hr'); frag.appendChild(hr);

  // Show extracted farm fields if any
  const farmKeys = ['farm_name','species','water_type','capacity','production_method',
    'license','certification','operator','country','region','latitude','longitude',
    'water_temp','salinity','dissolved_oxygen','ph','fcr','stocking_density',
    'harvest_cycles','total_area','employees','processing_capacity','input_species',
    'output_products','fishmeal_pct','fishoil_pct','feed_type','description'];
  const found = farmKeys.filter(k => fields[k]);

  if (found.length) {
    const flbl = document.createElement('div');
    flbl.className = 'label';
    flbl.textContent = `Extracted fields (${found.length})`;
    frag.appendChild(flbl);

    const grid = document.createElement('div');
    grid.className = 'vc-grid';
    grid.style.marginBottom = '12px';
    found.forEach(k => {
      const cell = document.createElement('div');
      cell.className = 'vf';
      const lbl = document.createElement('div'); lbl.className = 'vfl'; lbl.textContent = k.replace(/_/g,' ').toUpperCase();
      const val = document.createElement('div'); val.className = 'vfv'; val.textContent = fields[k];
      cell.appendChild(lbl); cell.appendChild(val);
      grid.appendChild(cell);
    });
    frag.appendChild(grid);

    // Save button for the extracted data
    const saveBtn = document.createElement('button');
    saveBtn.className = 'btn btn-blue btn-sm';
    saveBtn.textContent = 'Save Extracted Data';
    saveBtn.onclick = () => doSave({ name: fields.farm_name || fields.vessel_name || 'Pasted record', ...fields }, null);
    const row = document.createElement('div'); row.className = 'btn-row';
    row.appendChild(saveBtn);
    frag.appendChild(row);
  } else {
    const none = document.createElement('div');
    none.className = 'status s-warn';
    none.textContent = 'No structured fish farm fields detected. Try the keyword search below to find specific values.';
    frag.appendChild(none);
  }

  // Show highlighted text
  const tv = document.createElement('div');
  tv.className = 'text-view';
  tv.style.marginTop = '10px';
  tv.innerHTML = esc(text.slice(0, 8000)).replace(
    /\b(species|latitude|longitude|capacity|certification|FCR|salinity|pH|operator|country|region|license|harvest|stocking|temperature|fishmeal|fish oil|processing|employees?)\b/gi,
    '<mark style="background:#fff3cd;color:#333;padding:0 2px">$1</mark>'
  );
  frag.appendChild(tv);

  out.innerHTML = ''; out.appendChild(frag);
}

/* ═══════════════════════════════════════════
   BULK SCRAPE HELPER
   Full pipeline for one query: APIs + Bing + follow links
═══════════════════════════════════════════ */
async function bulkScrapeItem(q, searchType, yearTo, catFilter, signal) {
  const isVessel = searchType === 'vessel';
  const isMill   = searchType === 'mill';

  // 1 ─ Direct API queries
  let scrapeResults = [];
  let imo = '', mmsi = '';

  if (isVessel) {
    const isIMO  = /^\d{7}$/.test(q) && validIMO(q);
    const isMMSI = /^\d{9}$/.test(q);
    const vl = await queryVesselAPIs(q, isIMO ? q : '', isMMSI ? q : '', signal)
                       .catch(() => ({ results:[], imo:'', mmsi:'' }));
    scrapeResults = vl.results;
    imo  = vl.imo  || (isIMO  ? q : '');
    mmsi = vl.mmsi || (isMMSI ? q : '');
  } else {
    scrapeResults = await queryFarmAPIs(q, signal, yearTo).catch(() => []);
  }

  // 2 ─ Build Bing search URL
  const words = q.trim().split(/\s+/);
  const qPhrase = (words.length >= 3 || q.length >= 16) ? `"${q}"` : q;
  const catKW   = catFilter ? ` ${catFilter}` : '';
  let bingQ;
  if (isVessel) {
    bingQ = `${qPhrase}${catKW} vessel ship fishing registry IMO`;
  } else if (isMill) {
    bingQ = `${qPhrase}${catKW} fish meal fishmeal processing plant`;
  } else {
    bingQ = `${qPhrase}${catKW} fish farm aquaculture facility`;
  }

  // 3 ─ Build list of URLs to scrape (Bing + DDG + direct registries for vessels)
  const ddgBulkQ = isVessel
    ? `${qPhrase}${catKW} vessel ship IMO flag registry`
    : isMill ? `${qPhrase}${catKW} fishmeal fish oil processing`
             : `${qPhrase}${catKW} aquaculture fish farm species`;
  const scraperURLs = [
    { id:'Web-Discovery', url:`https://www.bing.com/search?q=${encodeURIComponent(bingQ)}` },
    { id:'DDG-Search',    url:`https://html.duckduckgo.com/html/?q=${encodeURIComponent(ddgBulkQ)}` },
    { id:'Intl-Search',   url:`https://www.bing.com/search?q=${encodeURIComponent(
        isVessel ? `${q} nave barco buque vessel schiff` : `${q} acuicultura aquaculture élevage`
      )}&setlang=en`, _fallback:true },
  ];

  if (isVessel) {
    if (imo) {
      scraperURLs.push(
        { id:'MarineTraffic', url:`https://www.marinetraffic.com/en/ais/details/ships/imo:${imo}` },
        { id:'VesselFinder',  url:`https://www.vesselfinder.com/vessels/details/${imo}` },
      );
    } else {
      scraperURLs.push(
        { id:'MarineTraffic', url:`https://www.marinetraffic.com/en/ais/details/ships/shipid:0/mmsi:0/vessel:${encodeURIComponent(q)}` },
      );
    }
  }

  const allImgs = scrapeResults.flatMap(r => r.imgs || []);

  // 4 ─ Scrape each URL sequentially (polite for bulk)
  for (const s of scraperURLs) {
    if (signal?.aborted) break;
    try {
      const html = await fetchViaProxy(s.url, signal);
      const doc  = parseHTML(html);
      let   text = doc.body?.innerText?.slice(0, 8000) || '';

      const pageLang = detectLang(doc, text);
      if (pageLang !== 'en') {
        try { text = await translate(text.slice(0, 3000), signal); } catch {}
      }

      const fields = extractFields(doc, text);
      const imgs   = extractImages(doc, s.url);
      if (!imo) { const f = extractIMOs(text); if (f.length) imo = f[0]; }

      // Follow top result links from Bing / DDG pages
      if (['Web-Discovery','DDG-Search','Intl-Search'].includes(s.id)) {
        const urlMatches = html.match(/href="(https?:\/\/(?!www\.bing\.com|www\.google\.com|html\.duckduckgo\.com)[^"]{12,300})"/g) || [];
        const topURLs = [...new Set(urlMatches.map(m => m.slice(6,-1)).filter(u => isValidURL(u) && !u.includes('duckduckgo.com')))]
                          .slice(0, s._fallback ? 4 : 8);
        for (const u of topURLs) {
          if (signal?.aborted) break;
          try {
            const ph = await fetchViaProxy(u, signal);
            const pd = parseHTML(ph);
            let   pt = pd.body?.innerText?.slice(0, 8000) || '';
            const subLang = detectLang(pd, pt);
            if (subLang !== 'en') {
              try { pt = await translate(pt.slice(0, 3000), signal); } catch {}
            }
            if (relevanceScore(pt, q) === 0) continue;
            if (!topicMatch(pt, searchType)) continue;
            const rawPf = extractFields(pd, pt);
            const pf    = filterFieldsByType(rawPf, searchType);
            const pi = extractImages(pd, u);
            if (Object.keys(pf).filter(k => !k.startsWith('_')).length >= 1) {
              scrapeResults.push({ id: new URL(u).hostname, ok:true, url:u, fields:pf, imgs:pi, text:pt });
              allImgs.push(...pi);
            }
          } catch(e) { if (e.name === 'AbortError') throw e; }
          await sleep(700); // polite gap between page fetches within one item
        }
      }

      const filteredFields = filterFieldsByType(fields, searchType);
      const fc = Object.keys(filteredFields).filter(k => !k.startsWith('_')).length;
      const topicOk = topicMatch(text, searchType);
      if ((fc > 0 || imgs.length > 0) && topicOk) {
        scrapeResults.push({ id:s.id, ok:true, url:s.url, fields:filteredFields, imgs, text });
        allImgs.push(...imgs);
      }
    } catch(e) {
      if (e.name === 'AbortError') throw e;
      scrapeResults.push({ id:s.id, ok:false, url:s.url, error:e.message, fields:{}, imgs:[], text:'' });
    }
    await sleep(500); // polite gap between source URLs
  }

  // Deduplicate images
  const seenImgs = new Set();
  const dedupImgs = allImgs.filter(img => {
    if (!img?.src || seenImgs.has(img.src)) return false;
    seenImgs.add(img.src); return true;
  }).slice(0, 8);

  return { scrapeResults, allImgs: dedupImgs, imo, mmsi };
}

/* ═══════════════════════════════════════════
   BULK LOOKUP
═══════════════════════════════════════════ */
async function doBulk() {
  if (isRunning) { toast('A search is already running'); return; }
  const raw   = document.getElementById('bulk-in').value;
  const lines = raw.split(/[\n,]+/).map(l=>l.trim()).filter(Boolean).slice(0,20);
  if (!lines.length) { toast('Enter at least one name'); return; }
  bulkRes = [];
  const out     = document.getElementById('bulk-out');
  const prog    = document.getElementById('bulk-prog');
  const bar     = document.getElementById('bulk-bar');
  const txt     = document.getElementById('bulk-txt');
  const bulkBtn = document.querySelector('[onclick="doBulk()"]');
  out.innerHTML=''; prog.style.display='';
  isRunning = true;
  currentAC = new AbortController();
  const { signal } = currentAC;
  if (bulkBtn) { bulkBtn.disabled = true; bulkBtn.textContent = 'Running…'; }
  document.getElementById('cancel-btn').classList.add('show');

  try {
    for (let i = 0; i < lines.length; i++) {
      if (signal.aborted) break;
      const q = lines[i].replace(/[<>"']/g,'').slice(0,100);
      txt.textContent = `Scanning ${i+1}/${lines.length}: ${q}…`;
      bar.style.width = ((i+1)/lines.length*100) + '%';

      try {
        const bulkType   = document.getElementById('search-type')?.value || 'farm';
        const bulkYearTo = parseInt(document.getElementById('year-to')?.value || String(new Date().getFullYear()));
        const bulkCat    = document.getElementById('cat-filter')?.value || '';

        const { scrapeResults, allImgs, imo, mmsi } =
          await bulkScrapeItem(q, bulkType, bulkYearTo, bulkCat, signal);

        const merged = mergeFields(scrapeResults, q);
        if (imo)  merged._imo = merged._imo || imo;
        if (mmsi) merged.mmsi = merged.mmsi || mmsi;

        const isVesselType = bulkType === 'vessel';
        const cardName = isVesselType
          ? (merged.vessel_name || q)
          : (merged.farm_name || merged.vessel_name || merged.name || q);

        bulkRes.push({ query:q, ...merged });
        const div = document.createElement('div');
        div.innerHTML = renderCard(cardName, imo, merged, scrapeResults, allImgs);
        out.appendChild(div);
      } catch(e) {
        if (e.name === 'AbortError') break;
        bulkRes.push({ query:q, error:e.message });
        const d = document.createElement('div');
        d.className='status s-err'; d.textContent=`✗ ${q}: ${e.message}`;
        out.appendChild(d);
      }
      stats.searches++; stats.ships++; updateStats();
      if (!signal.aborted) await sleep(1500); // courtesy gap between items
    }
    const completed = !signal.aborted;
    txt.textContent = completed
      ? `Round complete — ${bulkRes.length} item(s) scanned.`
      : `Cancelled after ${bulkRes.length} item(s)`;

    // Show "Next Round" button after a completed run
    if (completed && document.getElementById('bulk-in')?.value.trim()) {
      const nextBtn = document.createElement('button');
      nextBtn.className = 'btn btn-blue';
      nextBtn.style.cssText = 'margin-top:10px;font-size:13px;padding:8px 24px;';
      nextBtn.textContent = 'Next Round →';
      nextBtn.onclick = () => { nextBtn.remove(); doBulk(); };
      prog.appendChild(nextBtn);
    }
  } finally {
    isRunning = false;
    currentAC = null;
    if (bulkBtn) { bulkBtn.disabled = false; bulkBtn.textContent = 'Bulk Lookup'; }
    document.getElementById('cancel-btn').classList.remove('show');
  }
}

/* ═══════════════════════════════════════════
   SAVE / EXPORT
═══════════════════════════════════════════ */
let _savedView = 'cards';

function doSave(info, btnId) {
  if (typeof info === 'string') { try { info = JSON.parse(info); } catch { return; } }
  const key = info.imo || info._imo || info.farm_name || info.vessel_name || info.name || '';
  const alreadySaved = key && saved.find(s =>
    (s.imo || s._imo || s.farm_name || s.vessel_name || s.name || '') === key);
  if (alreadySaved) { toast('Already saved'); return; }
  const rid = Date.now().toString(36) + Math.random().toString(36).slice(2);
  const record = {
    id:  rid,
    _id: rid,
    _savedAt: new Date().toISOString(),
    _notes: '',
    _verified: false,
    _category:     document.getElementById('cat-filter')?.value || '',
    _facilityType: document.getElementById('search-type')?.value || 'farm',
    ...info,
  };
  saved.push(record);
  persist();
  updateSavedBadge();
  updateStats();
  toast('Saved: ' + (info.name || info.vessel_name || info.farm_name || key || 'Record'));
  if (btnId) {
    const btn = document.getElementById(btnId);
    if (btn) { btn.textContent = 'Saved!'; btn.disabled = true; btn.style.color = 'var(--grn)'; }
  }
}

function saveVessel(info) { doSave(info, null); }

function deleteSaved(id) {
  if (!confirm('Delete this record?')) return;
  saved = saved.filter(s => s._id !== id);
  persist();
  updateSavedBadge();
  updateStats();
  renderSaved();
  toast('Record deleted');
}

function editNote(id) {
  const rec = saved.find(s => s._id === id);
  if (!rec) return;
  const note = prompt('Note for this record (500 char max):', rec._notes || '');
  if (note === null) return;
  rec._notes = note.slice(0, 500);
  persist();
  renderSaved();
}

function toggleVerified(id) {
  const rec = saved.find(s => s._id === id);
  if (!rec) return;
  rec._verified = !rec._verified;
  persist();
  renderSaved();
  toast(rec._verified ? '✓ Marked as verified' : 'Verification removed');
}

function exportRecord(id, fmt) {
  const rec = saved.find(s => s._id === id);
  if (!rec) return;
  const name = (rec.name || rec.vessel_name || rec.farm_name || 'record').replace(/[^a-z0-9]/gi,'_');
  if (fmt === 'json') {
    dlBlob(JSON.stringify(rec, null, 2), `${name}.json`, 'application/json');
  } else {
    const keys = Object.keys(rec).filter(k => !k.startsWith('_') || ['_savedAt','_notes','_verified','_facilityType','_category'].includes(k));
    const row  = keys.map(k => `"${String(rec[k]||'').replace(/"/g,'""')}"`).join(',');
    dlBlob(keys.join(',') + '\n' + row, `${name}.csv`, 'text/csv');
  }
}

function printRecord(id) {
  const rec = saved.find(s => s._id === id);
  if (!rec) return;
  const name  = rec.name || rec.vessel_name || rec.farm_name || 'Record';
  const rows  = Object.entries(rec)
    .filter(([k]) => !k.startsWith('_') || ['_savedAt','_notes','_verified','_facilityType','_category'].includes(k))
    .map(([k,v]) => `<tr><td style="font-weight:700;padding:4px 10px;color:#555;white-space:nowrap">${esc(k)}</td><td style="padding:4px 10px">${esc(String(v))}</td></tr>`)
    .join('');
  const win = window.open('','_blank','width=700,height=900');
  if (!win) { toast('Allow pop-ups to print'); return; }
  win.document.write(`<!DOCTYPE html><html><head><title>${esc(name)}</title>
    <style>body{font-family:sans-serif;padding:24px;font-size:13px}h2{margin-bottom:16px}table{border-collapse:collapse;width:100%}tr:nth-child(even){background:#f5f5f5}@media print{button{display:none}}</style>
    </head><body><h2>${esc(name)}</h2><table>${rows}</table>
    <br><button onclick="window.print()">Print</button></body></html>`);
  win.document.close();
}

function setView(v) {
  _savedView = v;
  document.getElementById('vt-cards').classList.toggle('active', v === 'cards');
  document.getElementById('vt-table').classList.toggle('active', v === 'table');
  renderSaved();
}

function updateSavedBadge() {
  const badge   = document.getElementById('saved-badge');
  const lbl     = document.getElementById('saved-count-lbl');
  const toolbar = document.getElementById('saved-toolbar');
  if (badge) {
    badge.textContent = saved.length;
    badge.classList.toggle('empty', saved.length === 0);
  }
  if (lbl) lbl.textContent = saved.length ? `${saved.length} record${saved.length > 1 ? 's' : ''}` : '';
  if (toolbar) toolbar.classList.toggle('is-hidden', saved.length === 0);
}

function filteredSaved() {
  const q   = (document.getElementById('saved-search')?.value || '').toLowerCase().trim();
  const cat = (document.getElementById('saved-cat')?.value   || '').toLowerCase().trim();
  const srt = document.getElementById('saved-sort')?.value || 'date-desc';
  let list  = [...saved];
  if (q) list = list.filter(r => {
    const txt = [r.name,r.vessel_name,r.farm_name,r.imo,r._imo,r.flag,r.country,r.species,r.operator,r._notes]
      .filter(Boolean).join(' ').toLowerCase();
    return txt.includes(q);
  });
  if (cat) list = list.filter(r => {
    const txt = [r.species,r.vessel_type,r.water_type,r.production_method,r.description,r._notes]
      .filter(Boolean).join(' ').toLowerCase();
    return cat.split(' ').some(kw => txt.includes(kw));
  });
  list.sort((a,b) => {
    if (srt === 'date-desc') return new Date(b._savedAt||0) - new Date(a._savedAt||0);
    if (srt === 'date-asc')  return new Date(a._savedAt||0) - new Date(b._savedAt||0);
    const na = (a.name||a.vessel_name||a.farm_name||'').toLowerCase();
    const nb = (b.name||b.vessel_name||b.farm_name||'').toLowerCase();
    return srt === 'name-asc' ? na.localeCompare(nb) : nb.localeCompare(na);
  });
  return list;
}

function renderSaved() {
  const list = document.getElementById('saved-list');
  if (!list) return;
  updateSavedBadge();
  const records = filteredSaved();
  if (!saved.length) {
    list.innerHTML = '<div class="empty"><div class="empty-title">No saved records yet</div><span class="empty-sub">Search for a farm, mill, or vessel — then click <strong>Save</strong> on any result to build your library.</span></div>';
    return;
  }
  if (!records.length) {
    list.innerHTML = '<div class="empty">No records match your filter.</div>';
    return;
  }

  if (_savedView === 'table') {
    // Compact table view
    const hdrs = ['Name','IMO','Category','Facility / Vessel Type','Species','Country','Description','Scraped','Actions'];
    const rows = records.map(r => {
      const id      = esc(r._id || '');
      const name    = esc(r.name || r.vessel_name || r.farm_name || '—');
      const imo     = esc(r.imo || r._imo || '—');
      const cat     = esc(r._category || '—');
      const ftype   = esc(r._facilityType === 'mill'   ? 'Fish Mill / Processing'
                        : r._facilityType === 'vessel' ? 'Shipping / Fishing Vessel'
                        : r._facilityType === 'farm'   ? 'Fish Farm / Aquaculture'
                        : r.vessel_type || r.production_method || '—');
      const species = esc(r.species || r.input_species || '—');
      const country = esc(r.flag || r.country || '—');
      const desc    = esc((r.description || '').slice(0, 80)) + ((r.description||'').length > 80 ? '…' : '');
      const dt      = r._savedAt ? new Date(r._savedAt).toLocaleString() : '—';
      return `<tr>
        <td>
          <b>${name}</b>${r._verified ? ' <span style="font-size:10px;color:var(--grn);font-weight:600">✓</span>' : ''}
          ${r.owner || r.operator ? `<div style="font-size:10px;color:#727272;margin-top:1px">${esc(r.owner||r.operator)}</div>` : ''}
          ${r._notes ? `<div style="font-size:10px;color:#7a5c2b;margin-top:2px">${esc(r._notes.slice(0,50))}</div>` : ''}
        </td>
        <td style="font-family:monospace;font-size:11px">${imo}</td>
        <td><span class="chip chip-b" style="font-size:10px">${cat}</span></td>
        <td><span class="chip chip-o" style="font-size:10px">${ftype}</span></td>
        <td><span class="chip chip-g" style="font-size:10px">${species}</span></td>
        <td>${country}</td>
        <td style="font-size:11px;color:var(--mut3);max-width:180px">${desc}</td>
        <td style="white-space:nowrap;color:var(--mut2);font-size:11px">${dt}</td>
        <td class="td-actions">
          <button class="btn-exp${r._verified ? ' btn-verified' : ''}" onclick="toggleVerified('${id}')" title="${r._verified ? 'Remove verification' : 'Mark as verified'}">${r._verified ? '✓ Verified' : 'Verify'}</button>
          <button class="btn-exp" onclick="editNote('${id}')">Note</button>
          <button class="btn-exp" onclick="exportRecord('${id}','json')">JSON</button>
          <button class="btn-exp" onclick="exportRecord('${id}','csv')">CSV</button>
          <button class="btn-exp" onclick="printRecord('${id}')">Print</button>
          <button class="btn-del" onclick="deleteSaved('${id}')">Del</button>
        </td>
      </tr>`;
    }).join('');
    list.innerHTML = `<div class="tbl-wrap"><table class="sv-table">
      <thead><tr>${hdrs.map(h=>`<th>${h}</th>`).join('')}</tr></thead>
      <tbody>${rows}</tbody></table></div>`;
  } else {
    // Card view
    list.innerHTML = '';
    records.forEach(r => {
      const div = document.createElement('div');
      div.innerHTML = renderCard(
        r.name || r.vessel_name || r.farm_name || 'Record',
        r.imo || r._imo || '',
        r, [], [], r._id
      );
      list.appendChild(div);
    });
  }
}

function clearSaved() {
  if (!confirm(`Delete all ${saved.length} saved record${saved.length !== 1 ? 's' : ''}? This cannot be undone.`)) return;
  saved = [];
  persist();
  updateSavedBadge();
  updateStats();
  renderSaved();
}

async function persist() {
  try {
    if (window.AppIDB) {
      await AppIDB.putAllRecords(saved);
    } else {
      localStorage.setItem('ship_saved3', JSON.stringify(saved));
    }
  } catch (e) {
    // IDB failed — try localStorage as fallback
    try { localStorage.setItem('ship_saved3', JSON.stringify(saved)); }
    catch { toast('Warning: could not save — storage unavailable.'); }
  }
}

/* ═══════════════════════════════════════════
   KNOWLEDGE BASE — persistent learning
═══════════════════════════════════════════ */
function normalizeName(n) {
  return (n || '').toLowerCase().replace(/[^\w\s]/g, '').replace(/\s+/g, ' ').trim();
}

function learnFromSearch(name, fields, sources) {
  const key = normalizeName(name);
  const fks = Object.keys(fields).filter(k => !k.startsWith('_'));
  if (!key || fks.length < 2) return;
  const ex = learned[key] || { fields:{}, sources:[], hitCount:0, lastSeen:null, confidence:0 };
  fks.forEach(k => { if (fields[k] && !ex.fields[k]) ex.fields[k] = fields[k]; });
  const goodSrc = (sources || []).filter(s => s.ok).map(s => s.id);
  ex.sources = [...new Set([...ex.sources, ...goodSrc])];
  ex.hitCount++;
  ex.lastSeen = new Date().toISOString();
  ex.confidence = Math.min(1, Object.keys(ex.fields).length / 8);
  learned[key] = ex;
  persistLearned();
}

function checkLearned(name) {
  const hit = learned[normalizeName(name)];
  if (!hit) return null;
  if (Date.now() - new Date(hit.lastSeen).getTime() > 30 * 24 * 60 * 60 * 1000) return null;
  return hit;
}

function learnFromDomain(hostname, success, fieldCount) {
  if (!hostname) return;
  const d = domainStats[hostname] || { hits:0, successes:0, totalFields:0 };
  d.hits++;
  if (success) { d.successes++; d.totalFields += (fieldCount || 0); }
  domainStats[hostname] = d;
  schedulePersistLearned(); // debounced — domain hits fire rapidly per search
}

// Debounce: batch rapid in-flight domain-stat updates into one write per 3 s
let _persistLearnedTimer = null;
function schedulePersistLearned() {
  clearTimeout(_persistLearnedTimer);
  _persistLearnedTimer = setTimeout(() => persistLearned(), 3000);
}

async function persistLearned() {
  // Evict stale entries before writing — keeps the store bounded
  const STALE_MS  = 30 * 24 * 60 * 60 * 1000; // 30 days
  const MAX_ENTRIES = 500;
  const now = Date.now();
  // Remove entries not seen in 30 days
  for (const k of Object.keys(learned)) {
    if (now - new Date(learned[k].lastSeen).getTime() > STALE_MS) delete learned[k];
  }
  // If still over cap, evict the oldest entries first
  const allKeys = Object.keys(learned);
  if (allKeys.length > MAX_ENTRIES) {
    allKeys
      .sort((a, b) => new Date(learned[a].lastSeen) - new Date(learned[b].lastSeen))
      .slice(0, allKeys.length - MAX_ENTRIES)
      .forEach(k => delete learned[k]);
  }

  try {
    if (window.AppIDB) {
      await AppIDB.put('knowledge', { key: 'learned', data: { learned, domainStats } });
    } else {
      localStorage.setItem('ship_learned1', JSON.stringify({ learned, domainStats }));
    }
  } catch {
    try { localStorage.setItem('ship_learned1', JSON.stringify({ learned, domainStats })); } catch {}
  }
}

async function saveProxyHealth() {
  try {
    // Save all known proxies including zeros so recovered proxies overwrite stale fail counts
    const pf = {};
    PROXIES.forEach(p => pf[p] = proxyFails.get(p) || 0);
    if (window.AppIDB) {
      await AppIDB.put('knowledge', { key: 'pfails', data: pf });
    } else {
      localStorage.setItem('ship_pfails1', JSON.stringify(pf));
    }
  } catch {}
}

/** Returns the known success rate [0–1] for a URL's domain (0.5 = unknown) */
function domainSuccessRate(url) {
  try {
    const d = domainStats[new URL(url).hostname];
    if (!d || d.hits < 2) return 0.5;
    return d.successes / d.hits;
  } catch { return 0.5; }
}

function clearKnowledge() {
  const n = Object.keys(learned).length;
  if (!confirm(`Clear all ${n} learned entity record${n!==1?'s':''} and domain performance data? This cannot be undone.`)) return;
  learned = {}; domainStats = {};
  persistLearned();
  renderKnowledge();
  toast('Knowledge base cleared');
}

function renderKnowledge() {
  const el = document.getElementById('know-body');
  if (!el) return;

  const entities = Object.entries(learned)
    .sort((a, b) => new Date(b[1].lastSeen) - new Date(a[1].lastSeen));
  const domains = Object.entries(domainStats)
    .sort((a, b) => b[1].successes - a[1].successes)
    .slice(0, 20);

  if (!entities.length && !domains.length) {
    el.innerHTML = '<div class="empty"><div class="empty-title">Nothing learned yet</div><span class="empty-sub">Run any search, scrape a URL, or upload a file — the bot stores every result here so future searches are faster and smarter.</span></div>';
    return;
  }

  const totalHits = entities.reduce((s, [,v]) => s + v.hitCount, 0);
  const avgConf   = entities.length ? Math.round(entities.reduce((s,[,v])=>s+v.confidence,0)/entities.length*100) : 0;

  const entityRows = entities.slice(0, 60).map(([key, v]) => {
    const confPct = Math.round(v.confidence * 100);
    const fillCls = confPct > 60 ? 'know-fill-grn' : confPct > 30 ? 'know-fill-gold' : 'know-fill-red';
    const age = Math.floor((Date.now() - new Date(v.lastSeen).getTime()) / 86400000);
    const ageStr = age === 0 ? 'today' : age === 1 ? 'yesterday' : `${age}d ago`;
    const display = key.replace(/\b\w/g, c => c.toUpperCase());
    const fCount  = Object.keys(v.fields).length;
    return `<tr>
      <td><b>${esc(display)}</b><div style="font-size:10px;color:var(--mut2);margin-top:1px">${esc(v.sources.slice(0,4).join(' · '))}</div></td>
      <td style="text-align:center">${v.hitCount}</td>
      <td style="text-align:center">${fCount}</td>
      <td><div style="display:flex;align-items:center;gap:6px"><div class="know-bar"><div class="${fillCls}" style="width:${confPct}%"></div></div><span style="font-size:11px;color:var(--mut2)">${confPct}%</span></div></td>
      <td style="color:var(--mut2);font-size:11px;white-space:nowrap">${esc(ageStr)}</td>
      <td><button class="btn-exp btn-resrch" data-resrch="${esc(display)}">Re-search</button></td>
    </tr>`;
  }).join('');

  const domainRows = domains.map(([host, d]) => {
    const rate = d.hits ? Math.round(d.successes / d.hits * 100) : 0;
    const avg  = d.successes ? (d.totalFields / d.successes).toFixed(1) : '—';
    const fillCls = rate > 60 ? 'know-fill-grn' : rate > 30 ? 'know-fill-gold' : 'know-fill-red';
    return `<tr>
      <td style="font-family:monospace;font-size:12px">${esc(host)}</td>
      <td style="text-align:center">${d.hits}</td>
      <td style="text-align:center">${d.successes}</td>
      <td><div style="display:flex;align-items:center;gap:6px"><div class="know-bar"><div class="${fillCls}" style="width:${rate}%"></div></div><span style="font-size:11px;color:var(--mut2)">${rate}%</span></div></td>
      <td style="text-align:center;color:var(--mut2)">${avg}</td>
    </tr>`;
  }).join('');

  el.innerHTML = `
    <div class="know-stats">
      <div class="know-stat"><span class="know-num">${entities.length}</span><span class="know-lbl">Entities learned</span></div>
      <div class="know-stat"><span class="know-num">${totalHits}</span><span class="know-lbl">Total searches</span></div>
      <div class="know-stat"><span class="know-num">${domains.length}</span><span class="know-lbl">Domains tracked</span></div>
      <div class="know-stat"><span class="know-num">${avgConf}%</span><span class="know-lbl">Avg confidence</span></div>
    </div>
    ${entityRows ? `<div class="know-section-title">Learned Entities <span style="color:var(--mut3);font-weight:400;font-size:11px">— most recent first, click Re-search to run again</span></div>
    <div class="tbl-wrap" style="margin-bottom:24px"><table class="sv-table">
      <thead><tr><th>Entity</th><th>Searches</th><th>Fields</th><th>Confidence</th><th>Last seen</th><th></th></tr></thead>
      <tbody>${entityRows}</tbody>
    </table></div>` : ''}
    ${domainRows ? `<div class="know-section-title">Domain Performance <span style="color:var(--mut3);font-weight:400;font-size:11px">— which sources consistently return data</span></div>
    <div class="tbl-wrap"><table class="sv-table">
      <thead><tr><th>Domain</th><th>Hits</th><th>Successes</th><th>Success rate</th><th>Avg fields/hit</th></tr></thead>
      <tbody>${domainRows}</tbody>
    </table></div>` : ''}`;

  // Event delegation for Re-search buttons (avoids inline JSON.stringify in onclick)
  el.onclick = e => {
    const btn = e.target.closest('.btn-resrch');
    if (!btn) return;
    setMode('search');
    document.getElementById('main-search').value = btn.dataset.resrch;
    document.getElementById('main-search').focus();
  };
}

function exportCSV(data, fn) {
  if (!data?.length) { toast('No data to export'); return; }
  const keys = [...new Set(data.flatMap(Object.keys))].filter(k => !k.startsWith('_') || ['_savedAt','_notes','_verified','_facilityType','_category'].includes(k));
  const rows = [keys.join(','), ...data.map(r =>
    keys.map(k => `"${String(r[k]||'').replace(/"/g,'""')}"`).join(','))];
  dlBlob(rows.join('\n'), fn, 'text/csv');
}
function exportJSON(data, fn) {
  if (!data?.length) { toast('No data to export'); return; }
  dlBlob(JSON.stringify(data, null, 2), fn, 'application/json');
}
function exportExcel(data, fn) {
  if (!data?.length) { toast('No data to export'); return; }
  if (typeof XLSX === 'undefined') { toast('SheetJS not loaded — check connection'); return; }
  const keys = [...new Set(data.flatMap(Object.keys))].filter(k => !k.startsWith('_') || ['_savedAt','_notes','_verified','_facilityType','_category'].includes(k));
  const rows = data.map(r => { const o={}; keys.forEach(k=>o[k]=r[k]||''); return o; });
  const ws   = XLSX.utils.json_to_sheet(rows);
  const wb   = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, ws, 'Records');
  XLSX.writeFile(wb, fn);
  toast('Downloaded ' + fn);
}
function dlBlob(content, fn, mime) {
  const url = URL.createObjectURL(new Blob([content],{type:mime}));
  const a   = document.createElement('a');
  a.href=url; a.download=fn; a.click();
  setTimeout(()=>URL.revokeObjectURL(url), 5000);
  toast('Downloaded ' + fn);
}

let _tt = null;
function toast(msg) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(_tt);
  _tt = setTimeout(()=>el.classList.remove('show'), 2600);
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

/* ── Dateline ── */
(function() {
  const el = document.getElementById('dateline-date');
  if (!el) return;
  const d = new Date();
  el.textContent = d.toLocaleDateString('en-US', { weekday:'long', year:'numeric', month:'long', day:'numeric' });
})();

/* ── Date range helpers ── */
function populateYearSelects() {
  const from = document.getElementById('year-from');
  const to   = document.getElementById('year-to');
  if (!from || !to) return;
  const curYear = new Date().getFullYear();
  for (let y = 2020; y <= curYear; y++) {
    from.add(new Option(y, y, y === 2020, y === 2020));
    to.add(new Option(y, y, y === curYear, y === curYear));
  }
  from.addEventListener('change', () => {
    if (parseInt(from.value) > parseInt(to.value)) to.value = from.value;
  });
  to.addEventListener('change', () => {
    if (parseInt(from.value) > parseInt(to.value)) from.value = to.value;
  });
}

/* Remove sentences mentioning years after yearTo */
function clipToYear(text, yearTo) {
  if (!text) return text;
  return text.split(/(?<=[.!?])\s+/).filter(s => {
    const yrs = (s.match(/\b(19|20)\d{2}\b/g) || []).map(Number);
    return !yrs.some(y => y > yearTo);
  }).join(' ');
}
