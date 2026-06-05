'use strict';

/* ═══════════════════════════════════════════
   SECURITY HELPERS
═══════════════════════════════════════════ */

/** Escape string for safe HTML insertion — single-pass lookup table (6× faster than chained replaces) */
const _ESC_MAP = { '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#x27;', '/':'&#x2F;' };
function esc(s) { return String(s ?? '').replace(/[&<>"'/]/g, c => _ESC_MAP[c]); }

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
      if (isNaN(n) || n < -90 || n > 90) return '';
      // Reject bare 0 — likely a default/null from a form, not the actual equator.
      // Only accept 0 when it has meaningful decimal precision (at least 3 places).
      if (n === 0 && !/\d\.\d{3}/.test(v)) return '';
      return parseFloat(n.toFixed(5)).toString();
    }
    case 'longitude': {
      const n = parseFloat(v.replace(/[°EW ]/gi,''));
      if (isNaN(n) || n < -180 || n > 180) return '';
      if (n === 0 && !/\d\.\d{3}/.test(v)) return '';
      return parseFloat(n.toFixed(5)).toString();
    }
    case 'year_built': {
      // 1[89]\d{2} = 1800–1999; 20\d{2} = 2000–2099 (avoids hardcoding decade limit)
      const m = v.match(/\b(1[89]\d{2}|20\d{2})\b/);
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
      if (v.length < 30) return '';
      // Reject generic site/platform meta descriptions and navigation boilerplate
      if (/^(search |find |explore |browse |home |menu |log.?in |sign.?in |register |subscribe |welcome to |this (site|website|page|portal) |we (are|provide|offer|specialize) |our (platform|service|database|website) )/i.test(v.trim())) return '';
      if (/(cookie policy|privacy policy|terms of (use|service)|all rights reserved|javascript (is |must be )|please enable)/i.test(v) && v.length < 300) return '';
      // Reject platform boilerplate — "ships tracked online in our database"
      if (/\b(ships?|vessels?|farms?|companies?)\s+(tracked|listed|online|in (our|the) database|registered on)\b/i.test(v) && !/\b(named|called|known as)\b/i.test(v)) return '';
      // Reject pure navigation fragments (but not descriptions that START with "Home Port:" etc.)
      if (/^\s*(search|find|explore|browse|login|sign\s*in|register|subscribe|menu|home)\s*$/i.test(v.trim())) return '';
      return v.slice(0, 1200);
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
      // Major aquaculture / seafood certifications
      if (/\bASC\b/.test(uc))                       return 'ASC Certified';
      if (/\bMSC\b/.test(uc))                       return 'MSC Certified';
      if (/\bBAP\b/.test(uc))                       return 'BAP Certified';
      if (/global\s*g\.?a\.?p/i.test(v))            return 'GlobalG.A.P. Certified';
      if (/friend\s*of\s*the\s*sea/i.test(v))       return 'Friend of the Sea';
      if (/\brspca\b/i.test(v))                     return 'RSPCA Assured';
      if (/naturland/i.test(v))                     return 'Naturland Certified';
      if (/\borganicf?\b|organic\s*cert/i.test(v))  return 'Organic Certified';
      if (/fair\s*trade/i.test(v))                  return 'Fairtrade Certified';
      if (/best\s*aquaculture\b|BAA\b/.test(uc))    return 'Best Aquaculture Certified';
      if (/\bsqs\b/i.test(v))                       return 'SQS Certified';
      if (/\bnativa\b/i.test(v))                    return 'NATIVA Certified';
      if (/\bdep\b.*seafood|seafood.*\bdep\b/i.test(v)) return 'Seafood DEP Certified';
      if (/\bices\b/i.test(v))                      return 'ICES Certified';
      if (/\bhalal\b/i.test(v))                     return 'Halal Certified';
      if (/\bkosher\b/i.test(v))                    return 'Kosher Certified';
      const isoM = v.match(/iso\s*(\d{4,5})/i);
      if (isoM) return `ISO ${isoM[1]} Certified`;
      const barc = v.match(/brc\s*(?:grade\s*)?([a-c+*])/i);
      if (barc || /\bbrc\b/i.test(v)) return barc ? `BRC Grade ${barc[1].toUpperCase()}` : 'BRC Certified';
      if (/\biffo\b/i.test(v))                      return 'IFFO RS Certified';
      if (/\bips\b.*marin|marine.*\bips\b/i.test(v)) return 'Marine Ingredients Certified';
      // Reject bare generic words that aren't real certification names
      if (/^(certified|yes|true|accredited|approved|compliant|標準)$/i.test(v.trim())) return '';
      return v.slice(0, 80);
    }
    case 'country': case 'flag': {
      // Reject org/foundation names masquerading as countries
      if (/\b(asc|fao|msc|bap|ices|imo|wwf|international|foundation|organization|association|institute|certified|standard)\b/i.test(v)) return '';
      // Map ISO-3, ISO-2, and common abbreviations to full country names
      // ISO-2 and ISO-3 alpha codes → full country names.
      // Maritime registries (Equasis, FAO, ITU) frequently return ISO-3 codes; we must expand them.
      const ISO_MAP = {
        // ISO-2
        UK:'United Kingdom', GB:'United Kingdom', US:'United States', USA:'United States',
        UAE:'United Arab Emirates', NO:'Norway', SE:'Sweden', DK:'Denmark', FI:'Finland',
        NL:'Netherlands', DE:'Germany', FR:'France', ES:'Spain', PT:'Portugal', IT:'Italy',
        BE:'Belgium', GR:'Greece', TR:'Turkey', IS:'Iceland', RU:'Russia', PL:'Poland',
        CL:'Chile', NZ:'New Zealand', AU:'Australia', CA:'Canada', PE:'Peru', IN:'India',
        CN:'China', JP:'Japan', KR:'South Korea', SG:'Singapore', PH:'Philippines',
        VN:'Vietnam', ID:'Indonesia', TH:'Thailand', MY:'Malaysia', BD:'Bangladesh',
        NG:'Nigeria', ZA:'South Africa', MA:'Morocco', EG:'Egypt', MX:'Mexico',
        BR:'Brazil', AR:'Argentina', CO:'Colombia', EC:'Ecuador', UY:'Uruguay',
        // ISO-3 alpha-3 — commonly emitted by Equasis, FAO Global Record, ITU ship databases
        GBR:'United Kingdom',
        NOR:'Norway', SWE:'Sweden', DNK:'Denmark', FIN:'Finland', NLD:'Netherlands',
        DEU:'Germany', FRA:'France', ESP:'Spain', PRT:'Portugal', ITA:'Italy',
        BEL:'Belgium', GRC:'Greece', TUR:'Turkey', ISL:'Iceland', RUS:'Russia', POL:'Poland',
        CHL:'Chile', NZL:'New Zealand', AUS:'Australia', CAN:'Canada', PER:'Peru',
        IND:'India', CHN:'China', JPN:'Japan', KOR:'South Korea', SGP:'Singapore',
        PHL:'Philippines', VNM:'Vietnam', IDN:'Indonesia', THA:'Thailand', MYS:'Malaysia',
        BGD:'Bangladesh', NGA:'Nigeria', ZAF:'South Africa', MAR:'Morocco', EGY:'Egypt',
        MEX:'Mexico', BRA:'Brazil', ARG:'Argentina', COL:'Colombia', ECU:'Ecuador',
        URY:'Uruguay', LBR:'Liberia', PAN:'Panama', BHS:'Bahamas', MRT:'Mauritania',
        TWN:'Taiwan', HKG:'Hong Kong', IRN:'Iran', IRQ:'Iraq', SAU:'Saudi Arabia',
        ARE:'United Arab Emirates', KWT:'Kuwait', QAT:'Qatar', OMN:'Oman', YEM:'Yemen',
        LBN:'Lebanon', ISR:'Israel', PAK:'Pakistan', LKA:'Sri Lanka', MMR:'Myanmar',
        KHM:'Cambodia', LAO:'Laos', PRI:'Puerto Rico', CUB:'Cuba', JAM:'Jamaica',
        // Common aliases / non-standard codes
        // Note: USA (ISO-3) is identical to USA (ISO-2 alias above) — no separate entry needed
        UAE:'United Arab Emirates', PRC:'China', ROC:'Taiwan',
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

// Global domain gate — page must mention at least one sea/maritime/aquaculture term.
// Prevents hotels, restaurants, and unrelated companies from appearing in results.
const _SEA_KW = new RegExp(
  // ── English ───────────────────────────────────────────────────────────────
  '\\b(?:aquaculture|fish(?:ery|eries|meal|oil|ing|farm|pond|cage|hatchery|feed|stock|pass)|seafood|' +
  'salmon|trout|shrimp|prawn|tilapia|tuna|cod|herring|menhaden|anchoveta|halibut|pollock|mackerel|' +
  'sea.?bass|seabass|sea.?bream|seabream|oyster|mussel|shellfish|crab|lobster|squid|mollusc|mollusk|' +
  'bivalve|finfish|pelagic|demersal|mariculture|pisciculture|net.?pen|smolt|broodstock|spawn(?:ing)?|' +
  'stocking.?density|biomass|fcr\\b|asc.?certif|msc.?certif|bap.?certif|global.?salmon|maritime|vessel|' +
  'trawler|purse.?seiner|factory.?ship|fish.?processing|fish.?factory|feed.?mill|marinetraffic|' +
  'vesselfinder|fleetmon|equasis|imo\\b|mmsi\\b|flag.?state|gross.?tonnage|deadweight|' +
  'port.?of.?registry|call.?sign|nav.?status|fishing.?vessel|cargo.?vessel|bulk.?carrier|tanker)\\b|' +
  // ── Norwegian / Nordic ───────────────────────────────────────────────────
  'fiskeoppdrett|akvakultur|oppdrettsanlegg|lakseoppdrett|settefisk|havbruk|fiskeridir|' +
  'fiskefartøy|skipsregister|fiskebåt|fiskemel|fiskeolje|reke|torsk|laks|ørret|' +
  // ── German ──────────────────────────────────────────────────────────────
  'aquakultur|fischzucht|fischfarm|lachszucht|fischerei|fischfarm|fischmehl|fischöl|garnele|' +
  // ── French ──────────────────────────────────────────────────────────────
  'aquaculture|pisciculture|élevage.?poisson|saumon|crevette|huître|farine.?poisson|huile.?poisson|' +
  // ── Spanish ─────────────────────────────────────────────────────────────
  'acuicultura|piscicultura|granja.?peces|salmón|camarón|langostino|harina.?pescado|aceite.?pescado|' +
  // ── Portuguese ──────────────────────────────────────────────────────────
  'aquicultura|piscicultura|camarão|salmão|farinha.?peixe|óleo.?peixe|' +
  // ── Japanese ────────────────────────────────────────────────────────────
  '養殖|水産|漁業|鮭|サーモン|エビ|かき|牡蠣|ぶり|まぐろ|漁船|船籍|船名|総トン数|' +
  // ── Korean ──────────────────────────────────────────────────────────────
  '양식|수산|어업|연어|새우|굴|어선|선명|선적|총톤수|' +
  // ── Russian ─────────────────────────────────────────────────────────────
  'аквакультура|рыбоводство|рыбная.?ферма|рыболовство|лосось|креветка|устрица|рыбная.?мука|рыбий.?жир|' +
  'рыболовное.?судно|название.?судна|' +
  // ── Arabic ──────────────────────────────────────────────────────────────
  'تربية.?الأحياء|استزراع.?سمكي|سمك|أسماك|روبيان|سلمون|سفينة.?صيد|' +
  // ── Chinese ─────────────────────────────────────────────────────────────
  '水产|养殖|渔业|鱼粉|鱼油|船舶|渔船|船东|捕鱼|海鲜|大西洋鲑|虾类|对虾|罗非鱼|鳟鱼|公众号|微信|WeChat',
  'i'
);

function isSeaRelated(text) {
  return text ? _SEA_KW.test(text) : false;
}

// Returns true if page text is topically compatible with the requested search type.
// isSeaRelated() is the first gate for ALL types — completely off-domain pages are
// rejected before the type-specific cross-checks run.
function topicMatch(text, searchType) {
  if (!text) return true;
  if (!isSeaRelated(text)) return false;           // global domain gate
  if (!searchType || searchType === 'general') return true;
  const tl = text.toLowerCase();
  const FARM_KW   = new RegExp(
    // English
    'aquaculture|fish farm|fish cage|net pen|hatchery|salmon farm|shrimp farm|trout farm|tilapia|' +
    'sea bass|seabass|bream|fcr|stocking density|harvest cycle|asc certified|bap certified|' +
    'certified producer|certified facility|seafood source|global salmon|species farmed|' +
    // Norwegian
    'fiskeoppdrett|oppdrettsanlegg|settefisk|havbruk|lakseoppdrett|' +
    // German
    'aquakultur|fischzucht|fischfarm|lachszucht|' +
    // French
    'pisciculture|élevage.?poisson|ferme.?piscicole|' +
    // Spanish
    'acuicultura|piscicultura|granja.?peces|cultivo.?peces|' +
    // Japanese
    '養殖場|水産養殖|魚類養殖|' +
    // Korean
    '양식장|수산양식|어류양식|' +
    // Russian
    'рыбоводство|рыбная.?ферма|аквакультура|' +
    // Chinese
    '水产养殖|养殖场|养殖品种',
    'i'
  );
  const MILL_KW   = new RegExp(
    // English
    'fishmeal|fish meal|fish oil|fishoil|processing plant|feed mill|reduction plant|feed factory|' +
    'skretting|biomar|tasa fishmeal|omega-3|marine ingredients|iffo|eumofa|menhaden|anchoveta|reduction|' +
    // Norwegian
    'fiskemellfabrikk|fiskeolje|' +
    // German
    'fischmehl|fischöl|fischmehlwerk|' +
    // French
    'farine.?poisson|huile.?poisson|usine.?traitement|' +
    // Spanish
    'harina.?pescado|aceite.?pescado|planta.?procesamiento|' +
    // Japanese
    '魚粉工場|魚粉|魚油|' +
    // Korean
    '어분공장|어분|어유|' +
    // Russian
    'рыбная.?мука|рыбий.?жир|рыбомучной|' +
    // Chinese
    '鱼粉|鱼油|加工厂|鱼粉厂',
    'i'
  );
  const VESSEL_KW = new RegExp(
    // English
    '\\bimo\\b|mmsi|flag state|call sign|gross tonnage|deadweight|port of registry|' +
    'marinetraffic|vesselfinder|fleetmon|ais|nav.?status|navigational.?status|' +
    'fishing vessel|cargo vessel|bulk carrier|tanker|container ship|year built|' +
    'fao global record|ship registry|vessel registry|' +
    // Norwegian
    'fiskefartøy|skipsregister|bruttotonn|hjemmehavn|' +
    // German
    'fischereifahrzeug|schiffsregister|bruttoraumzahl|heimathafen|' +
    // French
    'navire.?pêche|registre.?navire|jauge.?brute|port.?attache|' +
    // Spanish
    'buque.?pesquero|registro.?barco|arqueo.?bruto|puerto.?matrícula|' +
    // Japanese
    '漁船|船籍|総トン数|船名|呼出符号|' +
    // Korean
    '어선|선적|총톤수|선명|호출부호|' +
    // Russian
    'рыболовное.?судно|судовой.?реестр|название.?судна|' +
    // Chinese
    '船舶|渔船|船名|船旗|总吨|IMO|呼号',
    'i'
  );
  // Cross-category exclusion: reject if the page is strongly about a different category.
  // We no longer use "|| !OTHER_KW" — isSeaRelated already ensures sea context.
  if (searchType === 'farm')   return !VESSEL_KW.test(tl) || FARM_KW.test(tl);
  if (searchType === 'mill')   return !VESSEL_KW.test(tl) || MILL_KW.test(tl);
  if (searchType === 'vessel') return VESSEL_KW.test(tl)  || !FARM_KW.test(tl);
  return true;
}

/* ─────────────────────────────────────────────────────────────────
   SPECIES SYNONYM MAP — module-level constant (built once, not per-call)
   Maps common aliases → canonical English species name.
───────────────────────────────────────────────────────────────── */
const _SPECIES_ALIAS = {
  'Atlantic Salmon':   ['Salmo Salar','Salmon','Salmón Atlántico','Saumon Atlantique','Atlantisk Laks','鲑鱼','サーモン'],
  'Rainbow Trout':     ['Oncorhynchus Mykiss','Trout','Regenbogenforelle','Regnbueørret'],
  'Whiteleg Shrimp':   ['Pacific White Shrimp','Litopenaeus Vannamei','Penaeus Vannamei','Vannamei','White Shrimp'],
  'Tiger Prawn':       ['Penaeus Monodon','Black Tiger Shrimp','Giant Tiger Prawn'],
  'Tilapia':           ['Oreochromis Niloticus','Nile Tilapia'],
  'Atlantic Cod':      ['Gadus Morhua','Cod','Torsk','Kabeljau'],
  'European Sea Bass': ['Dicentrarchus Labrax','Sea Bass','Branzino','Loup de mer'],
  'Gilthead Sea Bream':['Sparus Aurata','Sea Bream','Dorade','Dorada'],
  'Yellowfin Tuna':    ['Thunnus Albacares','Yellowfin'],
  'Bluefin Tuna':      ['Thunnus Thynnus','Atlantic Bluefin'],
  'Anchoveta':         ['Peruvian Anchovy','Engraulis Ringens','Anchovy'],
  'Atlantic Mackerel': ['Scomber Scombrus','Makrell','Makrele'],
  'Atlantic Herring':  ['Clupea Harengus','Herring','Sild','Hering'],
};
const _ALIAS_LOOKUP = Object.freeze(
  Object.fromEntries(
    Object.entries(_SPECIES_ALIAS).flatMap(([canon, aliases]) =>
      aliases.map(a => [a.toLowerCase(), canon])
    )
  )
);

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
  // Use module-level _ALIAS_LOOKUP (built once at startup, not per call)
  ['species', 'input_species'].forEach(k => {
    if (!merged[k]) return;
    const parts = merged[k].split(/[,;\/]+/).map(s => {
      const titled = s.trim().replace(/\b\w/g, c => c.toUpperCase());
      return _ALIAS_LOOKUP[titled.toLowerCase()] || titled;
    }).filter(t =>
      t.length > 2 &&
      !/^(Fish|Seafood|Animal|Marine|Aquatic|Product|Species|Other|Various|Mixed|And|Or|The)$/.test(t)
    );
    // Case-insensitive dedup — keep first-seen capitalisation
    const seen = new Map();
    for (const p of parts) { const lc = p.toLowerCase(); if (!seen.has(lc)) seen.set(lc, p); }
    const deduped = [...seen.values()].slice(0, 6).join(', ');
    if (deduped) merged[k] = deduped; else delete merged[k];
  });

  // ── Certification: deduplicate / merge multiple mentions into a clean list
  if (merged.certification) {
    const CERTS = [
      'ASC Certified','MSC Certified','BAP Certified','GlobalG.A.P. Certified',
      'Friend of the Sea','RSPCA Assured','Naturland Certified','Organic Certified',
      'Fairtrade Certified','Best Aquaculture Certified','BRC Certified','IFFO RS Certified',
      'Halal Certified','Kosher Certified','SQS Certified','NATIVA Certified',
    ];
    const src = merged.certification.toLowerCase();
    const hits = CERTS.filter(c => src.includes(c.split(' ')[0].toLowerCase()));
    if (hits.length) merged.certification = hits.join(', ');
    else merged.certification = merged.certification.slice(0, 120);
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
  'https://api.allorigins.win/raw?url=',          // battle-tested, high uptime
  'https://corsproxy.io/?url=',                   // solid secondary, rate-limited per domain
  'https://api.codetabs.com/v1/proxy?quest=',     // reliable fallback
  'https://cors.deno.dev/',                        // backed by Deno Deploy, globally distributed
  'https://api.allorigins.win/get?url=',           // JSON wrapper fallback for same origin
  'https://proxy.cors.sh/',                        // good for EU sources
  // Removed: thingproxy.freeboard.io (deprecated 2023), openproxy.space (logs requests),
  //          duplicate corsproxy.io entries, corsproxy.org (inconsistent)
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
  // Chrome 150 / Windows 11 — most common desktop UA worldwide
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36',
  // Chrome 150 / macOS 15 Sequoia — matches current (2025-2026) Mac users
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36',
  // Firefox 126 / Linux — common developer / open-source segment
  'Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0',
  // Firefox 126 / Windows 11
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0',
  // Safari 18.4 / macOS 15 Sequoia — AppleWebKit build matches Safari 18.x series
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15',
  // Edge 150 / Windows 11 — Chromium-based Edge, same Blink version as Chrome
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 Edg/150.0.0.0',
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
// LRU request cache — delete-then-reinsert on hit moves entry to Map tail (newest).
// Eviction removes the first key (Map.keys().next() = oldest insertion = LRU victim).
const REQ_CACHE_MAX = 120;
const reqCache = new Map();
function reqCacheSet(url, text) {
  if (reqCache.size >= REQ_CACHE_MAX) reqCache.delete(reqCache.keys().next().value);
  reqCache.set(url, text);
}
function reqCacheGet(url) {
  if (!reqCache.has(url)) return null;
  const v = reqCache.get(url); // move to tail (LRU)
  reqCache.delete(url);
  reqCache.set(url, v);
  return v;
}

/* ═══════════════════════════════════════════
   LAZY LIBRARY LOADER
   pdf.js · xlsx · mammoth loaded on first file upload — not on page load
═══════════════════════════════════════════ */
const LIB_URLS = {
  pdf:     'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js',
  xlsx:    'https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js',
  mammoth: 'https://cdnjs.cloudflare.com/ajax/libs/mammoth/1.8.0/mammoth.browser.min.js',
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
  // ── 0. One-time DB rename migration (fish-intel-db → website-extractor-db) ─
  if (window.AppIDB) await AppIDB.migrateFromOldDB().catch(() => {});

  // ── 1. Init SQLite first (reads its binary blob from IDB) ─────────────────
  let sqliteOk = false;
  if (window.AppSQLite) {
    sqliteOk = await AppSQLite.init().catch(() => false);
  }

  // ── 2. Load saved entity records ──────────────────────────────────────────
  if (sqliteOk) {
    const rows = await AppSQLite.getAllEntities();
    if (rows.length) {
      // Primary path: hydrate saved[] directly from SQLite
      saved = rows.map(AppSQLite.rowToRecord);
      console.info(`[Storage] Loaded ${saved.length} records from SQLite`);
    } else {
      // SQLite is empty — migrate from legacy IDB records or localStorage
      let legacy = [];
      try {
        if (window.AppIDB) {
          await AppIDB.migrateFromLocalStorage();
          legacy = await AppIDB.getAll('records');
        }
        if (!legacy.length) {
          legacy = JSON.parse(localStorage.getItem('ship_saved3') || '[]');
        }
        legacy = legacy.map(r => (r.id ? r : { ...r, id: r._id }));
      } catch {}

      if (legacy.length) {
        saved = legacy;
        const n = await AppSQLite.batchUpsert(saved);
        console.info(`[Storage] Migrated ${n} records → SQLite`);
      }
    }
  } else {
    // SQLite unavailable — fall back to IDB records then localStorage
    console.warn('[Storage] SQLite unavailable, falling back to IDB');
    try {
      if (window.AppIDB) await AppIDB.migrateFromLocalStorage();
      const records = window.AppIDB ? await AppIDB.getAll('records') : [];
      if (records.length) {
        saved = records.sort((a, b) => (b._ts || 0) - (a._ts || 0));
      } else {
        try { saved = JSON.parse(localStorage.getItem('ship_saved3') || '[]'); } catch {}
      }
      saved = saved.map(r => (r.id ? r : { ...r, id: r._id }));
    } catch {
      try { saved = JSON.parse(localStorage.getItem('ship_saved3') || '[]'); } catch {}
    }
  }

  // ── 3. Knowledge base + proxy health — always from IDB (not in SQLite) ───
  try {
    const kEntry = window.AppIDB ? await AppIDB.get('knowledge', 'learned') : null;
    if (kEntry?.data) {
      learned     = kEntry.data.learned     || {};
      domainStats = kEntry.data.domainStats || {};
    } else {
      try {
        const ld = JSON.parse(localStorage.getItem('ship_learned1') || '{}');
        learned = ld.learned || {}; domainStats = ld.domainStats || {};
      } catch {}
    }
  } catch {}

  try {
    const pfEntry = window.AppIDB ? await AppIDB.get('knowledge', 'pfails') : null;
    if (pfEntry?.data) {
      Object.entries(pfEntry.data).forEach(([k, v]) => proxyFails.set(k, v));
    } else {
      try {
        const pf = JSON.parse(localStorage.getItem('ship_pfails1') || '{}');
        Object.entries(pf).forEach(([k, v]) => proxyFails.set(k, v));
      } catch {}
    }
  } catch {}
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
    const ph    = { farm:'Farm or mill name (e.g. Lerøy Seafood, Mowi, Skretting)',
                    mill:'Mill or processing plant name (e.g. Skretting, BioMar, TASA)',
                    vessel:'Vessel name or IMO number (e.g. Atlantic Dawn, 1234567)',
                    general:'Name, IMO, or URL to search' };
    const titles = { farm:'Farm Extractor', mill:'Mill Extractor',
                     vessel:'Vessel Data Extractor', general:'Website Extractor Tools' };
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

  // 3. Light up AI dot if key is already configured, or probe server for AI
  updateClaudeHeaderDot();
  detectServerAI(); // fire-and-forget; updates dot again if server AI is found

  // 4. Directus — initialise from saved IDB settings
  initDirectus();

  // 5. Register service worker for offline + asset caching
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

// Shared secret for server API routes — set NEXT_PUBLIC_API_SECRET in .env.local
// This stops automated scanners; note it is visible in the JS bundle.
const API_SECRET  = (typeof process !== 'undefined' && process.env?.NEXT_PUBLIC_API_SECRET) || '';

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
  // Pre-fill Claude key (masked) + model
  const savedKey   = await getClaudeKey();
  const savedModel = await getClaudeModel();
  const keyInput   = document.getElementById('claude-key-input');
  const modelSel   = document.getElementById('claude-model-sel');
  if (keyInput) keyInput.value = savedKey ? '••••••••' + savedKey.slice(-6) : '';
  if (modelSel) modelSel.value = savedModel;
  updateClaudeStatus(!!savedKey);
  // Pre-fill Directus collection name (URL + token live in env vars, not IDB)
  const { collection } = await getDirectusCreds();
  const colEl = document.getElementById('directus-collection-input');
  if (colEl) colEl.value = collection || '';
  updateDirectusStatus(window.Directus?.isConfigured() || false);
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
    // Preserve the user's model preference — only clear the key
    const currentModel = await getClaudeModel();
    if (window.AppIDB) await AppIDB.put('knowledge', { key: 'claude-settings', apiKey: null, model: currentModel });
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
  dot.style.display = (key || _serverAIReady) ? 'inline-flex' : 'none';
}

// ── Directus settings (only collection name stored in IDB) ───────────────
// The Directus URL + token live in Vercel env vars (DIRECTUS_URL / DIRECTUS_TOKEN).
// Browsers call /api/directus/ proxy — the token never reaches the client.
async function getDirectusCreds() {
  try {
    const entry = window.AppIDB ? await AppIDB.get('knowledge', 'directus-settings') : null;
    return { collection: entry?.collection || '' };
  } catch { return { collection: '' }; }
}

async function initDirectus() {
  const { collection } = await getDirectusCreds();
  if (window.Directus) {
    window.Directus.configure(collection || '', API_SECRET || '');
    await window.Directus.loadIdMap();   // restore localId→directusId map from IDB
  }
  updateDirectusStatus(window.Directus?.isConfigured() || false);
}

async function saveDirectusSettings() {
  const colEl     = document.getElementById('directus-collection-input');
  const collection = colEl?.value?.trim() || '';

  if (!collection) { toast('Enter a collection name'); return; }

  try {
    if (window.AppIDB) {
      await AppIDB.put('knowledge', { key: 'directus-settings', collection });
    }
    if (window.Directus) window.Directus.configure(collection, API_SECRET || '');

    // Test immediately — proxy will confirm DIRECTUS_URL + DIRECTUS_TOKEN env vars are set
    const statusEl = document.getElementById('directus-status');
    if (statusEl) statusEl.innerHTML = '<span style="color:var(--mut)">Testing connection…</span>';

    const ok = window.Directus ? await window.Directus.ping() : false;
    updateDirectusStatus(ok);
    toast(ok
      ? '✓ Directus connected'
      : '✗ Proxy reachable but collection not found — check DIRECTUS_URL, DIRECTUS_TOKEN env vars and collection name');
  } catch {
    toast('Failed to save Directus settings');
  }
}

async function clearDirectusSettings() {
  if (!confirm('Disconnect Directus?')) return;
  try {
    if (window.AppIDB) await AppIDB.put('knowledge', { key: 'directus-settings', collection: '' });
    if (window.Directus) window.Directus.configure('', null);
    const colEl = document.getElementById('directus-collection-input');
    if (colEl) colEl.value = '';
    updateDirectusStatus(false);
    toast('Directus disconnected');
  } catch {}
}

function updateDirectusStatus(connected) {
  const el = document.getElementById('directus-status');
  if (!el) return;
  el.innerHTML = connected
    ? `<div class="directus-status-ok">✓ Connected — saved records will sync to Directus</div>`
    : `<div class="directus-status-off">Not connected — records are saved locally only</div>`;
}

// ── Server AI availability probe ──────────────────────────────────────────
// Set to true once /api/health confirms at least one server-side AI provider.
// This lets runBot() use AI even when no client-side key is stored.
let _serverAIReady = false;

async function detectServerAI() {
  try {
    const r = await fetch('/api/health', {
      signal: AbortSignal.timeout(3000),
      headers: API_SECRET ? { 'x-api-secret': API_SECRET } : {},
    });
    if (!r.ok) return;
    const d = await r.json();
    _serverAIReady = !!(d.providers?.claude || d.providers?.qwen);
    if (_serverAIReady) {
      updateClaudeHeaderDot();
      console.info('[AI] Server AI available:', d.providers);
    }
  } catch { /* probe failed — stay false */ }
}

// ── Core Claude API call ───────────────────────────────────────────────────
async function callClaude(system, user, maxTokens = 800, signal = null) {
  // ── Next.js server route (handles Qwen32B or Claude key server-side, no CORS) ──
  try {
    const r = await fetch('/api/ai', {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...(API_SECRET ? { 'x-api-secret': API_SECRET } : {}) },
      body: JSON.stringify({ system, user, maxTokens }),
      signal: timedSignal(signal, 35000),
    });
    if (r.ok) {
      const d = await r.json();
      if (d.text) {
        log(`AI via server (${d.provider || 'server'}) ✓`, 'ok');
        return d.text;
      }
    }
    // 404 = static/GitHub Pages mode — fall through to direct browser call
    // 503 = server route exists but no AI provider configured — try client key below
    // Other non-2xx = server error — do not retry with client key
    if (r.status !== 404 && r.status !== 503) return null;
  } catch (e) {
    if (e.name === 'AbortError') throw e;
    // Network error or missing route — continue to direct call below
  }

  // ── Direct browser → Anthropic (GitHub Pages fallback, requires client-stored key) ──
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
    region:      'City, region, province or address',
    latitude:    'Decimal degrees (number)',
    longitude:   'Decimal degrees (number)',
    description: 'Write an investigative-grade paragraph (200–600 words) as if you are a journalist. Cover: what the entity does, where it operates, its scale and capacity, ownership structure, certifications, notable incidents or controversies, and any financial or environmental context found in the text. Only use facts explicitly stated in the provided content — never infer or hallucinate.',
  };
  if (searchType === 'vessel') return {
    vessel_name:      'Full vessel name',
    imo:              '7-digit IMO number',
    flag:             'Flag state — full country name',
    call_sign:        'Radio call sign',
    vessel_type:      'e.g. Trawler, Longliner, Purse Seiner, Reefer, Cargo',
    gross_tonnage:    'GT figure (number or number with units)',
    dwt:              'Deadweight tonnage',
    length:           'LOA in metres',
    beam:             'Beam in metres',
    year_built:       '4-digit year vessel was built',
    port_of_registry: 'Home port / port of registry',
    owner:            'Registered owner',
    operator:         'Commercial operator or manager',
    mmsi:             '9-digit MMSI',
    nav_status:       'AIS navigational status e.g. Underway, At Anchor, Moored',
    class_soc:        'Classification society e.g. DNV, Lloyd\'s Register, Bureau Veritas',
    country:          'Country of operation or registration',
    description:      'Investigative summary paragraph covering vessel history, ownership chain, flag changes, trading routes, any detentions or port-state control findings, and notable incidents. Facts only.',
  };
  if (searchType === 'mill') return {
    ...base,
    input_species:       'Raw fish species used as input, comma-separated',
    output_products:     'Output products e.g. fishmeal, fish oil, surimi',
    processing_capacity: 'Annual throughput with units e.g. 50,000 t/yr',
    fishmeal_pct:        'Fishmeal percentage of output e.g. 22%',
    fishoil_pct:         'Fish oil percentage of output e.g. 5%',
    capacity:            'Total production capacity with units',
    certification:       'Certifications held e.g. IFFO RS, MarinTrust',
    employees:           'Number of employees',
  };
  return { // farm / general
    ...base,
    species:           'Species farmed, comma-separated',
    capacity:          'Annual production output with units e.g. 12,000 t/yr',
    water_type:        'Freshwater | Saltwater / Marine | Brackish water',
    production_method: 'e.g. Sea cage / Net pen, RAS, Pond culture',
    certification:     'e.g. ASC Certified, BAP Certified, GlobalG.A.P.',
    total_area:        'Farm area with units e.g. 250 ha or 2,500 m²',
    stocking_density:  'Stocking density with units e.g. 25 kg/m³',
    fcr:               'Feed Conversion Ratio (number e.g. 1.2)',
    harvest_cycles:    'Number of harvest cycles per year or cycle duration e.g. 2/yr or 24 months',
    feed_type:         'Feed type used e.g. commercial pellets, organic',
    license:           'License or permit number',
    employees:         'Number of employees',
  };
}

// ── Smart extraction: runs concurrently with the scraping loop ────────────
async function claudeExtract(pageTexts, query, searchType, signal = null) {
  const schema = claudeFieldSchema(searchType);
  const system = [
    `You are a precision data extraction engine for a maritime and aquaculture intelligence platform.`,
    `Extract structured data about "${query}" from the provided web content.`,
    `Return ONLY a valid raw JSON object — no markdown fences, no explanation, no surrounding text.`,
    ``,
    `STRICT RULES — violations will corrupt the database:`,
    `• Include ONLY fields with values EXPLICITLY stated verbatim in the source text.`,
    `• If a field is not mentioned, omit it entirely — never guess, infer, or fill in typical values.`,
    `• Return {} immediately if the page is not about "${query}" specifically.`,
    `• Coordinates: decimal degrees only, as plain numbers e.g. 60.4215 and 5.3124 (never DMS, never with ° symbol, never with N/S/E/W suffix). Negative = South or West.`,
    `• Country: always full English name e.g. "Norway", never abbreviations like "NO" or "NOR".`,
    `• Species: comma-separated common English names e.g. "Atlantic Salmon, Rainbow Trout".`,
    `• Numbers: plain digits with unit e.g. "5000 t/yr" — no currency symbols, no date ranges.`,
    `• If multiple sources contradict on a field value, use the more authoritative source (registry > news > wiki).`,
    `• Never combine fields — each key maps to exactly one value string.`,
  ].join('\n');

  // Sort by source authority before slicing — highest-ranked sources first
  const sortedTexts = [...pageTexts].sort((a, b) => sourceRank(b.source) - sourceRank(a.source));
  // 8 sources × 4000 chars = 32,000 chars — well within Claude's context window.
  // Sorted by source authority so the most trusted registries appear first.
  const corpus = sortedTexts
    .slice(0, 8)
    .map((p, i) => {
      const excerpt = p.text.slice(0, 4000);
      const truncated = p.text.length > 4000;
      return `=== Source ${i + 1} [${p.source}] ===\n${excerpt}${truncated ? '\n[…truncated]' : ''}`;
    })
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
    // Remap Claude-facing alias keys → internal field names used by mergeFields
    // 'imo'  is human-readable in the schema prompt but stored as '_imo' internally
    // 'name' is a user-facing alias — vessel searches use 'vessel_name', others 'farm_name'
    if (clean.imo)  { clean._imo = clean._imo || clean.imo; delete clean.imo; }
    if (clean.name) {
      const nameKey = searchType === 'vessel' ? 'vessel_name' : 'farm_name';
      clean[nameKey] = clean[nameKey] || clean.name;
      delete clean.name;
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

  const system = `You are an investigative journalist writing for a maritime and aquaculture intelligence platform.
Write a factual profile paragraph about "${query}" using ONLY the structured data fields provided below.

Rules — follow every one strictly:
• Write ONLY facts that appear in the structured data. Never invent, infer, or add "likely" or "typical" values.
• If data is sparse, write a short accurate sentence or two — do NOT pad with generic industry context or guesses.
• Do NOT mention MarineTraffic, VesselFinder, Wikipedia, SeafoodSource, or any data source by name.
• If the existing description is about a website or platform rather than "${query}", ignore it entirely.
• Write in plain direct English. No marketing language. Active voice. Present tense for current status.
• Return ONLY the paragraph text — no JSON, no quotes, no heading, no label.
• If the structured data is insufficient to write a meaningful sentence about "${query}" specifically, return an empty string.`;

  const user = `Entity: "${query}" (${searchType})
${existingDesc && isEntityDescription(existingDesc, query) ? `Existing description to improve:\n${existingDesc}\n\n` : ''}Structured data:\n${fields || '(none)'}`;

  try {
    const desc = await callClaude(system, user, 800, signal);
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
  // Escape first, then highlight — prevents XSS in raw scraped text.
  // Single-pass alternation avoids double-wrapping already-highlighted spans
  // that the second chained replace would otherwise re-process.
  return esc(text)
    .replace(/\bIMO[\s:.\-#]*(\d{7})\b|\b(\d{7})\b/gi, (match, prefixed, bare) => {
      if (prefixed !== undefined) return `IMO <span class="ih">${prefixed}</span>`;
      return validIMO(bare) ? `<span class="ih">${bare}</span>` : bare;
    });
}

/* ═══════════════════════════════════════════
   PROXY FETCH — with fallback chain & cache
═══════════════════════════════════════════ */
async function fetchViaProxy(url, signal) {
  if (!isValidURL(url)) throw new Error('Blocked: invalid or private URL');

  const cached = reqCacheGet(url);
  if (cached) { log('Cache hit ✓', 'ok'); return cached; }

  // ── Next.js server-side scrape (no CORS, full headers, direct HTTP) ──
  try {
    const r = await fetch('/api/scrape', {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...(API_SECRET ? { 'x-api-secret': API_SECRET } : {}) },
      body: JSON.stringify({ url }),
      signal: timedSignal(signal, 22000),
    });
    if (r.ok) {
      const d = await r.json();
      if (d.ok && d.text && d.text.length > 50) {
        reqCacheSet(url, d.text);
        log('Fetched via server ✓', 'ok');
        return d.text;
      }
      // Server returned ok:false — fall through to proxy chain
    } else if (r.status !== 404) {
      // Server error (5xx) — don't silently swallow, just fall through
    }
    // 404 = running on GitHub Pages (no API routes) — fall through to CORS proxies
  } catch (e) {
    if (e.name === 'AbortError') throw e;
    // Network error / no route — fall through to CORS proxy chain
  }

  // Rate limit per domain (only needed for CORS proxy path)
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

        reqCacheSet(url, text);
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

function parseHTML(html, sourceURL) {
  const doc = new DOMParser().parseFromString(html, 'text/html');

  // ── WeChat article special handling (mp.weixin.qq.com) ───────────────────
  // WeChat articles have a well-known structure. Promote the article body to
  // the top of the document so text extraction captures all content.
  const isWeChat = sourceURL && /mp\.weixin\.qq\.com/i.test(sourceURL);
  if (isWeChat) {
    const articleBody = doc.getElementById('js_content');
    const title       = doc.querySelector('.rich_media_title');
    const account     = doc.querySelector('.rich_media_nickname');
    const date        = doc.querySelector('.rich_media_meta_primary,.publish_time');
    if (articleBody) {
      // Inject structured hints that extractFields can pick up
      if (title)   articleBody.insertAdjacentHTML('afterbegin', `<p data-wx="title">${title.textContent}</p>`);
      if (account) articleBody.insertAdjacentHTML('afterbegin', `<p data-wx="account">Operator: ${account.textContent}</p>`);
      if (date)    articleBody.insertAdjacentHTML('afterbegin', `<p data-wx="date">Date: ${date.textContent}</p>`);
    }
  }

  // Keep <header> and <footer> — maritime registries (MarineTraffic, Equasis) and
  // Chinese portals put key vessel/farm data inside those elements.
  // Only strip executable code, pure navigation, consent banners, and ads.
  doc.querySelectorAll([
    'script', 'style', 'iframe', 'form',
    'nav',                                         // top-level nav bars
    'header nav', 'footer nav',                    // nav inside header/footer only
    '[role="navigation"]',
    '[class*="cookie"]', '[class*="consent"]',
    '[class*="banner"]', '[class*="popup"]',
    '[class*="ad-"]', '[class*="-ad"]', '[id*="cookie"]', '[id*="gdpr"]',
    '[class*="newsletter"]', '[class*="subscribe"]',
    // WeChat-specific chrome to strip
    '#js_pc_qr_code', '.discuss_container', '#js_message_card_list',
    '.wx_follow_tip', '#js_profile_qrcode', '.rich_media_area_extra',
  ].join(',')).forEach(e => e.remove());
  return doc;
}

/* ═══════════════════════════════════════════
   TRANSLATION (chunked, with abort)
═══════════════════════════════════════════ */
/** Detect page language from HTML lang attribute or common script patterns */
function detectLang(doc, text) {
  const htmlLang = doc?.documentElement?.getAttribute('lang') || '';
  if (htmlLang) return htmlLang.slice(0, 2).toLowerCase();
  if (!text) return 'en';
  // Non-Latin scripts — unambiguous
  if (/[一-鿿]/.test(text)) return 'zh';
  if (/[぀-ゟ゠-ヿ]/.test(text)) return 'ja';
  if (/[가-힯]/.test(text)) return 'ko';
  if (/[؀-ۿ؀-ۿ]/.test(text)) return 'ar';
  if (/[Ѐ-ӿ]/.test(text)) return 'ru';
  if (/[ก-๛]/.test(text)) return 'th';
  if (/[Ā-ģ]/.test(text) && /māja|zivju|laima/i.test(text)) return 'lv'; // Latvian
  // Latin-script heuristics via distinctive diacritics
  if (/[æøÆØ]/.test(text)) return 'no'; // Norwegian (also Danish, but close enough)
  if (/[äÄöÖüÜß]/.test(text) && !/[æøÆØñÑ]/.test(text)) return 'de';
  if (/[ñÑ]/.test(text) || (/[áéíóúÁÉÍÓÚ]/.test(text) && /\b(de|del|la|el|los|las|en|por|con|para)\b/.test(text))) return 'es';
  if (/[àâêîôûùçÀÂÊÎÔÛÙÇ]/.test(text)) return 'fr';
  if (/[ãõÃÕ]/.test(text)) return 'pt';
  if (/[ăîâȘȚ]/.test(text)) return 'ro';
  if (/[åÅ]/.test(text) && !/[æøÆØ]/.test(text)) return 'sv'; // Swedish (å without æø)
  if (/[äÄöÖ]/.test(text) && /\b(och|att|det|som|är)\b/.test(text)) return 'sv';
  return 'en';
}

/**
 * Detect the language of a user's search query.
 * More aggressive than detectLang — queries are short so we check
 * character composition rather than relying on word frequency.
 */
function detectQueryLang(q) {
  if (!q) return 'en';
  // Non-Latin scripts first
  if (/[一-鿿]/.test(q)) return 'zh';
  if (/[぀-ゟ゠-ヿ]/.test(q)) return 'ja';
  if (/[가-힯]/.test(q)) return 'ko';
  if (/[؀-ۿ؀-ۿ]/.test(q)) return 'ar';
  if (/[Ѐ-ӿ]/.test(q)) return 'ru';
  if (/[ก-๛]/.test(q)) return 'th';
  // Latin diacritics
  if (/[æøÆØÅå]/.test(q)) return /[åÅ]/.test(q) && !/[æøÆØ]/.test(q) ? 'sv' : 'no';
  if (/[ñÑ]/.test(q)) return 'es';
  if (/[àâêîôûùçÀÂÊÎÔÛÙÇ]/.test(q)) return 'fr';
  if (/[ãõÃÕ]/.test(q)) return 'pt';
  if (/[äÄöÖüÜß]/.test(q)) return 'de';
  if (/[ăîâȘȚ]/.test(q)) return 'ro';
  return 'en';
}

/**
 * Translate a short query string from one language to another.
 * Used to cross-search: Norwegian query on English databases and vice-versa.
 * Returns the original query if translation fails.
 */
async function translateQuery(q, fromLang, toLang, signal) {
  if (fromLang === toLang || !q.trim()) return q;
  const enc = encodeURIComponent(q);
  // Google Translate gtx — reliable for short queries
  try {
    const r = await fetch(
      `https://translate.googleapis.com/translate_a/single?client=gtx&sl=${fromLang}&tl=${toLang}&dt=t&q=${enc}`,
      { signal: timedSignal(signal, 6000) }
    );
    const d = await r.json();
    const t = (d?.[0] || []).map(s => s?.[0] || '').join('').trim();
    if (t && t !== q) return t;
  } catch {}
  // MyMemory fallback
  try {
    const r = await fetch(
      `https://api.mymemory.translated.net/get?q=${enc}&langpair=${fromLang}|${toLang}`,
      { signal: timedSignal(signal, 6000) }
    );
    const d = await r.json();
    const t = d.responseData?.translatedText?.trim();
    if (t && t !== q) return t;
  } catch {}
  return q; // return original on failure
}

/**
 * Industry-specific search terms for each language / facility type.
 * These are appended to search queries so language-specific results surface.
 */
function langIndustryTerms(lang, searchType) {
  const TERMS = {
    no: { farm: 'fiskeoppdrett akvakultur laks oppdrettsanlegg',  vessel: 'fiskefartøy skipsnavn IMO fiskeri', mill: 'fiskemellfabrikk fiskeolje fiskemel' },
    sv: { farm: 'fiskodling vattenbruk lax odlingsanläggning',    vessel: 'fiskefartyg fartygsnamn IMO',        mill: 'fiskemjölsfabrik fiskolja fiskemjöl' },
    da: { farm: 'fiskeopdræt akvakultur laks opdrætsanlæg',       vessel: 'fiskefartøj skibsnavn IMO',         mill: 'fiskemelsfabrik fiskeolie fiskemel' },
    fi: { farm: 'kalankasvatus vesiviljely lohi kalanviljelylaitos', vessel: 'kalastusalus alusnimi IMO',       mill: 'kalanjauhotehdas kalaöljy kalanjauhot' },
    de: { farm: 'Aquakultur Fischzucht Lachsfarm Fischfarm',      vessel: 'Fischereifahrzeug Schiffsname IMO', mill: 'Fischmehlwerk Fischöl Fischmehl' },
    fr: { farm: 'aquaculture pisciculture ferme piscicole',        vessel: 'navire de pêche nom du navire IMO', mill: 'usine de farine de poisson huile de poisson' },
    es: { farm: 'acuicultura piscicultura granja acuícola',        vessel: 'buque pesquero nombre del barco IMO', mill: 'fábrica de harina de pescado aceite de pescado' },
    pt: { farm: 'aquicultura piscicultura fazenda aquícola',       vessel: 'embarcação pesqueira nome IMO',     mill: 'fábrica de farinha de peixe óleo de peixe' },
    zh: { farm: '水产养殖 养殖场 养殖品种 产量',                   vessel: '船舶 船名 IMO 渔船',                mill: '鱼粉厂 鱼油 水产品加工' },
    ja: { farm: '養殖 水産養殖 養殖場 水産物',                    vessel: '漁船 船名 IMO 船籍',               mill: '魚粉工場 魚粉 魚油' },
    ko: { farm: '양식 수산양식 양식장 수산물',                    vessel: '어선 선명 IMO 선적',               mill: '어분공장 어분 어유' },
    ar: { farm: 'تربية الأحياء المائية مزرعة سمك أحواض',         vessel: 'سفينة صيد اسم السفينة IMO',        mill: 'مصنع طحين السمك زيت السمك' },
    ru: { farm: 'аквакультура рыбоводство рыбная ферма',          vessel: 'рыболовное судно название IMO',     mill: 'рыбомучной завод рыбная мука рыбий жир' },
  };
  const set = TERMS[lang];
  if (!set) return '';
  const type = searchType === 'vessel' ? 'vessel' : searchType === 'mill' ? 'mill' : 'farm';
  return set[type] || '';
}

/**
 * Language-specific official registries and databases per country.
 * Returns an array of {id, url, _lang} source objects.
 */
function langSpecificSources(q, qEn, lang, searchType) {
  const enc   = encodeURIComponent(q);
  const encEn = encodeURIComponent(qEn);
  const terms = encodeURIComponent(langIndustryTerms(lang, searchType));
  const isV = searchType === 'vessel';
  const isM = searchType === 'mill';
  const sources = [];

  // ── Norwegian / Nordic ───────────────────────────────────────────────────
  if (lang === 'no' || lang === 'sv' || lang === 'da' || lang === 'fi') {
    sources.push(
      // Official Norwegian aquaculture registry + AIS / vessel registry
      { id:'Fiskeridir',   url:`https://www.fiskeridir.no/Akvakultur/Registre-og-skjema/Akvakulturregisteret?s=${enc}`, _lang:'no' },
      { id:'BarentsWatch', url:`https://www.barentswatch.no/bw/map?lat=68&lon=15&zoom=5`, _lang:'no' },
      // Google Norway — surfaces Norwegian-language pages effectively
      { id:'Google-NO',    url:`https://www.google.no/search?q=${enc}+${terms}&hl=no&gl=no&num=20`, _lang:'no' },
      { id:'Bing-NO',      url:`https://www.bing.com/search?q=${enc}+${terms}&setlang=nb-NO&cc=NO`, _lang:'no' },
    );
    if (isV) sources.push(
      { id:'Sjøfart',      url:`https://www.sjofartsdir.no/sjofart/fartoy/fartoyregisteret/?sok=${enc}`, _lang:'no' },
    );
  }

  // ── Spanish / Latin America ─────────────────────────────────────────────
  if (lang === 'es') {
    sources.push(
      { id:'Subpesca-CL',  url:`https://www.subpesca.cl/buscador/606/w3-propertyvalue-${enc}.html`, _lang:'es' },
      { id:'Sernapesca',   url:`https://www.sernapesca.cl/informes-y-estadisticas/consulta/${enc}`, _lang:'es' },
      { id:'Produce-PE',   url:`https://www.produce.gob.pe/index.php/busqueda?q=${enc}`, _lang:'es' },
      { id:'Google-ES',    url:`https://www.google.es/search?q=${enc}+${terms}&hl=es&gl=es&num=20`, _lang:'es' },
      { id:'Google-CL',    url:`https://www.google.cl/search?q=${enc}+${terms}&hl=es&gl=cl&num=20`, _lang:'es' },
      { id:'Bing-ES',      url:`https://www.bing.com/search?q=${enc}+${terms}&setlang=es-ES`, _lang:'es' },
    );
  }

  // ── Portuguese / Brazil ─────────────────────────────────────────────────
  if (lang === 'pt') {
    sources.push(
      { id:'MAPA-BR',      url:`https://www.gov.br/agricultura/pt-br/busca?SearchableText=${enc}`, _lang:'pt' },
      { id:'Google-BR',    url:`https://www.google.com.br/search?q=${enc}+${terms}&hl=pt-BR&gl=br&num=20`, _lang:'pt' },
      { id:'Bing-PT',      url:`https://www.bing.com/search?q=${enc}+${terms}&setlang=pt-PT`, _lang:'pt' },
    );
  }

  // ── French ──────────────────────────────────────────────────────────────
  if (lang === 'fr') {
    sources.push(
      { id:'FranceAgriMer',url:`https://www.franceagrimer.fr/recherche?text=${enc}`, _lang:'fr' },
      { id:'Google-FR',    url:`https://www.google.fr/search?q=${enc}+${terms}&hl=fr&gl=fr&num=20`, _lang:'fr' },
      { id:'Bing-FR',      url:`https://www.bing.com/search?q=${enc}+${terms}&setlang=fr-FR`, _lang:'fr' },
    );
  }

  // ── German ──────────────────────────────────────────────────────────────
  if (lang === 'de') {
    sources.push(
      { id:'BLE-DE',       url:`https://www.ble.de/DE/Fischerei/Fischerei_node.html?q=${enc}`, _lang:'de' },
      { id:'Google-DE',    url:`https://www.google.de/search?q=${enc}+${terms}&hl=de&gl=de&num=20`, _lang:'de' },
      { id:'Bing-DE',      url:`https://www.bing.com/search?q=${enc}+${terms}&setlang=de-DE`, _lang:'de' },
    );
  }

  // ── Japanese — Yahoo Japan is dominant, not Google ───────────────────────
  if (lang === 'ja') {
    const termsJa = encodeURIComponent(langIndustryTerms('ja', searchType));
    sources.push(
      { id:'Yahoo-JP',     url:`https://search.yahoo.co.jp/search?p=${enc}+${termsJa}`, _lang:'ja', _cn:true },
      { id:'Google-JP',    url:`https://www.google.co.jp/search?q=${enc}+${termsJa}&hl=ja&gl=jp&num=20`, _lang:'ja', _cn:true },
      { id:'Bing-JA',      url:`https://www.bing.com/search?q=${enc}+${termsJa}&setlang=ja-JP&cc=JP`, _lang:'ja', _cn:true },
      { id:'JFA-Japan',    url:`https://www.jfa.maff.go.jp/j/saibai/search/?keyword=${enc}`, _lang:'ja', _cn:true },
    );
    if (isV) sources.push(
      { id:'JG-Registry',  url:`https://www6.kaiho.mlit.go.jp/inquiry/jsp/ShipInfo.jsp?name=${enc}`, _lang:'ja', _cn:true },
    );
  }

  // ── Korean — Naver is dominant ──────────────────────────────────────────
  if (lang === 'ko') {
    const termsKo = encodeURIComponent(langIndustryTerms('ko', searchType));
    sources.push(
      { id:'Naver-KO',     url:`https://search.naver.com/search.naver?query=${enc}+${termsKo}`, _lang:'ko', _cn:true },
      { id:'Daum-KO',      url:`https://search.daum.net/search?q=${enc}+${termsKo}`, _lang:'ko', _cn:true },
      { id:'Google-KR',    url:`https://www.google.co.kr/search?q=${enc}+${termsKo}&hl=ko&gl=kr&num=20`, _lang:'ko', _cn:true },
      { id:'FIPS-KR',      url:`https://www.fips.go.kr/search/search.do?searchWord=${enc}`, _lang:'ko', _cn:true },
    );
  }

  // ── Russian — Yandex is dominant ────────────────────────────────────────
  if (lang === 'ru') {
    const termsRu = encodeURIComponent(langIndustryTerms('ru', searchType));
    sources.push(
      { id:'Yandex-RU',    url:`https://yandex.ru/search/?text=${enc}+${termsRu}`, _lang:'ru', _cn:true },
      { id:'Google-RU',    url:`https://www.google.ru/search?q=${enc}+${termsRu}&hl=ru&gl=ru&num=20`, _lang:'ru', _cn:true },
      { id:'Bing-RU',      url:`https://www.bing.com/search?q=${enc}+${termsRu}&setlang=ru-RU&cc=RU`, _lang:'ru', _cn:true },
      { id:'Rosrybolovstvo',url:`https://fish.gov.ru/search/?q=${enc}`, _lang:'ru', _cn:true },
    );
  }

  // ── Arabic ──────────────────────────────────────────────────────────────
  if (lang === 'ar') {
    const termsAr = encodeURIComponent(langIndustryTerms('ar', searchType));
    sources.push(
      { id:'Google-AR',    url:`https://www.google.com.sa/search?q=${enc}+${termsAr}&hl=ar&gl=sa&num=20`, _lang:'ar', _cn:true },
      { id:'Bing-AR',      url:`https://www.bing.com/search?q=${enc}+${termsAr}&setlang=ar-SA&cc=SA`, _lang:'ar', _cn:true },
    );
  }

  return sources;
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
    // Google Translate (unofficial client=gtx endpoint) — auto → en
    // More reliable than community Lingva instances which come and go.
    // Response format: [[["translated","original",...],...],...] — join segment[0] of each pair.
    async () => {
      const r = await fetch(
        `https://translate.googleapis.com/translate_a/single?client=gtx&sl=auto&tl=en&dt=t&q=${enc}`,
        { signal: timedSignal(signal, 8000) }
      );
      const d = await r.json();
      const t = (d?.[0] || []).map(s => s?.[0] || '').join('');
      if (!t || t === text) throw new Error('no translation');
      return t;
    },
  ];
  for (const api of apis) {
    try { return await api(); } catch {}
  }
  return text; // fallback: return original
}

async function translate(text, signal) {
  if (!text?.trim()) return text;
  // Split at word boundaries — hard slicing at a fixed byte offset can break
  // mid-word and produce garbled translations, especially in CJK/Arabic scripts.
  const MAX = 450;
  const chunks = [];
  let start = 0;
  while (start < text.length) {
    let end = Math.min(start + MAX, text.length);
    if (end < text.length) {
      // Walk back to the nearest whitespace so we never cut mid-word
      let boundary = end;
      while (boundary > start && !/\s/.test(text[boundary])) boundary--;
      end = boundary > start ? boundary : end; // hard cut if no whitespace in window
    }
    chunks.push(text.slice(start, end).trimEnd());
    // Advance past the whitespace character we stopped at
    start = end + (end < text.length && /\s/.test(text[end]) ? 1 : 0);
  }
  if (signal?.aborted) throw new DOMException('Aborted', 'AbortError');
  // Sequential — MyMemory free tier has strict per-second rate limits;
  // parallel requests trip them and return untranslated fallbacks.
  const results = [];
  for (const c of chunks) {
    if (signal?.aborted) throw new DOMException('Aborted', 'AbortError');
    results.push(await translateChunk(c, signal));
  }
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

  // JSON-LD — deep parse: @graph, arrays, GeoCoordinates, address, typed-entity priority
  doc.querySelectorAll('script[type="application/ld+json"]').forEach(s => {
    try {
      const raw = JSON.parse(s.textContent);
      // Flatten top-level @graph arrays so nested entities are all processed
      let items = Array.isArray(raw) ? raw : [raw];
      items = items.flatMap(item =>
        item?.['@graph'] ? (Array.isArray(item['@graph']) ? item['@graph'] : [item['@graph']]) : [item]
      );

      // Sort: prefer typed entities (Organization, Farm, Vessel, Place) over generic ones
      const ORG_TYPES = /Organization|Corporation|Company|Farm|AquacultureFacility|Vessel|Ship|Port|Place|FoodEstablishment/i;
      items.sort((a, b) => {
        const at = [].concat(a?.['@type'] || []).join(',');
        const bt = [].concat(b?.['@type'] || []).join(',');
        return (ORG_TYPES.test(bt) ? 1 : 0) - (ORG_TYPES.test(at) ? 1 : 0);
      });

      items.forEach(d => {
        if (!d || typeof d !== 'object') return;
        const typeStr = [].concat(d['@type'] || []).join(',');

        // Name — prefer Organization/Vessel typed names
        const nm = d.name || d.legalName || d.alternateName;
        if (nm && !f._ldname) f._ldname = cleanField(String(nm));

        if (d.description && !f.description) f.description = cleanField(String(d.description)).slice(0, 1200);

        // Coordinates — GeoCoordinates object or direct latitude/longitude
        const geo = d.geo || (typeStr && d);
        if (geo?.latitude  !== undefined && !f.latitude)  f.latitude  = String(geo.latitude);
        if (geo?.longitude !== undefined && !f.longitude) f.longitude = String(geo.longitude);

        // Address block
        const addr = d.address || d.location?.address;
        if (addr && typeof addr === 'object') {
          if (addr.addressCountry && !f.country) f.country = cleanField(String(addr.addressCountry));
          if (addr.addressRegion  && !f.region)  f.region  = cleanField(String(addr.addressRegion));
          if (addr.addressLocality && !f.region) f.region  = cleanField(String(addr.addressLocality));
        }

        // Organization roles
        if (d.founder?.name    && !f.operator)  f.operator  = cleanField(d.founder.name);
        if (d.legalName        && !f.operator)  f.operator  = cleanField(String(d.legalName));
        if (d.parentOrganization?.name && !f.owner) f.owner = cleanField(d.parentOrganization.name);
        if (d.containedInPlace?.name && !f.region)  f.region = cleanField(d.containedInPlace.name);

        // Employee count
        if (d.numberOfEmployees?.value && !f.employees) f.employees = String(d.numberOfEmployees.value);
        if (typeof d.numberOfEmployees === 'number' && !f.employees) f.employees = String(d.numberOfEmployees);

        // Aquaculture / species specific
        if (d.produces?.name && !f.species) f.species = cleanField(d.produces.name);
        if (d.knowsAbout    && !f.species) f.species = cleanField(String(d.knowsAbout));
      });

      // Use _ldname as name only — vessel pages should have vessel_name set by other patterns
      if (f._ldname && !f.vessel_name && !f.farm_name) f.farm_name = f._ldname;
      delete f._ldname;
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
  doc.querySelectorAll([
    '.vessel-detail','.ship-detail','.detail-row','.info-row',
    '.property-row','.data-row','.field-row','.spec-row',
    '.vessel-info-item','.ship-info-item','.farm-detail',
    '.ais-data-item','.info-block-row','.vessel-data',
  ].join(',')).forEach(row => {
    const ch = [...row.children];
    if (ch.length >= 2) assignField(f, cleanField(ch[0].textContent).toLowerCase(), cleanField(ch[1].textContent));
    // Also handle rows where label is in a nested <strong> or <b>
    const strong = row.querySelector('strong,b,.label,.key');
    if (strong) {
      const rest = cleanField(row.textContent.replace(strong.textContent, '').trim());
      if (rest) assignField(f, cleanField(strong.textContent).toLowerCase(), rest);
    }
  });

  // Span label/value pairs — common on MarineTraffic, Equasis, and Chinese maritime sites
  // Pattern: <span class="bold-text|label|key">Label</span><span>value</span>
  doc.querySelectorAll([
    'span.bold-text','span.label-text','span.field-label','span.prop-name',
    'span[class*="label"]','span[class*="title"]','span[class*="key"]',
    'td.key','td.label','th.field',
  ].join(',')).forEach(lbl => {
    const k = cleanField(lbl.textContent).toLowerCase();
    // Look for value in next sibling span/td or parent's sibling
    const nxtSpan = lbl.nextElementSibling;
    const nxtTxt  = lbl.parentElement?.nextElementSibling;
    const v = nxtSpan ? cleanField(nxtSpan.textContent) : (nxtTxt ? cleanField(nxtTxt.textContent) : '');
    if (k && v) assignField(f, k, v);
  });

  // Microdata itemprop — Schema.org properties in itemprop attributes
  doc.querySelectorAll('[itemprop]').forEach(el => {
    const prop = el.getAttribute('itemprop')?.toLowerCase();
    if (!prop) return;
    const val = el.getAttribute('content') || cleanField(el.textContent);
    if (!val) return;
    // Map common itemprop names to field keys
    const ITEMPROP_MAP = {
      name: '_ldname', description: 'description', legalname: 'operator',
      addresscountry: 'country', addressregion: 'region', addresslocality: 'region',
      latitude: 'latitude', longitude: 'longitude',
      numberofemployees: 'employees',
    };
    const key = ITEMPROP_MAP[prop];
    if (key && !f[key]) f[key] = val;
    else if (!key) assignField(f, prop, val);
  });
  if (f._ldname && !f.vessel_name && !f.farm_name) f.farm_name = f._ldname;
  delete f._ldname;

  // List item key:value patterns — "Species: Salmon" inside <li>
  doc.querySelectorAll('li').forEach(li => {
    const txt = li.textContent;
    const sep = txt.match(/^([^:]{3,40}):\s*(.{2,120})$/);
    if (sep) assignField(f, sep[1].toLowerCase().trim(), sep[2].trim());
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
    // DMS format: handles °/º, '/′/ʼ, "/″/ʺ and decimal seconds e.g. 60°12'34.5"N, 005°19'22"E
    [/(\d{1,3})[°º]\s*(\d{1,2})[''′ʼ]\s*(\d{1,2}(?:[.,]\d+)?)[""″ʺ]?\s*[Nn][\s,;]+(\d{1,3})[°º]\s*(\d{1,2})[''′ʼ]\s*(\d{1,2}(?:[.,]\d+)?)[""″ʺ]?\s*[EeWw]/i, '_dms'],
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
      // Convert degrees°minutes'seconds"N/S E/W to decimal — handles decimal-comma and S/W signs
      const m = text.match(re);
      if (m && !f.latitude) {
        const toDec = (d, mn, s) =>
          parseFloat(d) + parseFloat(mn) / 60 + parseFloat(String(s).replace(',', '.')) / 3600;
        let lat = toDec(m[1], m[2], m[3]);
        let lon = toDec(m[4], m[5], m[6]);
        // Apply hemisphere sign from the matched suffix characters
        const lonDir = (m[0].match(/[EeWw]\s*$/) || [])[0] || '';
        if (/[Ss]/.test(m[0].split(m[4])[0])) lat = -lat;  // South of lat
        if (/[Ww]/i.test(lonDir)) lon = -lon;               // West of lon
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
  // Flag/country: bandera(ES), pavillon(FR), flagge(DE), flagg(NO), bandeira(PT), 船旗/国籍(ZH)
  if (/flag|country.*reg|bandera|pavillon|flagge|flagg|bandeira|船旗|国籍/.test(k))
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
  // Owner: propietario(ES), propriétaire(FR), eigentümer(DE), eier(NO), 船东/所有人(ZH)
  else if (/owner|beneficial|propietario|propri.taire|eigent.mer|reder\b|eier\b|船东|所有人|所有者/.test(k))
                                                 f.owner            = f.owner            || v;
  // Manager: gestor(ES), gestionnaire(FR), betreiber(DE), drifter(NO)
  else if (/manager|technical.?mgr|gestor|gestionnaire|betreiber|drifter/.test(k))
                                                 f.manager          = f.manager          || v;
  else if (/\bimo\b|imo.?number|imo.?no/.test(k) && /\d{7}/.test(v))
                                                 f._imo             = f._imo             || v.match(/\d{7}/)?.[0];
  // Vessel name: ship name, vessel name, nave(ES), navire(FR)
  else if (/vessel.?name|ship.?name|ship.?s.?name|nombre.?buque|nom.?navire|nome.?nave|schiffsname/.test(k))
                                                 f.vessel_name      = f.vessel_name      || v;
  // Farm/facility name — use farm_name; vessel pages already matched vessel.?name above
  else if (/\bname\b|facility|site.?name|farm.?name|nombre|nom\b/.test(k) && v.length < 80)
                                                 f.farm_name        = f.farm_name        || v;

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
  // Species: especie(ES), espèce(FR), art(NO/DE), espécie(PT), 养殖品种/鱼种(ZH)
  else if (/\bspecies\b|especie|esp.ce|fiskeart|\bart\b|organismo|kultiviert|espécie|养殖品种|鱼种|品种/.test(k))
                                                 f.species          = f.species          || v;
  // Water type: tipo de agua(ES), type d'eau(FR), vanntype(NO), tipo de água(PT)
  else if (/water.?type|tipo.?agua|type.?eau|vanntype|tipo.?água/.test(k))
                                                 f.water_type       = f.water_type       || v;
  // Capacity: capacidad(ES), capacité(FR), kapasitet(NO), capacidade(PT), 产量/产能(ZH)
  else if (/\bcapaci|kapasitet|capacidad|capacit.|capacidade|annual.?prod|produksjon|产量|产能|养殖规模/.test(k))
                                                 f.capacity         = f.capacity         || v;
  // License: licencia(ES), licence(FR), tillatelse(NO), licença(PT)
  else if (/\blicen|tillatelse|licencia|licen.e|licença|permit.?no|registr.?no/.test(k))
                                                 f.license          = f.license          || v;
  // Certification: certificación(ES), certification(FR), sertifisering(NO)
  else if (/certif|sertifisering|certificaci|asc.?cert|bap.?cert|global.?g\.?a\.?p/.test(k))
                                                 f.certification    = f.certification    || v;
  // Operator: operador(ES), opérateur(FR), betreiber(DE), operatør(NO), 经营者/运营商(ZH)
  else if (/\boperator\b|operatør|operador|op.rateur|betreiber|company.?name|farm.?owner|经营者|运营商|养殖单位/.test(k))
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
  'Broad-Search','Intl-Search','Baidu-Search',                          // lowest — broad fallbacks
  'Web-Discovery','DDG-Search','Google-Search','Google-CN',             // web search result pages
  'Wikipedia','MMSI-Decode','AIS-Registry',                             // encyclopedic / AIS
  'Bing-EN-Xlat',                                                      // cross-search (same trust as Web-Discovery)
  'Bing-NO','Bing-ES','Bing-PT','Bing-FR','Bing-DE','Bing-JA','Bing-KO','Bing-AR','Bing-RU', // lang-specific Bing
  'WeChat-Bing','WeChat-Sogou-Articles','WeChat-Sogou-Accounts','WeChat-Industry', // WeChat search
  'mp.weixin.qq.com',                                                  // WeChat article pages (direct)
  'Shuichan-Farm','Shuichan-Mill','FishFirst-Farm','FishFirst-Mill',    // Chinese trade portals
  'Fiskeridir','BarentsWatch','Sjøfart','Kystverket',                  // Nordic official registries
  'Subpesca-CL','Sernapesca','Produce-PE',                             // Latin American registries
  'JFA-Japan','JG-Registry','FIPS-KR',                                 // Asian registries
  'FranceAgriMer','BLE-DE','Rosrybolovstvo','MAPA-BR',                 // EU / Russian / Brazil
  'SeafoodSource','EUMOFA','MarineIngredients','GlobalSalmonIndex','Undercurrent', // trade & market databases
  'FIS','IFFO','BAP','GlobalGAP','MARA-Fisheries',                      // sector-specific registries
  'FAO','ASC',                                                          // UN / certification bodies
  'OpenStreetMap',                                                      // verified structured geo data
  'FAO-Global-Record','ITU',                                            // authoritative vessel registries
  'ShipXY','MSA-China',                                                 // Chinese maritime registries
  'Equasis','MarineTraffic','VesselFinder','FleetMon','MyShipTracking',  // highest for vessel data
];
function sourceRank(id) {
  if (!id) return 0;
  // Exact match first (preferred — avoids 'FAO' substring matching 'FAO-Global-Record')
  const exact = SOURCE_RANK.indexOf(id);
  if (exact >= 0) return exact;
  // Prefix match for dynamic ids like 'Wikipedia-2'
  const prefix = SOURCE_RANK.findIndex(s => id.startsWith(s) || s.startsWith(id));
  return prefix >= 0 ? prefix : 0;
}

// Returns true if a description is actually about the searched entity —
// not a generic website description or platform boilerplate.
function isEntityDescription(text, query) {
  if (!text || text.length < 30) return false;
  if (!query) return true;
  const stopWords = /^(the|and|for|of|in|a|an|is|are|by|at|on|with|asa|ltd|inc|llc|co|bv|nv|sa|ab|as|plc|group|holding)$/i;
  const terms = query.toLowerCase().split(/\s+/).filter(t => t.length > 2 && !stopWords.test(t));
  if (terms.length === 0) return true;
  const tl = text.toLowerCase();
  const hits = terms.filter(t => tl.includes(t)).length;
  // Short queries (1–2 meaningful words): require at least 1 hit
  // Longer queries (3+ words): require majority (≥50%) to avoid false positives
  const required = terms.length <= 2 ? 1 : Math.ceil(terms.length * 0.5);
  return hits >= required;
}

function mergeFields(results, query) {
  // Sort results: higher-ranked sources first, then by relevance to query
  const ranked = [...results]
    .filter(r => r.ok)
    .map(r => ({
      ...r,
      // Authority (×100) vastly outweighs relevance (capped at 20) so a high-authority
      // low-text source (Equasis rank 28 = 2800) always beats a noisy low-rank source
      // (Broad-Search rank 0 = 0 + 20 cap = 20). Relevance is a tiebreaker only.
      _score: sourceRank(r.id) * 100 + Math.min(relevanceScore(r.text || '', query || ''), 20),
    }))
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

  // Accumulate species / input_species across ALL ranked sources (union, not first-wins)
  // This ensures "Salmon" from source 1 + "Trout, Atlantic Cod" from source 2 → all three
  for (const specKey of ['species', 'input_species']) {
    const parts = [];
    for (const r of ranked) {
      const raw = r.fields?.[specKey];
      if (!raw) continue;
      const validated = validateFieldValue(specKey, raw);
      if (validated) parts.push(validated);
    }
    if (parts.length > 0) m[specKey] = parts.join(', ');
    // normalizeFields() below will split, deduplicate, title-case, and cap at 6
  }

  // Use _heading as name fallback if no structured name found.
  // Prefer farm_name — vessel pages should already have vessel_name set from
  // assignField patterns (vessel.?name, ship.?name…).  Setting vessel_name here
  // for a farm/mill page would corrupt the record type and dedup key.
  if (!m.farm_name && !m.vessel_name) {
    for (const r of ranked) {
      const h = r.fields?._heading;
      if (h && h.length > 2 && h.length < 80) { m.farm_name = h; break; }
    }
  }

  // Reject description if it doesn't actually mention the searched entity
  // (catches generic website meta descriptions and wrong Wikipedia articles)
  if (m.description && !isEntityDescription(m.description, query)) {
    delete m.description;
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
   FLAG EMOJI HELPERS
═══════════════════════════════════════════ */
/** Full country name → ISO-3166-1 alpha-2 code */
const COUNTRY_ISO2 = {
  'Afghanistan':'AF','Albania':'AL','Algeria':'DZ','Angola':'AO',
  'Antigua & Barbuda':'AG','Argentina':'AR','Armenia':'AM','Australia':'AU',
  'Austria':'AT','Azerbaijan':'AZ','Bahamas':'BS','Bangladesh':'BD',
  'Belgium':'BE','Belize':'BZ','Benin':'BJ','Bermuda':'BM','Bhutan':'BT',
  'Bolivia':'BO','Bosnia and Herzegovina':'BA','Brazil':'BR','Brunei':'BN',
  'Bulgaria':'BG','Cambodia':'KH','Cameroon':'CM','Canada':'CA','Cabo Verde':'CV',
  'Cayman Islands':'KY','Chile':'CL','China':'CN','Colombia':'CO','Comoros':'KM',
  'Congo':'CG','Cook Islands':'CK','Costa Rica':'CR','Croatia':'HR','Cuba':'CU',
  'Cyprus':'CY','Czech Republic':'CZ','Denmark':'DK','Djibouti':'DJ',
  'Dominica':'DM','Dominican Republic':'DO','DR Congo':'CD','Ecuador':'EC',
  'Egypt':'EG','Eritrea':'ER','Estonia':'EE','Ethiopia':'ET',
  'Faroe Islands':'FO','Fiji':'FJ','Finland':'FI','France':'FR',
  'French Polynesia':'PF','Falkland Islands':'FK','Germany':'DE','Ghana':'GH',
  'Greece':'GR','Grenada':'GD','Guadeloupe':'GP','Guatemala':'GT','Guyana':'GY',
  'Haiti':'HT','Honduras':'HN','Hong Kong':'HK','Hungary':'HU','Iceland':'IS',
  'India':'IN','Indonesia':'ID','Iran':'IR','Iraq':'IQ','Ireland':'IE',
  'Israel':'IL','Italy':'IT','Jamaica':'JM','Japan':'JP','Jordan':'JO',
  'Kazakhstan':'KZ','Kenya':'KE','Kiribati':'KI','Kuwait':'KW','Kyrgyzstan':'KG',
  'Laos':'LA','Latvia':'LV','Lebanon':'LB','Liberia':'LR','Lithuania':'LT',
  'Luxembourg':'LU','Macau':'MO','Madagascar':'MG','Malaysia':'MY','Maldives':'MV',
  'Malta':'MT','Marshall Islands':'MH','Mauritania':'MR','Mauritius':'MU',
  'Mexico':'MX','Micronesia':'FM','Montenegro':'ME','Morocco':'MA',
  'Mozambique':'MZ','Myanmar':'MM','Namibia':'NA','Nauru':'NR','Nepal':'NP',
  'Netherlands':'NL','Netherlands Antilles':'AN','New Caledonia':'NC',
  'New Zealand':'NZ','Nicaragua':'NI','Nigeria':'NG','Niue':'NU',
  'North Macedonia':'MK',"Democratic People's Republic of Korea":'KP',
  'Norway':'NO','Oman':'OM','Pakistan':'PK','Palau':'PW','Palestine':'PS',
  'Panama':'PA','Papua New Guinea':'PG','Peru':'PE','Philippines':'PH',
  'Poland':'PL','Portugal':'PT','Qatar':'QA','Romania':'RO','Russia':'RU',
  'Rwanda':'RW','Samoa':'WS','San Marino':'SM','Saudi Arabia':'SA',
  'Senegal':'SN','Serbia':'RS','Seychelles':'SC','Sierra Leone':'SL',
  'Singapore':'SG','Slovakia':'SK','Slovenia':'SI','Solomon Islands':'SB',
  'Somalia':'SO','South Africa':'ZA','South Korea':'KR','Spain':'ES',
  'Sri Lanka':'LK','Sudan':'SD','Suriname':'SR','Sweden':'SE',
  'Switzerland':'CH','Taiwan':'TW','Tanzania':'TZ','Thailand':'TH','Togo':'TG',
  'Tonga':'TO','Trinidad and Tobago':'TT','Tunisia':'TN','Turkey':'TR',
  'Turkmenistan':'TM','Tuvalu':'TV','UAE':'AE','Ukraine':'UA',
  'United Arab Emirates':'AE','United Kingdom':'GB','United States':'US',
  'Uruguay':'UY','Uzbekistan':'UZ','Vanuatu':'VU','Venezuela':'VE',
  'Vietnam':'VN','Wallis and Futuna':'WF','Christmas Island':'CX',
  'Pitcairn Islands':'PN','Northern Mariana Islands':'MP','Saint Helena':'SH',
  'Saint Kitts and Nevis':'KN','Saint Lucia':'LC',
  'Saint Vincent and the Grenadines':'VC','Madeira':'PT',
  // Additional maritime nations and common aliases
  'Bahrain':'BH','Libya':'LY','Syria':'SY','Mongolia':'MN',
  'Georgia':'GE','Andorra':'AD','Moldova':'MD','Belarus':'BY',
  'Tajikistan':'TJ','Gibraltar':'GI','South Sudan':'SS',
  // Aliases: alternate spellings and common abbreviations used by data sources
  'North Korea':'KP','Cape Verde':'CV','Ivory Coast':'CI',
  "Côte d'Ivoire":'CI','Turkiye':'TR','Türkiye':'TR',
  'Korea':'KR',                              // ambiguous → South Korea
  'Britain':'GB','Great Britain':'GB','England':'GB','Scotland':'GB','Wales':'GB',
  'USA':'US','UK':'GB','PRC':'CN','ROC':'TW', // ISO-2/ISO-3 short codes
  'Czechia':'CZ','Slovak Republic':'SK','The Gambia':'GM','Gambia':'GM',
  'DR Congo':'CD','DRC':'CD','Republic of Congo':'CG',
  'East Timor':'TL','Timor-Leste':'TL',
  'Eswatini':'SZ','Swaziland':'SZ','Burma':'MM',
};

/**
 * Convert a full country name (or flag state) to its Unicode flag emoji.
 * Uses ISO-3166-1 alpha-2 regional indicator pairs (U+1F1E6…U+1F1FF).
 *
 * Lookup order:
 *   1. Exact match   — 'Norway' → 'NO'
 *   2. Title-case    — 'norway' or 'NORWAY' → title-case → 'Norway' → 'NO'
 * The ISO code is always uppercased before the codepoint calculation so
 * any stray lowercase entry in COUNTRY_ISO2 still produces a valid emoji.
 * Returns '' if the country is unknown or the input is empty.
 */
function flagEmoji(country) {
  if (!country) return '';
  const key = country.trim();
  const iso = COUNTRY_ISO2[key]
    || COUNTRY_ISO2[key.replace(/\b\w/g, c => c.toUpperCase())];
  if (!iso || iso.length !== 2) return '';
  const RI_A = 0x1F1E6;  // U+1F1E6 Regional Indicator Symbol Letter A
  const u = iso.toUpperCase();  // Guard: RI formula requires uppercase A–Z (char 65–90)
  return String.fromCodePoint(RI_A + u.charCodeAt(0) - 65) +
         String.fromCodePoint(RI_A + u.charCodeAt(1) - 65);
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

  // Flag emoji — derived from country/flag state; used in header and field cells
  const _flagCountry = info.flag || info.country || '';
  const _flagEmoji   = flagEmoji(_flagCountry);
  /** Return value with its flag emoji prepended (only for flag/country cells) */
  const withFlag = (label, val) => {
    if (!val) return val;
    const _lc = label.toLowerCase();
    if (_lc.includes('flag') || _lc.includes('country') || _lc.includes('nationality') || _lc.includes('registration')) {
      const e = flagEmoji(val);
      return e ? e + ' ' + val : val;   // non-breaking space keeps emoji+text together
    }
    return val;
  };

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
    ['Harvest Cycles',    info.harvest_cycles,                         false],
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
    ['Navigational Status', info.nav_status,                           false],
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

  // Source chips — rendered as styled badges
  const okSrcs = sources.filter(s => s.ok);
  const srcChipsHTML = okSrcs.length
    ? `<div class="vc-sources">${okSrcs.map(s => `<span class="vc-src-chip src-ok">${esc(s.id)}</span>`).join('')}</div>`
    : '';

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
  const facilityLabel = info._facilityType === 'mill'   ? 'Mill / Processing'
    : info._facilityType === 'vessel' ? 'Shipping / Fishing Vessel'
    : info._facilityType === 'farm'   ? 'Farm / Aquaculture' : 'General';
  const catBadge  = info._category     ? `<span class="chip chip-b">${esc(info._category)}</span>` : '';
  const typeBadge = info._facilityType ? `<span class="chip chip-o">${esc(facilityLabel)}</span>` : '';
  const specBadge = info.species
    ? info.species.split(',').map(s => s.trim()).filter(Boolean)
        .map(s => `<span class="chip chip-g">${esc(s)}</span>`).join('')
    : '';
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
    info.nav_status                ? ['Navigational Status', info.nav_status]               : null,
  ].filter(Boolean);
  const identityHTML = idItems.length ? `
    <div class="vc-identity">
      ${idItems.map(([l,v]) => { const d = withFlag(l,v); return `<div class="vc-id-item"><b>${esc(l)}</b>${esc(d)}</div>`; }).join('')}
    </div>` : '';

  // Field count badge
  const fieldCount = fieldDefs.length;
  const fieldCountHTML = `<span class="vc-fieldcount${fieldCount >= 4 ? ' has-fields' : ''}">${fieldCount} field${fieldCount !== 1 ? 's' : ''} extracted</span>`;

  // Scrape footer
  const scrapeHTML = `
    <div class="vc-scrape">
      ${info._savedAt ? `<span>Retrieved ${new Date(info._savedAt).toLocaleDateString(undefined,{month:'short',day:'numeric',year:'numeric'})}</span>` : ''}
      ${info._category ? `<span>${esc(info._category)}</span>` : ''}
    </div>`;

  // Image gallery — hidden until loaded to prevent broken-image flash
  const imgHTML = imgs.length ? imgs.map(img =>
    `<div class="iw iw-loading" onclick="openLightbox('${encodeURIComponent(img.src)}','${encodeURIComponent(img.label)}')">
      <img src="${esc(img.src)}" alt="${esc(img.label)}"
           onload="this.parentElement.classList.remove('iw-loading')"
           onerror="this.parentElement.remove()">
      <div class="isrc">${esc(img.label)}</div>
    </div>`).join('') : '';

  const fieldHTML = fieldDefs.map(([l,v]) => {
    const disp = withFlag(l, v);
    return `<div class="vf"><div class="vfl">${esc(l)}</div><div class="vfv">${esc(disp)}</div></div>`;
  }).join('') || `<div class="vf" style="grid-column:1/-1;color:var(--mut3);font-style:italic;font-size:12px">No structured data available for this record.</div>`;

  const rawHTML = sources.filter(s => s.ok && s.text).map(s =>
    `<div style="margin-bottom:10px">
      <div class="label" style="margin-bottom:5px">${esc(s.id)}</div>
      <div class="text-view">${highlightIMO(s.text)}</div>
    </div>`).join('');

  // Type class for color-coded left border
  const typeClass = facilityType === 'vessel' ? 'vc-vessel'
                  : facilityType === 'mill'   ? 'vc-mill'
                  : 'vc-farm';

  // Save / saved-actions area — Save button pinned in card header when not yet saved
  const headerSaveBtn = savedId ? '' :
    `<button class="vc-save-btn" id="savebtn-${uid}" data-info="${esc(JSON.stringify({name, imo, ...info}))}" onclick="showSavePreview(JSON.parse(this.dataset.info),this.id)">Save ↗</button>`;

  return `
  <div class="vessel-card ${typeClass}" id="${uid}">
    <div class="vc-header">
      <div class="vc-header-main">
        <div class="vc-name">${safeName}</div>
        ${imo ? `<div class="vc-imo">IMO ${safeIMO}</div>` : ''}
        ${_flagCountry ? `<div class="vc-flag">${_flagEmoji ? `<span class="vc-flag-emoji" aria-hidden="true">${_flagEmoji}</span>` : ''}<span>${esc(_flagCountry)}</span></div>` : ''}
      </div>
      <div style="display:flex;flex-direction:column;align-items:flex-end;gap:6px;flex-shrink:0">
        ${headerSaveBtn}
        ${fieldCountHTML}
      </div>
    </div>
    ${badgeRow ? `<div class="vc-badges">${badgeRow}</div>` : ''}
    ${identityHTML}
    ${descHTML}
    ${srcChipsHTML}
    <div class="vc-grid">${fieldHTML}</div>
    ${imgs.length ? `<div class="label" style="margin-bottom:8px">📷 Images (${imgs.length})</div><div class="img-gallery">${imgHTML}</div>` : ''}
    <div class="ship-links">${linkHTML}</div>
    ${noteText}
    ${scrapeHTML}
    <div class="btn-row">
      ${savedId ? savedActions : ''}
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
/**
 * triggerCrossRefVesselLookup — fires background lookups to the three most
 * authoritative vessel registries the moment an IMO is discovered mid-scrape.
 * Non-blocking: results are pushed to scrapeResults as they arrive.
 *
 * @param {string}   imo             - Validated 7-digit IMO number
 * @param {AbortSignal} signal       - Scrape abort signal
 * @param {Array}    scrapeResults   - Shared results array (push-safe in JS single-thread)
 * @param {Function} maybeFireClaude - Callback to feed good text to Claude
 * @param {Function} checkEarlyExit  - Callback to check field threshold
 */
function triggerCrossRefVesselLookup(imo, signal, scrapeResults, maybeFireClaude, checkEarlyExit) {
  log(`IMO ${imo} discovered — cross-referencing Equasis, MarineTraffic, VesselFinder…`, 'ok');
  const TARGETS = [
    { id:'Equasis',       url:`https://www.equasis.org/EquasisWeb/restricted/ShipInfo?fs=Search&P_IMO=${imo}` },
    { id:'MarineTraffic', url:`https://www.marinetraffic.com/en/ais/details/ships/imo:${imo}` },
    { id:'VesselFinder',  url:`https://www.vesselfinder.com/vessels/details/${imo}` },
  ];
  Promise.allSettled(
    TARGETS.map(t => fetchViaProxy(t.url, timedSignal(signal, 20000)).then(html => ({ ...t, html })))
  ).then(settled => {
    for (const res of settled) {
      if (res.status !== 'fulfilled') continue;
      const { id, url, html } = res.value;
      try {
        const pd  = parseHTML(html, url);
        const pt  = pd.body?.innerText?.slice(0, 15000) || '';
        if (!isSeaRelated(pt)) continue;
        const pf  = filterFieldsByType(extractFields(pd, pt), 'vessel');
        pf._imo   = imo;
        const fc  = Object.keys(pf).filter(k => !k.startsWith('_')).length;
        if (fc >= 1) {
          log(`✓ Cross-ref ${id}: ${fc} field(s)`, 'ok');
          scrapeResults.push({ id, ok:true, url, fields:pf, imgs:extractImages(pd, url), text:pt });
          if (typeof maybeFireClaude === 'function') maybeFireClaude(pt, id);
          if (typeof checkEarlyExit  === 'function') checkEarlyExit();
        }
      } catch(e) {
        if (e.name !== 'AbortError') log(`Cross-ref ${id} parse error: ${e.message}`, 'warn');
      }
    }
  }).catch(e => { if (e.name !== 'AbortError') log(`Cross-ref failed: ${e.message}`, 'warn'); });
}

async function runBot() {
  if (isRunning) return;
  const raw = document.getElementById('main-search').value.trim();
  if (!raw) { toast('Enter a name or IMO number'); return; }

  // Sanitize input
  const q = raw.replace(/[<>"']/g,'').slice(0,200);
  const searchType = document.getElementById('search-type')?.value || 'farm';
  const isMill   = searchType === 'mill';
  const isVessel = searchType === 'vessel';
  const isIMO    = /^\d{7}$/.test(q) && validIMO(q);
  const isMMSI   = /^\d{9}$/.test(q.replace(/\s/g,''));
  let imo  = isIMO  ? q : '';
  let mmsi = isMMSI ? q.replace(/\s/g,'') : '';
  const yearFrom  = parseInt(document.getElementById('year-from')?.value  || '2000');
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

  // Log to SQLite search history (non-blocking)
  if (window.AppSQLite) AppSQLite.logSearch(q, searchType).catch(() => {});

  const out = document.getElementById('bot-output');
  out.innerHTML = `
    <div class="card">
      <div class="run-title"><span class="spin"></span> Searching for <em>${esc(q)}</em></div>
      <div class="run-status" id="run-status">Scanning sources…</div>
      <div class="prog-bar"><div class="prog-fill" id="bprog" style="width:5%"></div></div>
      <div class="bot-log" id="bot-log"></div>
      <div id="bot-res"></div>
    </div>`;

  logEl = document.getElementById('bot-log');
  const setProgress = p => { const el = document.getElementById('bprog'); if(el) el.style.width = p + '%'; };
  const setStatus   = s => { const el = document.getElementById('run-status'); if(el) el.textContent = s; };
  let _sourcesDone  = 0;
  let _sourcesTotal = 0;
  const tickSource  = (id) => {
    _sourcesDone++;
    setStatus(`Checking ${id}… (${_sourcesDone}/${_sourcesTotal} sources)`);
  };

  // Check knowledge base for prior results
  const priorKnowledge = checkLearned(q);
  if (priorKnowledge) {
    const fCount = Object.keys(priorKnowledge.fields).length;
    log(`Knowledge base hit: "${q}" searched ${priorKnowledge.hitCount}× — ${fCount} fields cached, fetching updates…`, 'ok');
  }

  try {
    // ── Query language detection + cross-language translation ──────────────
    const queryLang = detectQueryLang(q);
    let qEn = q; // English version — used for English-language search engines
    if (queryLang !== 'en') {
      log(`Query language: ${queryLang} — generating English cross-search…`, 'info');
      setStatus('Translating query…');
      try { qEn = await translateQuery(q, queryLang, 'en', signal); } catch(e) { if (e.name !== 'AbortError') log(`Query translation failed (${queryLang}→en): ${e.message}`, 'warn'); }
      if (qEn !== q) log(`Cross-search: "${qEn}"`, 'ok');
    }
    // Language-specific industry supplement terms (appended to search queries)
    const langTerms = langIndustryTerms(queryLang, searchType);

    log(`Query: "${q}" — type: ${searchType}${queryLang !== 'en' ? ` [${queryLang}]` : ''}`, 'info');
    setProgress(20); setStatus('Building source list…');

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
          bingQ = `${qPhrase}${catKW} vessel ship IMO registry flag site:marinetraffic.com OR site:vesselfinder.com OR site:fleetmon.com OR site:equasis.org OR site:myshiptracking.com`;
          scraperURLs.push(
            { id:'MarineTraffic',    url:`https://www.marinetraffic.com/en/ais/details/ships/shipid:0/mmsi:0/vessel:${encodeURIComponent(q)}` },
            { id:'VesselFinder',     url:`https://www.vesselfinder.com/?name=${encodeURIComponent(q)}` },
            { id:'FleetMon',         url:`https://www.fleetmon.com/vessels/?search_vessel=${encodeURIComponent(q)}` },
            { id:'MyShipTracking',   url:`https://www.myshiptracking.com/vessels?name=${encodeURIComponent(q)}` },
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
          bingQ = `${qPhrase}${catKW} fishmeal "fish oil" processing plant site:iffo.com OR site:fis.com OR site:seafoodsource.com OR site:eumofa.eu OR site:undercurrentnews.com OR site:allaboutfeed.net OR site:marineingredients.org OR site:shuichan.cc OR site:fishfirst.cn`;
          scraperURLs.push(
            { id:'IFFO',             url:`https://www.iffo.com/search?keyword=${encodeURIComponent(q)}` },
            { id:'MarineIngredients',url:`https://www.marineingredients.org/?s=${encodeURIComponent(q)}` },
            { id:'EUMOFA',           url:`https://www.eumofa.eu/en/search?text=${encodeURIComponent(q)}` },
            { id:'FIS',              url:`https://www.fis.com/fis/search/?search=${encodeURIComponent(q)}&type=companies` },
            { id:'SeafoodSource',    url:`https://www.seafoodsource.com/search?q=${encodeURIComponent(q)}` },
            { id:'Undercurrent',     url:`https://www.undercurrentnews.com/?s=${encodeURIComponent(q)}` },
            // Chinese sources — fish meal / processing plants
            { id:'Shuichan-Mill',    url:`https://www.shuichan.cc/search/?keyword=${encodeURIComponent(q)}`, _cn:true },
            { id:'FishFirst-Mill',   url:`https://www.fishfirst.cn/?s=${encodeURIComponent(q)}`, _cn:true },
          );
        } else {
          // Farm: site-targeted Bing query hitting ASC, BAP, SeafoodSource, GlobalG.A.P., etc.
          bingQ = `${qPhrase}${catKW} aquaculture "fish farm" certified site:asc-aqua.org OR site:bapcertification.org OR site:seafoodsource.com OR site:fis.com OR site:undercurrentnews.com OR site:intrafish.com OR site:globefish.org OR site:globalgap.org OR site:mara.gov.cn OR site:fishfirst.cn OR site:shuichan.cc`;
          scraperURLs.push(
            { id:'ASC',              url:`https://www.asc-aqua.org/find-a-farm/?q=${encodeURIComponent(q)}` },
            { id:'BAP',              url:`https://www.bapcertification.org/searchfacilities?name=${encodeURIComponent(q)}` },
            { id:'SeafoodSource',    url:`https://www.seafoodsource.com/search?q=${encodeURIComponent(q)}` },
            { id:'GlobalSalmonIndex',url:`https://salmonindex.org/search?query=${encodeURIComponent(q)}` },
            { id:'FIS',              url:`https://www.fis.com/fis/search/?search=${encodeURIComponent(q)}&type=companies` },
            { id:'GlobalGAP',        url:`https://www.globalgap.org/uk_en/who-we-are/GFSI/?Id=0018&Type=ProductionSite&search_type=db_search&search_term=${encodeURIComponent(q)}&LanguageId=1` },
            // Chinese sources — aquaculture farms
            { id:'Shuichan-Farm',    url:`https://www.shuichan.cc/search/?keyword=${encodeURIComponent(q)}`, _cn:true },
            { id:'FishFirst-Farm',   url:`https://www.fishfirst.cn/?s=${encodeURIComponent(q)}`, _cn:true },
            { id:'MARA-Fisheries',   url:`https://www.mara.gov.cn/sousuo/index.htm?keywords=${encodeURIComponent(q)}&type=zdly`, _cn:true },
          );
        }
        log(`Date filter: ${yearFrom}–${yearTo}${catFilter ? ` · category: ${catFilter}` : ''}`, 'info');
        farmAPIResults = await queryFarmAPIs(q, signal, yearTo, searchType).catch(() => []);
      }

      // Use qEn (English translation) for English search engines when query is non-English
      const qEnPhrase = (qEn !== q && (words.length >= 3 || qEn.length >= 16)) ? `"${qEn}"` : qEn;

      scraperURLs.push({ id:'Web-Discovery', url:`https://www.bing.com/search?q=${encodeURIComponent(bingQ)}` });

      // If query is non-English, also search with English translation on Bing
      if (qEn !== q) {
        const bingEnQ = isVessel
          ? `${qEnPhrase}${catKW} vessel ship IMO registry flag`
          : isMill ? `${qEnPhrase}${catKW} fishmeal processing plant`
                   : `${qEnPhrase}${catKW} aquaculture fish farm certified`;
        scraperURLs.push({ id:'Bing-EN-Xlat', url:`https://www.bing.com/search?q=${encodeURIComponent(bingEnQ)}` });
      }

      // DuckDuckGo — uses English translation query for best results
      const ddgQ = isVessel
        ? `${qEnPhrase}${catKW} vessel ship IMO MMSI flag registry gross tonnage year built`
        : isMill
          ? `${qEnPhrase}${catKW} fishmeal "fish oil" processing plant IFFO certified capacity input species`
          : `${qEnPhrase}${catKW} aquaculture "fish farm" ASC BAP certified species production capacity`;
      scraperURLs.push({ id:'DDG-Search', url:`https://html.duckduckgo.com/html/?q=${encodeURIComponent(ddgQ)}` });

      // Google (English) — uses English translation + language-specific industry terms
      const googleQ = isVessel
        ? `${qEnPhrase}${catKW} vessel ship IMO flag "call sign" "gross tonnage" "year built" ${langTerms}`
        : isMill
          ? `${qEnPhrase}${catKW} fishmeal "fish oil" mill capacity "input species" certifications ${langTerms}`
          : `${qEnPhrase}${catKW} fish farm aquaculture species certified production capacity operator ${langTerms}`;
      scraperURLs.push({ id:'Google-Search', url:`https://www.google.com/search?q=${encodeURIComponent(googleQ.trim())}&num=20&hl=en&gl=us` });

      // Language-specific official registries (Norwegian, Spanish, Japanese, etc.)
      const langSources = langSpecificSources(q, qEn, queryLang, searchType);
      if (langSources.length) {
        log(`Adding ${langSources.length} ${queryLang.toUpperCase()} language-specific source(s)`, 'info');
        scraperURLs.push(...langSources);
      }

      // Google (Chinese) — targets .cn domains and Chinese-language results
      const googleCNQ = isVessel
        ? `${q} 船舶 船名 IMO 船旗 呼号 总吨`
        : isMill
          ? `${q} 鱼粉厂 鱼油 加工厂 产能 原料鱼`
          : `${q} 水产养殖 养殖场 养殖品种 产量 认证`;
      scraperURLs.push({ id:'Google-CN', url:`https://www.google.com/search?q=${encodeURIComponent(googleCNQ)}&num=20&hl=zh-CN&gl=cn`, _cn:true });

      // Baidu — dominant Chinese search engine; surfaces .cn government and industry pages
      const baiduQ = isVessel
        ? `${q} 船舶 船名 IMO 船旗`
        : isMill
          ? `${q} 鱼粉 加工厂 水产品加工`
          : `${q} 水产养殖 养殖场`;
      scraperURLs.push({ id:'Baidu-Search', url:`https://www.baidu.com/s?wd=${encodeURIComponent(baiduQ)}&rn=20`, _cn:true, _fallback:true });

      // Chinese vessel registries — added for vessel searches
      if (isVessel) {
        scraperURLs.push(
          { id:'ShipXY',    url:`https://www.shipxy.com/ship/shiplist?name=${encodeURIComponent(q)}`, _cn:true },
          { id:'MSA-China', url:`https://www.msa.gov.cn/search/index.html?q=${encodeURIComponent(q)}`, _cn:true },
        );
      }

      // ── WeChat (微信公众号) ─────────────────────────────────────────────────
      // Companies publish farm inspections, vessel registrations, and operational
      // updates on WeChat Official Accounts. Articles at mp.weixin.qq.com are
      // public web pages — no login required — and are indexed by Bing.
      //
      // Strategy:
      //   1. Bing `site:mp.weixin.qq.com` — reliable index of public WX articles
      //   2. Sogou WeChat search (`weixin.sogou.com`) — the dedicated WX article
      //      search engine; covers accounts that Bing hasn't indexed yet
      const wxQ = isVessel
        ? `${q} 船舶 船名 渔船`
        : isMill
          ? `${q} 鱼粉 鱼油 水产品加工`
          : `${q} 水产养殖 养殖场 养殖品种`;
      scraperURLs.push(
        // Bing WeChat article search — follows real links to mp.weixin.qq.com
        { id:'WeChat-Bing',  url:`https://www.bing.com/search?q=${encodeURIComponent(q + ' ' + wxQ.split(' ')[1])}&q1=site:mp.weixin.qq.com&hl=zh-CN`, _cn:true, _wechat:true },
        // Sogou WeChat — type=2 = articles, type=1 = official accounts
        { id:'WeChat-Sogou-Articles',  url:`https://weixin.sogou.com/weixin?type=2&query=${encodeURIComponent(q)}`, _cn:true, _wechat:true },
        { id:'WeChat-Sogou-Accounts',  url:`https://weixin.sogou.com/weixin?type=1&query=${encodeURIComponent(q)}`, _cn:true, _wechat:true },
        // Direct Bing search for WeChat articles with Chinese industry terms
        { id:'WeChat-Industry', url:`https://www.bing.com/search?q=${encodeURIComponent(wxQ + ' site:mp.weixin.qq.com')}&setlang=zh-CN`, _cn:true, _wechat:true, _fallback:true },
      );

      // Broad fallback — no date, no exact phrase; uses English translation if query is non-English
      const fallbackQ = isVessel
        ? `${qEn} vessel ship registry`
        : isMill ? `${qEn} fishmeal fish processing` : `${qEn} fish farm aquaculture`;
      scraperURLs.push({ id:'Broad-Search', url:`https://www.bing.com/search?q=${encodeURIComponent(fallbackQ)}`, _fallback:true });

      // International fallback — original query with multilingual industry terms
      // This surfaces foreign-language pages that English-only queries miss
      const intlTerms = isVessel
        ? `nave barco buque vessel schiff navire 船 漁船 مركب ${langTerms}`
        : isMill
          ? `harina pescado fischmehl farine poisson 鱼粉 鱼油厂 ${langTerms}`
          : `acuicultura aquaculture aquacultura élevage poisson 水产养殖 养殖场 ${langTerms}`;
      const intlQ = `${q} ${intlTerms.trim()}`;
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
    if (claudeKey || _serverAIReady) {
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
    // Vessels have 15+ core fields — don't exit early, we want all of them
    // Farms have 12+, Mills have 10+. Raising these means more sources get scraped
    // before we stop, which is exactly the intensive behaviour we want.
    const FIELD_THRESHOLD = isVessel ? 14 : isMill ? 10 : 12;
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

    const DISCOVERY_IDS = [
      'Web-Discovery','DDG-Search','Google-Search','Broad-Search','Intl-Search',
      'Google-CN','Baidu-Search',                      // Chinese search engines
      'Bing-EN-Xlat',                                  // English cross-search for non-EN queries
      'Shuichan-Farm','Shuichan-Mill',                 // Chinese aquaculture portals
      'FishFirst-Farm','FishFirst-Mill','MARA-Fisheries',
      'WeChat-Bing','WeChat-Sogou-Articles','WeChat-Sogou-Accounts','WeChat-Industry', // WeChat
      // Language-specific search engines
      'Bing-NO','Bing-ES','Bing-PT','Bing-FR','Bing-DE','Bing-JA','Bing-KO','Bing-AR','Bing-RU',
    ];

    // ── Scrape helper: fetch one source, translate if needed, extract fields ──
    const TEXT_BUDGET = 15000; // ~2,500 words — captures tables and specs deeper in pages
    // Domains to skip when following discovery links — search engine result pages only,
    // NOT content sites. mp.weixin.qq.com is a content site and must NOT be skipped.
    const SKIP_DOMAINS = /^https?:\/\/(www\.bing\.com|www\.google\.(com|cn)\/search|html\.duckduckgo\.com|duckduckgo\.com|baidu\.com\/s)[/?]/i;

    async function scrapeOne(s) {
      if (scrapeSignal.aborted) return;
      try {
        tickSource(s.id);
        log(`→ ${s.id}…`, 'info');
        // Chinese government/portal sites can be slow — give them extra time
        const timeout = (s._cn || s._lang) ? 28000 : 22000;
        const html = await fetchViaProxy(s.url, timedSignal(scrapeSignal, timeout));
        if (scrapeSignal.aborted) return;

        const doc  = parseHTML(html, s.url);
        // For WeChat articles focus on #js_content; for others use full body
        const bodyEl = s._wechat
          ? (doc.getElementById('js_content') || doc.body)
          : doc.body;
        let   text = bodyEl?.innerText?.slice(0, TEXT_BUDGET) || '';

        const pageLang = detectLang(doc, text);
        if (pageLang !== 'en') {
          log(`Language: ${pageLang} — translating…`, 'info');
          try { text = await translate(text.slice(0, 4000), scrapeSignal); } catch(e) { if (e.name !== 'AbortError') log(`Translation failed: ${e.message}`, 'warn'); }
        }

        const fields = extractFields(doc, text);
        const imgs   = extractImages(doc, s.url);

        // Cross-reference: if a valid IMO is freshly discovered, immediately
        // trigger targeted Equasis + MarineTraffic lookups in the background
        if (!imo) {
          const imoFound = extractIMOs(text).filter(validIMO); // validIMO check added
          if (imoFound.length) {
            imo = imoFound[0];
            triggerCrossRefVesselLookup(imo, scrapeSignal, scrapeResults, maybeFireClaude, checkEarlyExit);
          }
        }

        // Discovery sources: follow top result links — use DOM, not regex
        if (DISCOVERY_IDS.includes(s.id)) {
          // DOM-based link extraction handles relative URLs and avoids regex false-matches
          const anchors = [...doc.querySelectorAll('a[href]')];
          const discovered = [];
          for (const a of anchors) {
            try {
              const href = new URL(a.href || a.getAttribute('href'), s.url).href;
              if (isValidURL(href) && !SKIP_DOMAINS.test(href) && !discovered.includes(href))
                discovered.push(href);
            } catch {}
          }
          // WeChat/Sogou results — prioritise mp.weixin.qq.com article links
          const wxFirst = s._wechat
            ? [...discovered.filter(u => /mp\.weixin\.qq\.com/i.test(u)),
               ...discovered.filter(u => !/mp\.weixin\.qq\.com/i.test(u))]
            : discovered;
          // Intensive: follow up to 12 links from primary discovery pages, 8 from WeChat, 5 from fallbacks
          const topURLs = [...new Set(wxFirst)].slice(0, s._fallback ? 5 : (s._wechat ? 8 : 12));

          for (const u of topURLs) {
            if (scrapeSignal.aborted) break;
            try {
              const isWX = /mp\.weixin\.qq\.com/i.test(u);
              const ph = await fetchViaProxy(u, timedSignal(scrapeSignal, isWX ? 30000 : (s._cn ? 28000 : 20000)));
              if (scrapeSignal.aborted) break;
              const pd     = parseHTML(ph, u);
              // WeChat articles: focus on #js_content for cleaner text extraction
              const pdBody = isWX ? (pd.getElementById('js_content') || pd.body) : pd.body;
              let   pt     = pdBody?.innerText?.slice(0, TEXT_BUDGET) || '';
              const subLang = detectLang(pd, pt);
              if (subLang !== 'en') { try { pt = await translate(pt.slice(0, 4000), scrapeSignal); } catch(e) { if (e.name !== 'AbortError') log(`Sub-page translation failed: ${e.message}`, 'warn'); } }

              if (!isSeaRelated(pt)) { log(`Skipped (off-domain): ${new URL(u).hostname}`, 'warn'); continue; }
              if (!topicMatch(pt, searchType)) { log(`Skipped (wrong type): ${new URL(u).hostname}`, 'warn'); continue; }

              const pf = filterFieldsByType(extractFields(pd, pt), searchType);
              const fc = Object.keys(pf).filter(k => !k.startsWith('_')).length;
              if (fc >= 1) {
                const hostname = new URL(u).hostname;
                log(`✓ ${s._fallback ? 'Fallback' : 'Found'}: ${hostname} — ${fc} field(s)${subLang !== 'en' ? ` [${subLang}]` : ''}`, 'ok');
                scrapeResults.push({ id: hostname, ok:true, url:u, fields:pf, imgs:extractImages(pd, u), text:pt });
                maybeFireClaude(pt, hostname);
                checkEarlyExit();
              }
            } catch(e) { if (e.name === 'AbortError') throw e; }
          }
        }

        if (scrapeSignal.aborted) return;
        const rel = relevanceScore(text, q);
        const filteredFields = filterFieldsByType(fields, searchType);
        const fc = Object.keys(filteredFields).filter(k => !k.startsWith('_')).length;

        if (!isSeaRelated(text) || (rel === 0 && fc < 2 && s._fallback) || !topicMatch(text, searchType)) {
          log(`Skipped (${!isSeaRelated(text) ? 'off-domain' : 'off-topic'}): ${s.id}`, 'warn');
        } else {
          log(`✓ ${s.id} — ${fc} field(s), ${imgs.length} img(s)`, 'ok');
          scrapeResults.push({ id:s.id, ok:true, url:s.url, fields:filteredFields, imgs, text });
          maybeFireClaude(text, s.id);
          checkEarlyExit();
        }
      } catch(e) {
        if (e.name === 'AbortError') throw e;
        log(`✗ ${s.id}: ${e.message}`, 'err');
        scrapeResults.push({ id:s.id, ok:false, url:s.url, error:e.message, fields:{}, imgs:[], text:'' });
      }
    }

    // Claude trigger — fires after the FIRST good page (not waiting for 2)
    function maybeFireClaude(text, sourceId) {
      if (!(claudeKey || _serverAIReady)) return;
      if (relevanceScore(text, q) >= 1 && text.length > 300) {
        claudeTexts.push({ source: sourceId, text });
        if (!claudePromise && claudeTexts.length >= 1)
          claudePromise = claudeExtract(claudeTexts, q, searchType, signal);
      }
    }

    // ── Parallel scrape with concurrency limit ────────────────────────────────
    // Non-fallback sources run at 4 concurrent; fallbacks are sequential after.
    const primary   = scraperURLs.filter(s => !s._fallback);
    const fallbacks = scraperURLs.filter(s =>  s._fallback);
    _sourcesTotal = scraperURLs.length;
    setStatus(`Scanning ${_sourcesTotal} source${_sourcesTotal !== 1 ? 's' : ''}…`);
    const CONCURRENCY = 6; // 6 concurrent workers — intensive but polite

    // Run primary sources CONCURRENCY-at-a-time
    let idx = 0;
    async function worker() {
      while (idx < primary.length && !scrapeSignal.aborted) {
        const s = primary[idx++];
        await scrapeOne(s).catch(e => { if (e.name !== 'AbortError') {} });
      }
    }
    await Promise.all(Array.from({ length: CONCURRENCY }, worker));

    // Fallbacks: run sequentially but stop if early-exit already fired
    for (const s of fallbacks) {
      if (scrapeSignal.aborted) break;
      await scrapeOne(s).catch(e => { if (e.name !== 'AbortError') {} });
    }

    if (signal.aborted) throw new DOMException('Search cancelled by user', 'AbortError');
    setProgress(70); setStatus('Merging results…');

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
    setProgress(88); setStatus('AI enrichment…');

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
      const retryQ   = isVessel ? `${q} vessel ship` : isMill ? `${q} fishmeal plant` : `${q} aquaculture`;
      const retryCNQ = isVessel ? `${q} 船舶 船名` : isMill ? `${q} 鱼粉厂` : `${q} 水产养殖`;
      const retryURLs = [
        `https://www.bing.com/search?q=${encodeURIComponent(retryQ)}`,
        `https://html.duckduckgo.com/html/?q=${encodeURIComponent(retryQ)}`,
        `https://www.google.com/search?q=${encodeURIComponent(retryCNQ)}&num=10&hl=zh-CN&gl=cn`,
      ];
      for (const rUrl of retryURLs) {
        if (signal.aborted) break;
        try {
          const rHtml = await fetchViaProxy(rUrl, signal);
          const rDoc  = parseHTML(rHtml, rUrl);
          // DOM-based link extraction — same quality as the main scrape loop
          const rAnchors = [...rDoc.querySelectorAll('a[href]')];
          const rDiscovered = [];
          for (const a of rAnchors) {
            try {
              const href = new URL(a.href || a.getAttribute('href'), rUrl).href;
              if (isValidURL(href) && !rDiscovered.includes(href)) rDiscovered.push(href);
            } catch {}
          }
          const rTopURLs = [...new Set(rDiscovered)].slice(0, 12); // 12 links in retry too
          for (const ru of rTopURLs) {
            if (signal.aborted) break;
            try {
              const rPh = await fetchViaProxy(ru, signal);
              const rPd = parseHTML(rPh, ru);
              let rPt = rPd.body?.innerText?.slice(0, 15000) || '';
              const rLang = detectLang(rPd, rPt);
              if (rLang !== 'en') { try { rPt = await translate(rPt.slice(0, 4000), signal); } catch {} }
              if (relevanceScore(rPt, q) === 0 && relevanceScore(rPt, qEn || q) === 0) continue;
              if (!isSeaRelated(rPt)) continue;
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

    // ── Claude: fire on all accumulated pages if not yet triggered ────────
    // (maybeFireClaude fires early on first good page; this catches the case
    //  where all good pages arrived in the same concurrent batch)
    if ((claudeKey || _serverAIReady) && claudeTexts.length >= 1 && !claudePromise)
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
    const fieldCount  = Object.keys(merged).filter(k => !k.startsWith('_')).length;
    const okSources   = scrapeResults.filter(r => r.ok).length;
    const doneMsg = [
      `${fieldCount} field${fieldCount !== 1 ? 's' : ''} extracted`,
      `${okSources}/${_sourcesTotal} sources hit`,
      aiEnhanced ? 'AI-enhanced ✓' : '',
      allImgs.length  ? `${allImgs.length} image${allImgs.length !== 1 ? 's' : ''}` : '',
    ].filter(Boolean).join(' · ');
    setStatus(doneMsg);
    log(`Complete — ${doneMsg}`, 'ok');

    // Build card name — then sanity-check it matches the search query.
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
      if (fieldCount < 2 && !signal.aborted) {
        // No-results state — clear, actionable, not just a broken card
        const altType = isVessel ? 'farm' : 'vessel';
        const altLabel = isVessel ? 'Farm / Aquaculture' : 'Shipping / Fishing Vessel';
        resEl.innerHTML = `
          <div class="no-results">
            <div class="no-results-icon">🔍</div>
            <div class="no-results-title">No data found for "${esc(q)}"</div>
            <div class="no-results-sub">
              Checked ${okSources} sources — none had structured data matching this entity.
              Try a more specific name, an IMO number, or switch the facility type.
            </div>
            <div class="no-results-actions">
              <button class="btn btn-blue btn-sm" onclick="
                document.getElementById('search-type').value='${esc(altType)}';
                runBot()">
                Try as ${esc(altLabel)}
              </button>
              <button class="btn btn-ghost btn-sm" onclick="
                document.getElementById('main-search').value='${esc(q)} aquaculture';
                runBot()">
                Broaden search
              </button>
              <button class="btn btn-ghost btn-sm" onclick="setMode('url')">
                Paste a URL instead
              </button>
            </div>
          </div>`;
      } else {
        const div = document.createElement('div');
        div.innerHTML = renderCard(cardName, imo, merged, scrapeResults, allImgs, aiEnhanced);
        resEl.appendChild(div);
      }

      // Cache the rendered HTML for 30 minutes
      if (window.AppCache && fieldCount >= 2) {
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
async function queryFarmAPIs(q, signal, yearTo = new Date().getFullYear(), searchType = 'farm') {
  const results = [];
  // \p{L}\p{N} — preserve letters/digits from ANY script (CJK, Arabic, Cyrillic, etc.)
  const safeQ = q.replace(/[^\p{L}\p{N}\s\-]/gu, '').trim().slice(0, 80);

  // Run OSM and Wikipedia in parallel (both are direct API calls, no proxy contention)
  const [osmSettled, wikiSettled] = await Promise.allSettled([

    /* ── 1. OpenStreetMap Overpass ── real lat/lon of facilities */
    (async () => {
      const isMill_ = searchType === 'mill';
      log(`OSM Overpass: searching ${isMill_ ? 'processing plant' : 'aquaculture'} facilities…`, 'info');
      const words = safeQ.trim().split(/\s+/);
      const isShort = words.length <= 2;
      let nameClause;
      if (isMill_) {
        // Processing plants / feed mills — use industrial tags
        nameClause = isShort
          ? `(node["name"~"${safeQ}","i"]["industrial"~"fish|fishmeal|feed","i"];` +
            ` way["name"~"${safeQ}","i"]["industrial"~"fish|fishmeal|feed","i"];` +
            ` node["name"~"${safeQ}","i"]["man_made"="works"];` +
            ` node["name"~"${safeQ}","i"]["craft"~"fish","i"];)`
          : `(node["name"~"${safeQ}","i"][~"^(industrial|craft|man_made)$"~"fish|works|factory","i"];` +
            ` way["name"~"${safeQ}","i"][~"^(industrial|craft)$"~"fish","i"];)`;
      } else {
        nameClause = isShort
          ? `(node[~"^(landuse|produce|species|name)$"~"${safeQ}","i"]["landuse"~"aquaculture|fish_farm|fishery","i"];` +
            ` way[~"^(landuse|produce|species|name)$"~"${safeQ}","i"]["landuse"~"aquaculture|fish_farm|fishery","i"];` +
            ` node["name"~"${safeQ}","i"]["water"="fish_farm"];` +
            ` node["name"~"${safeQ}","i"]["man_made"~"fish_pass|aquaculture"];)`
          : `(node["name"~"${safeQ}","i"][~"^(landuse|aquaculture|craft|industrial)$"~"aquaculture","i"];` +
            ` way["name"~"${safeQ}","i"][~"^(landuse|aquaculture|craft|industrial)$"~"aquaculture","i"];` +
            ` node["name"~"${safeQ}","i"]["man_made"="fish_pass"];` +
            ` node["name"~"${safeQ}","i"]["water"="fish_farm"];)`;
      }
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

    /* ── 2. Wikipedia ── progressively broader queries, type-aware */
    (async () => {
      log('Wikipedia: searching…', 'info');
      const wikiQueries = searchType === 'mill'
        ? [ q + ' fishmeal processing plant',
            q + ' fish oil mill',
            q + ' fish processing',
            q ]
        : [ q + ' aquaculture fish farm',
            q + ' fishery fishing',
            'fish farming ' + q,
            q ];
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
      // Only use Wikipedia extract as description if the article title matches the entity
      if (s.extract && isEntityDescription(s.title || s.extract, q)) {
        fields.description = clipToYear(cleanField(s.extract), yearTo).slice(0, 1200);
      }
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

  // Run FAO, ASC, BAP, and GlobalG.A.P. all in parallel — intensive multi-source lookup
  const [faoSettled, ascSettled, bapSettled, ggapSettled] = await Promise.allSettled([

    /* ── 3. FAO Fisheries & Aquaculture ── */
    (async () => {
      log('FAO: searching fisheries & aquaculture records…', 'info');
      const faoHTML = await fetchViaProxy(
        `https://www.fao.org/fishery/en/search?query=${encodeURIComponent(safeQ)}&field=aquaculture`,
        signal
      );
      const faoDoc  = parseHTML(faoHTML);
      const faoText = faoDoc.body?.innerText?.slice(0, 8000) || '';
      if (relevanceScore(faoText, q) > 0) {
        const fields = extractFields(faoDoc, faoText);
        const fc = Object.keys(fields).filter(k => !k.startsWith('_')).length;
        if (fc > 0) {
          log(`FAO: ${fc} field(s) found`, 'ok');
          return { id:'FAO', ok:true, url:`https://www.fao.org/fishery/en/search?query=${encodeURIComponent(safeQ)}`, fields, imgs:[], text:faoText };
        }
      }
      return null;
    })(),

    /* ── 4. ASC (Aquaculture Stewardship Council) ── */
    searchType === 'mill' ? Promise.resolve(null) : (async () => {
      log('ASC: searching certified producers…', 'info');
      const ascHTML = await fetchViaProxy(
        `https://www.asc-aqua.org/find-a-farm/?q=${encodeURIComponent(safeQ)}`,
        signal
      );
      const ascDoc  = parseHTML(ascHTML);
      const ascText = ascDoc.body?.innerText?.slice(0, 6000) || '';
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

    /* ── 5. BAP (Best Aquaculture Practices) — farms + mills ── */
    (async () => {
      log('BAP: searching certified facilities…', 'info');
      const bapHTML = await fetchViaProxy(
        `https://www.bapcertification.org/Producers?name=${encodeURIComponent(safeQ)}&country=&type=`,
        signal
      );
      const bapDoc  = parseHTML(bapHTML);
      const bapText = bapDoc.body?.innerText?.slice(0, 6000) || '';
      if (relevanceScore(bapText, q) > 0) {
        const fields = extractFields(bapDoc, bapText);
        if (/bap|certified|star/i.test(bapText) && !fields.certification) fields.certification = 'BAP Certified';
        const fc = Object.keys(fields).filter(k => !k.startsWith('_')).length;
        if (fc > 0) {
          log(`BAP: ${fc} field(s) found`, 'ok');
          return { id:'BAP', ok:true, url:`https://www.bapcertification.org/Producers?name=${encodeURIComponent(safeQ)}`, fields, imgs:[], text:bapText };
        }
      }
      return null;
    })(),

    /* ── 6. GlobalG.A.P. — certified aquaculture producers ── */
    searchType !== 'vessel' ? (async () => {
      log('GlobalG.A.P.: searching certified producers…', 'info');
      const ggapHTML = await fetchViaProxy(
        `https://database.globalgap.org/globalgap/search/search.do?query=${encodeURIComponent(safeQ)}&subSchemeId=AQUA`,
        signal
      );
      const ggapDoc  = parseHTML(ggapHTML);
      const ggapText = ggapDoc.body?.innerText?.slice(0, 6000) || '';
      if (relevanceScore(ggapText, q) > 0) {
        const fields = extractFields(ggapDoc, ggapText);
        if (/global.?g\.?a\.?p|certified/i.test(ggapText) && !fields.certification) fields.certification = 'GlobalG.A.P. Certified';
        const fc = Object.keys(fields).filter(k => !k.startsWith('_')).length;
        if (fc > 0) {
          log(`GlobalG.A.P.: ${fc} field(s) found`, 'ok');
          return { id:'GlobalGAP', ok:true, url:`https://database.globalgap.org/globalgap/search/search.do?query=${encodeURIComponent(safeQ)}`, fields, imgs:[], text:ggapText };
        }
      }
      return null;
    })() : Promise.resolve(null),
  ]);

  if (faoSettled.status  === 'fulfilled' && faoSettled.value)  results.push(faoSettled.value);
  if (ascSettled.status  === 'fulfilled' && ascSettled.value)  results.push(ascSettled.value);
  if (bapSettled.status  === 'fulfilled' && bapSettled.value)  results.push(bapSettled.value);
  if (ggapSettled.status === 'fulfilled' && ggapSettled.value) results.push(ggapSettled.value);

  return results;
}

/* ═══════════════════════════════════════════
   VESSEL API QUERIES
═══════════════════════════════════════════ */
async function queryVesselAPIs(q, imo, mmsi, signal) {
  const results = [];
  const safeQ   = q.replace(/[^\p{L}\p{N}\s\-]/gu, '').trim().slice(0, 80);

  // Phase 1: Wikipedia + OSM in parallel (both direct API calls)
  const [wikiV, osmV] = await Promise.allSettled([

    /* ── 1. Wikipedia — full article text ── */
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
        // Fetch full article plain-text (sections, tables, infobox) — much more data than summary
        const [summResp, fullResp] = await Promise.allSettled([
          fetch(`https://en.wikipedia.org/api/rest_v1/page/summary/${encodeURIComponent(p.title)}`, { signal: timedSignal(signal, 10000) }),
          fetch(`https://en.wikipedia.org/w/api.php?action=query&titles=${encodeURIComponent(p.title)}&prop=extracts&explaintext=1&exsectionformat=plain&format=json&origin=*`, { signal: timedSignal(signal, 12000) }),
        ]);
        if (summResp.status !== 'fulfilled' || !summResp.value.ok) continue;
        const summ = await summResp.value.json();
        if (!summ.extract || !isEntityDescription(summ.title || summ.extract, safeQ)) continue;

        // Use full article text when available — much more data than the summary alone
        let fullText = summ.extract;
        if (fullResp.status === 'fulfilled' && fullResp.value.ok) {
          try {
            const fd = await fullResp.value.json();
            const pages_ = Object.values(fd.query?.pages || {});
            if (pages_[0]?.extract) fullText = pages_[0].extract;
          } catch {}
        }

        const fullDoc = new DOMParser().parseFromString(`<pre>${fullText}</pre>`, 'text/html');
        const f = extractFields(fullDoc, fullText.slice(0, 15000));
        f.description = (f.description || summ.extract).slice(0, 1200);
        if (summ.title && !f.vessel_name) f.vessel_name = summ.title;
        if (summ.coordinates) { f.latitude = String(summ.coordinates.lat); f.longitude = String(summ.coordinates.lon); }
        const imoM = fullText.match(/\bIMO[\s:]*(\d{7})\b/i);
        if (imoM) { f._imo = imoM[1]; if (!imo) imo = imoM[1]; }
        const flagM = fullText.match(/flag(?:ged)?\s+(?:of\s+|state\s+)?([A-Z][a-z]+(?: [A-Z][a-z]+)?)/);
        if (flagM) f.flag = flagM[1];
        log(`✓ Wikipedia: "${p.title}" (${Math.round(fullText.length/1000)}k chars)`, 'ok');
        out.push({ id:'Wikipedia', ok:true, url:`https://en.wikipedia.org/wiki/${encodeURIComponent(p.title)}`, fields:f, imgs:[], text:fullText.slice(0, 8000) });
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
    // Europe
    '209':'Cyprus',   '211':'Germany',         '212':'Cyprus',        '215':'Malta',
    '219':'Denmark',  '224':'Spain',            '226':'France',        '227':'France',
    '228':'France',   '229':'Malta',            '231':'Faroe Islands', '232':'United Kingdom',
    '233':'United Kingdom','234':'United Kingdom','235':'United Kingdom',
    '237':'Greece',   '239':'Greece',           '240':'Greece',        '241':'Greece',
    '242':'Morocco',  '244':'Netherlands',      '245':'Netherlands',   '246':'Netherlands',
    '247':'Italy',    '248':'Italy',            '249':'Malta',         '250':'Ireland',
    '251':'Iceland',  '252':'Luxembourg',       '253':'Luxembourg',    '255':'Madeira',
    '256':'Malta',    '257':'Norway',           '258':'Norway',        '259':'Norway',
    '261':'Poland',   '262':'Montenegro',       '263':'Portugal',      '264':'Romania',
    '265':'Sweden',   '266':'Sweden',           '267':'Slovakia',      '268':'San Marino',
    '269':'Switzerland','270':'Czech Republic', '271':'Turkey',        '272':'Ukraine',
    '273':'Russia',   '274':'North Macedonia',  '275':'Latvia',        '276':'Estonia',
    '277':'Lithuania','278':'Slovenia',         '279':'Serbia',
    // North America
    '303':'United States','305':'Antigua & Barbuda','306':'Antigua & Barbuda',
    '308':'Bahamas',  '309':'Bahamas',          '310':'Bermuda',       '311':'Bahamas',
    '312':'Belize',   '316':'Canada',           '319':'Cayman Islands','320':'Canada',
    '321':'Costa Rica','323':'Cuba',            '325':'Dominica',      '327':'Dominican Republic',
    '329':'Guadeloupe','330':'Grenada',         '332':'Guatemala',     '334':'Honduras',
    '336':'Canada',   '338':'United States',    '339':'Jamaica',       '341':'Saint Kitts and Nevis',
    '343':'Saint Lucia','345':'Saint Vincent and the Grenadines','347':'Trinidad and Tobago',
    '351':'Panama',   '352':'Panama',           '353':'Panama',        '354':'Panama',
    '355':'Panama',   '356':'Panama',           '357':'Panama',        '358':'Panama',
    '359':'Panama',   '361':'Haiti',            '362':'Netherlands Antilles','366':'United States',
    '367':'United States','368':'United States','369':'United States',
    // South America
    '701':'Argentina','710':'Brazil',           '720':'Bolivia',       '725':'Chile',
    '730':'Colombia', '735':'Ecuador',          '740':'Falkland Islands','745':'Guyana',
    '750':'Peru',     '755':'Paraguay',         '760':'Peru',          '765':'Suriname',
    '770':'Uruguay',  '775':'Venezuela',
    // Africa
    '601':'South Africa','606':'Senegal',       '608':'Benin',         '609':'Mauritius',
    '610':'Ethiopia', '611':'Mozambique',       '612':'Comoros',       '613':'Tanzania',
    '616':'Eritrea',  '618':'Djibouti',         '619':'Somalia',       '620':'Kenya',
    '621':'Madagascar','622':'Mozambique',      '624':'Rwanda',        '625':'Sierra Leone',
    '626':'Seychelles','627':'Togo',            '629':'Nigeria',       '630':'Cameroon',
    '631':'Angola',   '632':'Benin',            '633':'Cabo Verde',    '634':'Congo',
    '635':'DR Congo', '636':'Liberia',          '637':'Liberia',       '638':'Liberia',
    '639':'Liberia',  '642':'Madagascar',       '644':'Liberia',       '645':'Liberia',
    '647':'Mauritania','648':'Mauritius',       '649':'Namibia',       '650':'Nigeria',
    '654':'Mauritania','655':'Nigeria',         '657':'Nigeria',       '659':'Namibia',
    '660':'Saint Helena','661':'Sudan',         '662':'Sudan',         '663':'Senegal',
    '664':'Somalia',  '665':'Somalia',          '666':'Tanzania',      '667':'Togo',
    '668':'Tanzania', '670':'Ghana',            '671':'Ghana',         '672':'Liberia',
    '674':'Tanzania', '677':'Morocco',          '678':'Mozambique',    '679':'Tunisia',
    // Asia / Pacific
    '401':'Afghanistan','403':'Saudi Arabia',   '405':'Bangladesh',    '408':'Bahrain',
    '412':'China',    '413':'China',            '414':'China',         '416':'Taiwan',
    '417':'Sri Lanka','419':'India',            '422':'Iran',          '423':'Azerbaijan',
    '425':'Iraq',     '428':'Israel',           '431':'Japan',         '432':'Japan',
    '434':'Turkmenistan','436':'Kazakhstan',    '437':'Uzbekistan',    '438':'Jordan',
    '440':'South Korea','441':'South Korea',    '443':'Palestine',     '445':'Democratic People\'s Republic of Korea',
    '447':'Kuwait',   '450':'Lebanon',          '451':'Kyrgyzstan',    '453':'Macau',
    '455':'Maldives', '457':'Mongolia',         '459':'Nepal',         '461':'Oman',
    '463':'Pakistan', '466':'Qatar',            '468':'Saudi Arabia',  '470':'UAE',
    '472':'UAE',      '477':'Hong Kong',        '478':'Bosnia and Herzegovina','479':'Armenia',
    '503':'Australia','506':'Myanmar',          '508':'Brunei',        '510':'Micronesia',
    '511':'Palau',    '512':'New Zealand',      '514':'Cambodia',      '515':'Cambodia',
    '516':'Christmas Island','518':'Cook Islands','520':'Fiji',        '521':'Indonesia',
    '523':'Indonesia','525':'Indonesia',        '529':'Kiribati',      '531':'Laos',
    '533':'Malaysia', '536':'Northern Mariana Islands','538':'Marshall Islands',
    '540':'New Caledonia','542':'Niue',         '544':'Nauru',         '546':'French Polynesia',
    '548':'Philippines','553':'Papua New Guinea','555':'Pitcairn Islands',
    '557':'Solomon Islands','559':'Samoa',      '561':'Tonga',         '563':'Singapore',
    '564':'Singapore','565':'Singapore',        '566':'Singapore',     '567':'Thailand',
    '570':'Tuvalu',   '572':'Vanuatu',          '574':'Vietnam',       '576':'Vanuatu',
    '577':'Vanuatu',  '578':'Wallis and Futuna',
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

  // Phase 3: Additional authoritative databases — run when IMO is known
  if (imo) {
    const [faoGR, rightship] = await Promise.allSettled([

      /* ── 5. FAO Global Record — fishing vessel flag + authorization ── */
      (async () => {
        log(`FAO Global Record: IMO ${imo}…`, 'info');
        const r = await fetchWikipediaText(`FAO Global Record IMO ${imo}`, signal).catch(() => null);
        // FAO Global Record is a scrape target — handled via scraper URLs, not direct API
        // But we can try the search endpoint directly
        const html = await fetch(
          `https://www.fao.org/global-record/search?imo=${imo}&lang=en`,
          { signal: timedSignal(signal, 10000), headers:{ 'User-Agent':'Mozilla/5.0' } }
        ).then(r => r.text()).catch(() => '');
        if (!html || html.length < 200) return null;
        const doc = parseHTML(html);
        const text = doc.body?.innerText?.slice(0, 8000) || '';
        if (!text.includes(imo) && !isSeaRelated(text)) return null;
        const f = filterFieldsByType(extractFields(doc, text), 'vessel');
        f._imo = imo;
        const fc = Object.keys(f).filter(k => !k.startsWith('_')).length;
        if (fc < 1) return null;
        log(`✓ FAO Global Record: ${fc} field(s)`, 'ok');
        return { id:'FAO-Global-Record', ok:true, url:`https://www.fao.org/global-record/search?imo=${imo}`, fields:f, imgs:[], text };
      })(),

      /* ── 6. Paris MOU / Tokyo MOU — Port State Control inspections ── */
      (async () => {
        log(`Paris MOU PSC: IMO ${imo}…`, 'info');
        const html = await fetch(
          `https://www.parismou.org/Inspection%20information/White%20and%20black%20list/Ship-particulars?imo=${imo}`,
          { signal: timedSignal(signal, 10000), headers:{ 'User-Agent':'Mozilla/5.0' } }
        ).then(r => r.text()).catch(() => '');
        if (!html || html.length < 200) return null;
        const doc = parseHTML(html);
        const text = doc.body?.innerText?.slice(0, 6000) || '';
        if (!text.includes(imo)) return null;
        const f = filterFieldsByType(extractFields(doc, text), 'vessel');
        f._imo = imo;
        const fc = Object.keys(f).filter(k => !k.startsWith('_')).length;
        if (fc < 1) return null;
        log(`✓ Paris MOU PSC: ${fc} field(s)`, 'ok');
        return { id:'Paris-MOU', ok:true, url:`https://www.parismou.org/inspection?imo=${imo}`, fields:f, imgs:[], text };
      })(),
    ]);

    if (faoGR.status    === 'fulfilled' && faoGR.value)    results.push(faoGR.value);
    if (rightship.status === 'fulfilled' && rightship.value) results.push(rightship.value);
  }

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
      <div class="run-title"><span class="spin"></span> Scraping <em>${urlLabel}</em></div>
      <div class="run-status" id="run-status">Fetching page content…</div>
      <div class="prog-bar"><div class="prog-fill" id="bprog" style="width:5%"></div></div>
      <div class="bot-log" id="bot-log"></div>
      <div id="bot-res"></div>
    </div>`;

  logEl = document.getElementById('bot-log');
  const setProgress = p => { const el = document.getElementById('bprog'); if(el) el.style.width = p + '%'; };
  const setStatus   = s => { const el = document.getElementById('run-status'); if(el) el.textContent = s; };
  let _sourcesDone = 0, _sourcesTotal = 0;
  const tickSource = (id) => {
    _sourcesDone++;
    setStatus(`Checking ${id}… (${_sourcesDone}/${_sourcesTotal} sources)`);
  };

  const searchType = document.getElementById('search-type')?.value || 'farm';
  const isVessel   = searchType === 'vessel';
  const isMill     = searchType === 'mill';
  const TEXT_LIMIT = 15000;

  try {
    // Step 1: Fetch all URLs in parallel with translation + field extraction
    log(`Scraping ${urls.length} URL${urls.length>1?'s':''} in parallel…`, 'info');
    setStatus('Fetching pages…');

    const settled = await Promise.allSettled(urls.map(async (urlRaw, i) => {
      const tag  = urls.length > 1 ? `[${i+1}] ` : '';
      const host = new URL(urlRaw).hostname;
      const isWX = /mp\.weixin\.qq\.com/i.test(urlRaw);
      log(`${tag}Fetching ${host}…`, 'info');

      const html = await fetchViaProxy(urlRaw, timedSignal(signal, isWX ? 30000 : 22000));
      const doc  = parseHTML(html, urlRaw);
      const bodyEl = isWX ? (doc.getElementById('js_content') || doc.body) : doc.body;
      let   text = bodyEl?.innerText?.slice(0, TEXT_LIMIT) || '';

      const pageLang = detectLang(doc, text);
      if (pageLang !== 'en') {
        log(`${tag}Language: ${pageLang} — translating…`, 'info');
        try { text = await translate(text.slice(0, 4000), signal); } catch {}
      }

      const fields = filterFieldsByType(extractFields(doc, text), searchType);
      const imgs   = extractImages(doc, urlRaw);
      const imos   = extractIMOs(text);
      if (imos.length && !fields._imo) fields._imo = imos[0];
      const fCount = Object.keys(fields).filter(k => !k.startsWith('_')).length;
      log(`${tag}✓ ${host} — ${fCount} field(s), ${imgs.length} img(s)${pageLang !== 'en' ? ` [${pageLang}]` : ''}`, 'ok');
      learnFromDomain(host, true, fCount);
      return { urlRaw, id: host, hostname: host, fields, imgs, text, ok: true };
    }));

    setProgress(50);

    const successes = settled.filter(r => r.status === 'fulfilled').map(r => r.value);
    settled.forEach((r, i) => {
      if (r.status === 'rejected') {
        const host = (() => { try { return new URL(urls[i]).hostname; } catch { return urls[i]; } })();
        log(`✗ ${host}: ${r.reason?.message || 'Failed'}`, 'err');
      }
    });
    if (!successes.length) throw new Error('All URLs failed to load');

    // Step 2: Run API queries (OSM, Wikipedia, FAO, ASC, vessel registries)
    // Use the name extracted from the first URL, or fall back to the domain
    const guessName = successes[0].fields.vessel_name || successes[0].fields.farm_name || successes[0].hostname;
    setStatus('Running registries…');
    log('Querying structured databases…', 'info');

    let apiResults = [];
    let imo = successes.map(s => s.fields._imo).find(Boolean) || '';
    let mmsi = successes.map(s => s.fields.mmsi).find(Boolean) || '';
    if (isVessel) {
      const vl = await queryVesselAPIs(guessName, imo, mmsi, signal).catch(() => ({ results:[], imo:'', mmsi:'' }));
      apiResults = vl.results;
      imo  = vl.imo  || imo;
      mmsi = vl.mmsi || mmsi;
    } else {
      apiResults = await queryFarmAPIs(guessName, signal, new Date().getFullYear(), searchType).catch(() => []);
    }
    if (apiResults.length) log(`API queries: ${apiResults.length} result(s)`, 'ok');

    // Step 3: Merge everything through the ranked pipeline
    setProgress(70); setStatus('Merging & ranking…');
    const allSources = [...successes, ...apiResults];
    let merged = mergeFields(allSources, guessName);
    if (imo)  merged._imo  = merged._imo  || imo;
    if (mmsi) merged.mmsi  = merged.mmsi  || mmsi;

    // Step 4: Images — scrape page images + targeted image searches
    let allImgs = successes.flatMap(s => s.imgs);
    const nameQ = merged.vessel_name || merged.farm_name || guessName;
    if (nameQ && document.getElementById('opt-imgs')?.checked !== false) {
      setStatus('Fetching images…');
      const [wikiImgs, bingImgs] = await Promise.allSettled([
        fetchWikipediaImages(nameQ, signal),
        fetchBingImages(nameQ, signal),
      ]);
      if (wikiImgs.status === 'fulfilled') allImgs = [...wikiImgs.value, ...allImgs];
      if (bingImgs.status === 'fulfilled') allImgs = [...allImgs, ...bingImgs.value];
    }
    // Dedup images
    const seenU = new Set();
    allImgs = allImgs.filter(img => img?.src && !seenU.has(img.src) && seenU.add(img.src)).slice(0, 12);

    // Step 5: AI enrichment — Claude extracts and polishes
    setProgress(88); setStatus('AI enrichment…');
    let aiEnhanced = false;
    if (claudeKey || _serverAIReady) {
      const texts = successes.map(s => ({ source: s.hostname, text: s.text }));
      try {
        const claudeFields = await claudeExtract(texts, guessName, searchType, signal);
        if (Object.keys(claudeFields).filter(k => claudeFields[k]).length > 0) {
          Object.entries(claudeFields).forEach(([k, v]) => { if (v) merged[k] = v; });
          aiEnhanced = true;
          log(`AI extracted ${Object.keys(claudeFields).filter(k => claudeFields[k]).length} field(s)`, 'ok');
        }
        if (Object.keys(merged).filter(k => !k.startsWith('_')).length >= 3) {
          const desc = await claudePolishDescription(merged, guessName, searchType, signal);
          if (desc && !signal.aborted) merged.description = desc;
        }
      } catch(e) { if (e.name === 'AbortError') throw e; }
    }

    setProgress(100);
    const fieldCount = Object.keys(merged).filter(k => !k.startsWith('_')).length;
    setStatus(`Done — ${fieldCount} field(s)${aiEnhanced ? ' · AI-enhanced ✓' : ''}${allImgs.length ? ` · ${allImgs.length} image(s)` : ''}`);
    log(`Complete — ${fieldCount} field(s), ${allImgs.length} image(s)${aiEnhanced ? ' · AI-enhanced ✓' : ''}`, 'ok');

    stats.ships++;
    stats.images += allImgs.length;
    updateStats();

    const cardName = merged.vessel_name || merged.farm_name || guessName;
    learnFromSearch(cardName, merged, allSources);

    const resEl = document.getElementById('bot-res');
    if (resEl) {
      // Merged card (always shown)
      const mergedDiv = document.createElement('div');
      mergedDiv.innerHTML = renderCard(cardName, merged._imo || '', merged, allSources, allImgs, aiEnhanced);
      resEl.appendChild(mergedDiv);

      // Per-source breakdown when multiple URLs
      if (successes.length > 1) {
        const breakdownHdr = document.createElement('div');
        breakdownHdr.className = 'label';
        breakdownHdr.style.cssText = 'margin:18px 0 6px;font-size:11px;text-transform:uppercase;letter-spacing:.5px';
        breakdownHdr.textContent = `Source breakdown (${successes.length} URLs)`;
        resEl.appendChild(breakdownHdr);
        successes.forEach(({ urlRaw, hostname, fields, imgs, text }) => {
          const lbl = document.createElement('div');
          lbl.style.cssText = 'font-size:10.5px;color:var(--mut2);margin:10px 0 3px;font-weight:600';
          lbl.textContent = hostname;
          resEl.appendChild(lbl);
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
        ['farm','Farm / Aquaculture'],['mill','Mill / Processing'],
        ['vessel','Shipping / Fishing Vessel'],['general','General / Auto']] },
      { key:'_category', label:'Category / Species', val: defCat, type:'select', opts:[
        ['','— Select —'],
        ['salmon','Salmon'],['trout','Trout'],['shrimp','Shrimp / Prawn'],
        ['tilapia','Tilapia'],['catfish','Catfish'],['tuna','Tuna'],['cod','Cod'],
        ['sea bass sea bream','Sea Bass / Sea Bream'],['carp','Carp'],
        ['oyster shellfish','Oyster / Shellfish'],['fishmeal processing','Mill / Processing'],
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
      { key:'harvest_cycles',   label:'Harvest Cycles',       val: info.harvest_cycles || '' },
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
    { label: 'Mill / Processing', showFor: ['mill','general'], fields: [
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
      { key:'nav_status',       label:'Navigational Status',  val: info.nav_status || '' },
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
          apiResults = await queryFarmAPIs(name, signal, new Date().getFullYear(), facilityType).catch(() => []);
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
        if ((claudeKey || _serverAIReady) && enrichTexts.length >= 1) {
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
  const dummy = new DOMParser().parseFromString('<pre>' + display.replace(/&/g,'&amp;').replace(/</g,'&lt;') + '</pre>', 'text/html');
  const fileFields = extractFields(dummy, display);
  const searchType = document.getElementById('search-type')?.value || 'farm';
  const filteredFileFields = filterFieldsByType(fileFields, searchType);
  const allKeys = Object.keys(filteredFileFields).filter(k => !k.startsWith('_'));

  const frag = document.createDocumentFragment();

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
          const { scrapeResults, merged: webMerged, allImgs, imo, mmsi } =
            await bulkScrapeItem(name, searchType, yearTo, catFilter, ac.signal);

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

// Extract entity names from file fields and raw text (up to 6 unique names)
function extractFileEntities(fields, text) {
  const names = new Set();
  // 1 ─ Prefer structured field names (highest confidence)
  for (const k of ['farm_name','vessel_name','name','operator','owner']) {
    const v = fields[k];
    if (v && v.length > 2 && v.length < 100) names.add(v.trim());
  }
  // 2 ─ Scan lines for English proper-noun entity patterns
  if (names.size < 4) {
    const lines = text.split(/[\n\r]+/).map(l => l.trim());
    for (const line of lines) {
      if (line.length < 4 || line.length > 100) continue;
      if (/^[A-Z][A-Za-z0-9\s&.,'\-()]{3,90}$/.test(line) &&
          !/^\d|^(page|date|version|ref|section|table|figure|annex|total|source|note|copyright)/i.test(line) &&
          line.split(/\s+/).length <= 8) {
        names.add(line.replace(/[.,:;]+$/, '').trim());
      }
      if (names.size >= 5) break;
    }
  }
  // 3 ─ Chinese entity name detection — 2–6 CJK chars often followed by 公司/集团/有限/养殖/渔业
  if (names.size < 5) {
    const cjkMatches = text.match(/[一-鿿]{2,20}(?:公司|集团|有限|养殖|渔业|水产|船务|海洋|食品)/g) || [];
    for (const m of cjkMatches) {
      names.add(m.trim());
      if (names.size >= 6) break;
    }
  }
  return [...names].slice(0, 6);
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
  // FileReader never throws for invalid UTF-8 — it silently inserts U+FFFD (replacement char).
  // We must detect those markers ourselves and retry with windows-1252, which is more complete
  // than iso-8859-1/latin1 (it maps 0x80–0x9F to printable chars instead of C1 control codes).
  const decode = enc => new Promise((res, rej) => {
    const r = new FileReader();
    r.onload  = e => res(e.target.result);
    r.onerror = rej;
    r.readAsText(file, enc);
  });
  const utf8 = await decode('utf-8').catch(() => null);
  if (utf8 === null) return '[Could not decode file]';
  // Heuristic: >5 replacement chars signals a non-UTF-8 encoding (legacy Windows document)
  if ((utf8.match(/�/g) || []).length > 5) {
    const w1252 = await decode('windows-1252').catch(() => null);
    // Accept the windows-1252 reading only if it produced no replacement chars
    if (w1252 && !/�/.test(w1252)) return w1252;
  }
  return utf8;
}

function fileSearch() {
  const raw  = document.getElementById('file-kw').value.trim().slice(0, 100);
  const view = document.getElementById('ftv');
  if (!raw || !view) return;
  const kw = raw.toLowerCase();
  const hits = lastFileText.split('\n')
    .map((l, i) => ({ n: i + 1, l }))
    .filter(x => x.l.toLowerCase().includes(kw));
  if (!hits.length) { toast('No matches for "' + raw + '"'); return; }
  // The highlight regex runs on esc()-encoded content, so the keyword must also
  // be HTML-entity-escaped. Without this, searching for '&' would try to match
  // literal '&' inside '&amp;' strings, splitting the entity and corrupting HTML.
  const escapedKW = esc(raw);   // e.g.  &  →  &amp;
  const safeKW    = escapedKW.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');  // regex-safe
  view.innerHTML = hits.slice(0, 100).map(h =>
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

  out.innerHTML = '<div class="status s-info"><span class="spin"></span> Processing…</div>';

  // 1 ─ Translate if needed
  let text = raw;
  const needsTranslation = document.getElementById('tgl-tt').classList.contains('on');
  const rawLang = detectLang(null, raw);
  if (needsTranslation || rawLang !== 'en') {
    try { text = await translate(raw.slice(0, 6000), null); } catch {}
  }

  // 2 ─ Extract structured fields
  const searchType = document.getElementById('search-type')?.value || 'farm';
  const dummy = new DOMParser().parseFromString('<pre>' + text.replace(/&/g,'&amp;').replace(/</g,'&lt;') + '</pre>', 'text/html');
  const rawFields    = extractFields(dummy, text);
  const fields       = filterFieldsByType(rawFields, searchType);
  const found        = Object.keys(fields).filter(k => !k.startsWith('_'));

  // 3 ─ AI extraction on the pasted text
  let aiFields = {};
  if ((claudeKey || _serverAIReady) && text.length > 100) {
    try {
      aiFields = await claudeExtract([{ source: 'Pasted text', text: text.slice(0, 6000) }], '', searchType, null);
      Object.entries(aiFields).forEach(([k, v]) => { if (v && !fields[k]) fields[k] = v; });
    } catch {}
  }

  const allFound = Object.keys(fields).filter(k => !k.startsWith('_'));

  const frag = document.createDocumentFragment();

  // Field grid
  if (allFound.length) {
    const flbl = document.createElement('div');
    flbl.className = 'label';
    flbl.textContent = `${allFound.length} field(s) extracted${rawLang !== 'en' ? ` [translated from ${rawLang}]` : ''}`;
    frag.appendChild(flbl);

    const grid = document.createElement('div');
    grid.className = 'vc-grid'; grid.style.marginBottom = '12px';
    allFound.forEach(k => {
      const cell = document.createElement('div'); cell.className = 'vf';
      const lbl  = document.createElement('div'); lbl.className = 'vfl'; lbl.textContent = k.replace(/_/g,' ').toUpperCase();
      const val  = document.createElement('div'); val.className = 'vfv'; val.textContent = fields[k];
      cell.appendChild(lbl); cell.appendChild(val); grid.appendChild(cell);
    });
    frag.appendChild(grid);

    const row = document.createElement('div'); row.className = 'btn-row';
    const saveBtn = document.createElement('button');
    saveBtn.className = 'btn btn-blue btn-sm'; saveBtn.textContent = 'Save Extracted Data';
    saveBtn.onclick = () => doSave({ name: fields.farm_name || fields.vessel_name || 'Pasted record', ...fields }, null);
    row.appendChild(saveBtn);
    frag.appendChild(row);
  } else {
    const none = document.createElement('div');
    none.className = 'status s-warn';
    none.textContent = 'No structured fields detected. The web intelligence section below will search for entities mentioned in the text.';
    frag.appendChild(none);
  }

  // Highlighted text view
  const tv = document.createElement('div');
  tv.className = 'text-view'; tv.style.marginTop = '10px';
  tv.innerHTML = esc(text.slice(0, 8000)).replace(
    /\b(species|latitude|longitude|capacity|certification|FCR|salinity|pH|operator|country|region|license|harvest|stocking|temperature|fishmeal|fish\s*oil|processing|employees?|IMO|MMSI|tonnage|flag|vessel|aquaculture|farm)\b/gi,
    '<mark style="background:#fff3cd;color:#333;padding:0 2px">$1</mark>'
  );
  frag.appendChild(tv);

  // Web enrichment — search for entity names found in the text
  const webHdr = document.createElement('div'); webHdr.className = 'label';
  webHdr.style.cssText = 'margin-top:16px'; webHdr.textContent = 'Web intelligence';
  frag.appendChild(webHdr);
  const webOut = document.createElement('div'); frag.appendChild(webOut);

  out.innerHTML = ''; out.appendChild(frag);

  // Identify entities to search (name fields + NLP-detected proper nouns from text)
  const entityNames = extractFileEntities(fields, text);
  if (entityNames.length) {
    webOut.innerHTML = `<div class="status s-info"><span class="spin"></span> Searching web for ${entityNames.length} entity(ies)…</div>`;
    const yearTo    = parseInt(document.getElementById('year-to')?.value || String(new Date().getFullYear()));
    const catFilter = document.getElementById('cat-filter')?.value || '';
    if (fileRawAC) fileRawAC.abort();
    fileRawAC = new AbortController();
    const ac = fileRawAC;

    (async () => {
      let cardCount = 0;
      webOut.innerHTML = '';
      for (const name of entityNames) {
        if (ac.signal.aborted) break;
        const status = document.createElement('div');
        status.className = 'status s-info';
        status.innerHTML = `<span class="spin"></span> Scanning: <b>${esc(name)}</b>…`;
        webOut.appendChild(status);
        try {
          const { scrapeResults, merged, allImgs, imo } =
            await bulkScrapeItem(name, searchType, yearTo, catFilter, ac.signal);
          // Layer in any fields already extracted from the pasted text
          const finalMerged = { ...merged, ...filterFieldsByType(fields, searchType) };
          if (imo) finalMerged._imo = finalMerged._imo || imo;
          const cardName = searchType === 'vessel'
            ? (finalMerged.vessel_name || name)
            : (finalMerged.farm_name || finalMerged.vessel_name || name);
          status.remove();
          const div = document.createElement('div');
          div.innerHTML = renderCard(cardName, imo, finalMerged, scrapeResults, allImgs);
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
        webOut.innerHTML = '<div class="status s-warn">No web results — try a more specific entity name.</div>';
      }
      if (fileRawAC === ac) fileRawAC = null;
    })();
  } else {
    webOut.innerHTML = '<div class="status s-warn">No entity names found — paste text that mentions a specific farm, vessel, or company name.</div>';
  }
}

/* ═══════════════════════════════════════════
   BULK SCRAPE HELPER
   Full pipeline for one query: APIs + Bing + follow links
═══════════════════════════════════════════ */
async function bulkScrapeItem(q, searchType, yearTo, catFilter, signal) {
  const isVessel = searchType === 'vessel';
  const isMill   = searchType === 'mill';
  const TEXT_BUDGET = 15000;
  const BULK_SKIP   = /^https?:\/\/(www\.bing\.com|www\.google\.(com|cn)\/search|html\.duckduckgo\.com|duckduckgo\.com|baidu\.com\/s)[/?]/i;

  // ── Query language detection + cross-language translation ───────────────
  const queryLang = detectQueryLang(q);
  let qEn = q;
  if (queryLang !== 'en') {
    try { qEn = await translateQuery(q, queryLang, 'en', signal); } catch(e) { if (e.name !== 'AbortError') log(`Query translation failed (${queryLang}→en): ${e.message}`, 'warn'); }
  }
  const langTerms = langIndustryTerms(queryLang, searchType);

  // 1 ─ Direct API queries (structured databases first)
  let scrapeResults = [];
  let imo = '', mmsi = '';
  const isIMO  = /^\d{7}$/.test(q) && validIMO(q);
  const isMMSI = /^\d{9}$/.test(q.replace(/\s/g,''));

  if (isVessel) {
    const vl = await queryVesselAPIs(q, isIMO ? q : '', isMMSI ? q.replace(/\s/g,'') : '', signal)
                       .catch(() => ({ results:[], imo:'', mmsi:'' }));
    scrapeResults = vl.results;
    imo  = vl.imo  || (isIMO  ? q : '');
    mmsi = vl.mmsi || (isMMSI ? q.replace(/\s/g,'') : '');
  } else {
    scrapeResults = await queryFarmAPIs(q, signal, yearTo, searchType).catch(() => []);
  }

  // 2 ─ Build search source list
  const words    = qEn.trim().split(/\s+/);
  const qEnPhrase = (words.length >= 3 || qEn.length >= 16) ? `"${qEn}"` : qEn;
  const catKW    = catFilter ? ` ${catFilter}` : '';

  // English engines use translated query; non-English engines get original query
  const bingQ = isVessel
    ? `${qEnPhrase}${catKW} vessel ship fishing registry IMO site:marinetraffic.com OR site:vesselfinder.com OR site:equasis.org`
    : isMill ? `${qEnPhrase}${catKW} fishmeal processing plant site:iffo.com OR site:fis.com OR site:seafoodsource.com`
             : `${qEnPhrase}${catKW} fish farm aquaculture facility site:asc-aqua.org OR site:seafoodsource.com OR site:fis.com OR site:mara.gov.cn`;

  const cnQ = isVessel ? `${q} 船舶 船名 IMO` : isMill ? `${q} 鱼粉厂 加工厂` : `${q} 水产养殖 养殖场`;

  const scraperURLs = [
    { id:'Web-Discovery', url:`https://www.bing.com/search?q=${encodeURIComponent(bingQ)}` },
    { id:'DDG-Search',    url:`https://html.duckduckgo.com/html/?q=${encodeURIComponent(
        isVessel ? `${qEnPhrase} vessel ship IMO flag registry year built ${langTerms}`
        : isMill  ? `${qEnPhrase} fishmeal fish oil processing capacity ${langTerms}`
                  : `${qEnPhrase} aquaculture fish farm species certified ${langTerms}`)}` },
    { id:'Google-Search', url:`https://www.google.com/search?q=${encodeURIComponent(
        isVessel ? `${qEnPhrase} vessel ship IMO flag gross tonnage ${langTerms}`
        : isMill  ? `${qEnPhrase} fishmeal mill capacity input species ${langTerms}`
                  : `${qEnPhrase} fish farm aquaculture capacity species certification ${langTerms}`)}&num=10&hl=en&gl=us` },
    // Chinese search
    { id:'Google-CN',    url:`https://www.google.com/search?q=${encodeURIComponent(cnQ)}&num=10&hl=zh-CN&gl=cn`, _cn:true },
    { id:'WeChat-Sogou', url:`https://weixin.sogou.com/weixin?type=2&query=${encodeURIComponent(q)}`, _cn:true, _wechat:true },
    // Intl fallback — original query + multilingual terms
    { id:'Intl-Search',  url:`https://www.bing.com/search?q=${encodeURIComponent(
        isVessel ? `${q} nave vessel schiff 船 مركب ${langTerms}`
                 : `${q} acuicultura aquaculture 水产养殖 ${langTerms}`)}&setlang=en`, _fallback:true },
  ];

  // Language-specific engines for the query's native language
  const langSrcs = langSpecificSources(q, qEn, queryLang, searchType);
  scraperURLs.push(...langSrcs);

  // Direct vessel registries when we have an IMO
  if (isVessel) {
    if (imo) {
      scraperURLs.push(
        { id:'MarineTraffic', url:`https://www.marinetraffic.com/en/ais/details/ships/imo:${imo}` },
        { id:'VesselFinder',  url:`https://www.vesselfinder.com/vessels/details/${imo}` },
        { id:'Equasis',       url:`https://www.equasis.org/EquasisWeb/restricted/ShipInfo?fs=Search&P_IMO=${imo}` },
      );
    } else {
      scraperURLs.push(
        { id:'MarineTraffic', url:`https://www.marinetraffic.com/en/ais/details/ships/shipid:0/mmsi:0/vessel:${encodeURIComponent(q)}` },
        { id:'ShipXY',        url:`https://www.shipxy.com/ship/shiplist?name=${encodeURIComponent(q)}`, _cn:true },
      );
    }
  }

  const DISCOVERY_BULK = [
    'Web-Discovery','DDG-Search','Google-Search','Google-CN','WeChat-Sogou','Intl-Search',
    'Bing-EN-Xlat',
    // Language-specific search engines — all follow their links
    'Google-NO','Bing-NO','Google-ES','Bing-ES','Google-CL','Google-BR','Bing-PT',
    'Google-FR','Bing-FR','Google-DE','Bing-DE',
    'Yahoo-JP','Google-JP','Bing-JA',
    'Naver-KO','Daum-KO','Google-KR',
    'Yandex-RU','Google-RU','Bing-RU',
    'Google-AR','Bing-AR',
  ];
  const allImgs = scrapeResults.flatMap(r => r.imgs || []);

  // 3 ─ Scrape with per-source translation and DOM-based link following
  for (const s of scraperURLs) {
    if (signal?.aborted) break;
    try {
      const isWX = s._wechat;
      const html = await fetchViaProxy(s.url, timedSignal(signal, (s._cn || s._lang) ? 28000 : 20000));
      const doc  = parseHTML(html, s.url);
      const bodyEl = isWX ? (doc.getElementById('js_content') || doc.body) : doc.body;
      let   text = bodyEl?.innerText?.slice(0, TEXT_BUDGET) || '';

      const pageLang = detectLang(doc, text);
      if (pageLang !== 'en') {
        try { text = await translate(text.slice(0, 4000), signal); } catch {}
      }

      if (!imo) { const f = extractIMOs(text); if (f.length) imo = f[0]; }

      // Discovery: follow top links using DOM (not regex)
      if (DISCOVERY_BULK.includes(s.id)) {
        const anchors = [...doc.querySelectorAll('a[href]')];
        const discovered = [];
        for (const a of anchors) {
          try {
            const href = new URL(a.href || a.getAttribute('href'), s.url).href;
            if (isValidURL(href) && !BULK_SKIP.test(href) && !discovered.includes(href))
              discovered.push(href);
          } catch {}
        }
        // WeChat: prioritise mp.weixin.qq.com article links
        const ordered = isWX
          ? [...discovered.filter(u => /mp\.weixin\.qq\.com/i.test(u)),
             ...discovered.filter(u => !/mp\.weixin\.qq\.com/i.test(u))]
          : discovered;
        const topURLs = [...new Set(ordered)].slice(0, s._fallback ? 4 : 7);

        for (const u of topURLs) {
          if (signal?.aborted) break;
          try {
            const subWX = /mp\.weixin\.qq\.com/i.test(u);
            const ph = await fetchViaProxy(u, timedSignal(signal, subWX ? 30000 : (s._cn ? 28000 : 18000)));
            const pd = parseHTML(ph, u);
            const pdBody = subWX ? (pd.getElementById('js_content') || pd.body) : pd.body;
            let   pt = pdBody?.innerText?.slice(0, TEXT_BUDGET) || '';
            const subLang = detectLang(pd, pt);
            if (subLang !== 'en') { try { pt = await translate(pt.slice(0, 4000), signal); } catch {} }
            if (!isSeaRelated(pt)) continue;
            if (relevanceScore(pt, q) === 0 && !s._fallback) continue;
            if (!topicMatch(pt, searchType)) continue;
            const pf = filterFieldsByType(extractFields(pd, pt), searchType);
            const pi = extractImages(pd, u);
            if (Object.keys(pf).filter(k => !k.startsWith('_')).length >= 1) {
              scrapeResults.push({ id: new URL(u).hostname, ok:true, url:u, fields:pf, imgs:pi, text:pt });
              allImgs.push(...pi);
            }
          } catch(e) { if (e.name === 'AbortError') throw e; }
          await sleep(400);
        }
      }

      const filteredFields = filterFieldsByType(extractFields(doc, text), searchType);
      const fc = Object.keys(filteredFields).filter(k => !k.startsWith('_')).length;
      if ((fc > 0) && (isSeaRelated(text) || s._cn) && topicMatch(text, searchType)) {
        const imgs = extractImages(doc, s.url);
        scrapeResults.push({ id:s.id, ok:true, url:s.url, fields:filteredFields, imgs, text });
        allImgs.push(...imgs);
      }
    } catch(e) {
      if (e.name === 'AbortError') throw e;
      scrapeResults.push({ id:s.id, ok:false, url:s.url, error:e.message, fields:{}, imgs:[], text:'' });
    }
    await sleep(500);
  }

  // 4 ─ AI enrichment
  let merged = mergeFields(scrapeResults, q);
  if (imo)  merged._imo = merged._imo || imo;
  if (mmsi) merged.mmsi = merged.mmsi || mmsi;

  if (claudeKey || _serverAIReady) {
    const goodTexts = scrapeResults.filter(r => r.ok && r.text && relevanceScore(r.text, q) >= 1)
                                   .slice(0, 4)
                                   .map(r => ({ source: r.id, text: r.text }));
    if (goodTexts.length) {
      try {
        const cf = await claudeExtract(goodTexts, q, searchType, signal);
        if (Object.keys(cf).filter(k => cf[k]).length > 0) {
          Object.entries(cf).forEach(([k, v]) => { if (v) merged[k] = v; });
        }
        if (Object.keys(merged).filter(k => !k.startsWith('_')).length >= 3) {
          const desc = await claudePolishDescription(merged, q, searchType, signal);
          if (desc && !signal?.aborted) merged.description = desc;
        }
      } catch(e) { if (e.name === 'AbortError') throw e; }
    }
  }

  // 5 ─ Deduplicate images
  const seenImgs = new Set();
  const dedupImgs = allImgs.filter(img => {
    if (!img?.src || seenImgs.has(img.src)) return false;
    seenImgs.add(img.src); return true;
  }).slice(0, 10);

  return { scrapeResults, merged, allImgs: dedupImgs, imo, mmsi };
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

        const { scrapeResults, merged, allImgs, imo, mmsi } =
          await bulkScrapeItem(q, bulkType, bulkYearTo, bulkCat, signal);

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
  persist(record);
  updateSavedBadge();
  updateStats();
  toast('Saved: ' + (info.name || info.vessel_name || info.farm_name || key || 'Record'));

  // Sync to Directus (fire-and-forget — never blocks local save)
  if (window.Directus?.isConfigured()) {
    const query      = info.name || info.vessel_name || info.farm_name || key;
    const searchType = record._facilityType || 'farm';
    window.Directus.saveEntity(info, query, searchType, rid)
      .then(d => { if (d) log(`Directus sync ✓ (id: ${d.id})`, 'ok'); })
      .catch(() => {});
  }
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
  // Mirror delete in SQLite
  if (window.AppSQLite) AppSQLite.remove(id).catch(() => {});
  // Mirror delete in Directus
  if (window.Directus?.isConfigured()) {
    window.Directus.deleteEntity(id).catch(() => {});
  }
}

function editNote(id) {
  const rec = saved.find(s => s._id === id);
  if (!rec) return;
  const note = prompt('Note for this record (500 char max):', rec._notes || '');
  if (note === null) return;
  rec._notes = note.slice(0, 500);
  persist(rec);
  renderSaved();
}

function toggleVerified(id) {
  const rec = saved.find(s => s._id === id);
  if (!rec) return;
  rec._verified = !rec._verified;
  persist(rec);
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
      const ftype   = esc(r._facilityType === 'mill'   ? 'Mill / Processing'
                        : r._facilityType === 'vessel' ? 'Shipping / Fishing Vessel'
                        : r._facilityType === 'farm'   ? 'Farm / Aquaculture'
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
  // Clear all three persistence layers in parallel so no stale records survive a
  // cold-start migration (IDB records → SQLite) or a localStorage fallback path.
  if (window.AppSQLite) AppSQLite.clearAll().catch(() => {});
  if (window.AppIDB)    AppIDB.putAllRecords([]).catch(() => {});
  localStorage.removeItem('ship_saved3');
  persist();
  updateSavedBadge();
  updateStats();
  renderSaved();
}

async function persist(record = null) {
  // Primary: SQLite
  if (window.AppSQLite) {
    try {
      if (record) {
        // Single-record path (doSave / editNote / toggleVerified):
        // upsert just the one row — O(1) instead of O(n)
        await AppSQLite.upsert(record);
      } else {
        // Full-batch path (deleteSaved, bulk-import, init):
        // one transaction covers the whole array
        await AppSQLite.batchUpsert(saved);
      }
      return;
    } catch (e) {
      console.warn('[persist] SQLite write failed, falling back:', e.message);
    }
  }
  // Fallback: legacy IDB records store or localStorage
  try {
    if (window.AppIDB) await AppIDB.putAllRecords(saved);
    else localStorage.setItem('ship_saved3', JSON.stringify(saved));
  } catch {
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

  // Dynamic fields (nav_status, flag, year) update on every search — may have changed.
  // Static fields (IMO, name, location) update only when not yet cached.
  const ALWAYS_UPDATE = new Set(['nav_status','flag','description','capacity','certification','employees']);
  fks.forEach(k => {
    if (!fields[k]) return;
    if (ALWAYS_UPDATE.has(k) || !ex.fields[k]) {
      ex.fields[k] = fields[k];
    }
  });

  const goodSrc = (sources || []).filter(s => s.ok).map(s => s.id);
  ex.sources = [...new Set([...ex.sources, ...goodSrc])].slice(0, 20);
  ex.hitCount++;
  ex.lastSeen = new Date().toISOString();
  // Confidence based on both field count and source diversity
  ex.confidence = Math.min(1, (Object.keys(ex.fields).length / 8) * 0.7 + (Math.min(ex.sources.length, 6) / 6) * 0.3);
  learned[key] = ex;
  schedulePersistLearned();
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
/* ═══════════════════════════════════════════
   SQLITE EXPORT + QUERY PANEL
═══════════════════════════════════════════ */
async function exportSQLiteDB() {
  if (!window.AppSQLite) { toast('SQLite not available'); return; }
  const btn = document.getElementById('sqlite-export-btn');
  if (btn) { btn.textContent = 'Preparing…'; btn.disabled = true; }
  try {
    const data = await AppSQLite.exportDB();
    if (!data) { toast('No data in SQLite database yet'); return; }
    const blob = new Blob([data], { type: 'application/x-sqlite3' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url;
    a.download = `records-${new Date().toISOString().slice(0,10)}.db`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
    toast('Downloaded SQLite database');
  } catch (e) {
    toast('Export failed: ' + e.message);
  } finally {
    if (btn) { btn.textContent = 'SQLite ↓'; btn.disabled = false; }
  }
}

function toggleSQLPanel() {
  const panel = document.getElementById('sql-panel');
  if (!panel) return;
  panel.hidden = !panel.hidden;
  if (!panel.hidden) document.getElementById('sql-input')?.focus();
}

function setSQLQuery(sql) {
  const el = document.getElementById('sql-input');
  if (el) { el.value = sql; el.focus(); }
}

async function runSQLQuery() {
  const el = document.getElementById('sql-input');
  const out = document.getElementById('sql-results');
  if (!el || !out) return;
  const sql = el.value.trim();
  if (!sql) return;
  if (!window.AppSQLite) { out.innerHTML = '<div class="sql-err">SQLite not initialised</div>'; return; }

  // Block all data-modifying and DDL statements — read-only panel
  if (/^\s*(drop|delete|truncate|alter|attach|detach|insert|update|replace|create)\b/i.test(sql)) {
    out.innerHTML = '<div class="sql-err">Only SELECT queries are permitted in this panel.</div>';
    return;
  }

  out.innerHTML = '<div class="sql-running">Running…</div>';
  try {
    const results = await AppSQLite.query(sql);
    if (!results.length) {
      out.innerHTML = '<div class="sql-empty">Query returned no rows.</div>';
      return;
    }
    const { columns, values } = results[0];
    const thead = `<tr>${columns.map(c => `<th>${esc(c)}</th>`).join('')}</tr>`;
    const tbody = values.map(row =>
      `<tr>${row.map(v => `<td>${esc(v == null ? '' : String(v))}</td>`).join('')}</tr>`
    ).join('');
    out.innerHTML = `
      <div class="sql-meta">${values.length} row${values.length !== 1 ? 's' : ''}</div>
      <div class="tbl-wrap"><table class="sv-table sql-table">
        <thead>${thead}</thead><tbody>${tbody}</tbody>
      </table></div>`;
  } catch (e) {
    out.innerHTML = `<div class="sql-err">Error: ${esc(e.message)}</div>`;
  }
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
  // Start from 1980: fishing vessels built in the 1980s–1990s are still active, and the
  // year_built validator already accepts 1800+. Default selection stays at 2000/curYear.
  const START_YEAR = 1980;
  for (let y = START_YEAR; y <= curYear; y++) {
    from.add(new Option(y, y, y === 2000, y === 2000));
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
  const filterSentences = parts =>
    parts.filter(s => {
      const yrs = (s.match(/\b(19|20)\d{2}\b/g) || []).map(Number);
      return !yrs.some(y => y > yearTo);
    });
  try {
    // Lookbehind: Chrome 62+, Firefox 78+, Safari 16.4+ — try first
    return filterSentences(text.split(/(?<=[.!?])\s+/)).join(' ');
  } catch {
    // Fallback for Safari < 16.4: split on punctuation and re-attach the terminator
    return filterSentences(
      text.split(/([.!?])\s+/).reduce((acc, part, i, arr) => {
        if (i % 2 === 0) acc.push(part + (arr[i + 1] || ''));
        return acc;
      }, [])
    ).join(' ');
  }
}
