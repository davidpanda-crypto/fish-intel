# js/app.js — CLAUDE.md

## Overview

`app.js` is the entire application in a single ~4400-line file. It runs in the browser with no bundler or transpiler. It is loaded as a `<script type="module">` after the three modules (`idb.js`, `router.js`, `cache.js`) which expose their APIs on `window`.

## Major sections (in file order)

### 1. Security helpers (lines ~1–210)

These functions are the first line of defense against XSS and data corruption. They must be used consistently — see the security rules in the root CLAUDE.md.

| Function | Purpose |
|---|---|
| `esc(s)` | HTML-escape a string for safe insertion into the DOM |
| `sanitize(html)` | DOMPurify whitelist sanitization for full HTML blobs |
| `isValidURL(url)` | Reject non-HTTPS, localhost, private IPs before fetching |
| `cleanField(v)` | Strip HTML tags, decode entities, reject noise/placeholder values, limit to 1500 chars |
| `validateFieldValue(key, val)` | Per-field precision validation (see below) |
| `relevanceScore(text, q)` | Count how many times query terms appear in text |
| `isSeaRelated(text)` | Global domain gate: does this page mention any aquaculture/maritime keyword? |
| `topicMatch(text, searchType)` | Cross-category exclusion (e.g. reject vessel pages when searching for farms) |
| `filterFieldsByType(fields, searchType)` | Strip fields that don't belong to the requested entity type |

#### `validateFieldValue` field rules

- `latitude` / `longitude` — parse float, enforce range, reject 0.0, max 5 decimal places
- `year_built` — must be 1800–2029
- `imo` / `_imo` — must be 7 digits and pass the IMO check-digit algorithm (`validIMO()`)
- `mmsi` — exactly 9 digits
- `capacity`, `gross_tonnage`, `dwt`, `processing_capacity`, `total_area`, `employees` — must contain at least one digit
- `fcr` — float between 0.5 and 10
- `description` — min 30 chars; rejects generic site/platform boilerplate; max 1200 chars
- `species` / `input_species` — title-case, reject single generic words (Fish, Seafood, etc.)
- `certification` — normalized to known canonical values: "ASC Certified", "MSC Certified", "BAP Certified", "GlobalG.A.P. Certified", "Halal Certified", `ISO NNNN Certified`
- `country` / `flag` — ISO-2/ISO-3/abbreviation → full country name via `ISO_MAP`
- `production_method` — normalized to: "Sea cage / Net pen", "RAS (Recirculating)", "Pond culture", "Tank culture", "Longline / Raft", "Flow-through", "Integrated system"
- `water_type` — normalized to: "Freshwater", "Saltwater / Marine", "Brackish water"

### 2. CORS proxy & fetch infrastructure (lines ~220–380)

The app scrapes third-party sites by routing requests through a rotating chain of public CORS proxies.

| Function | Purpose |
|---|---|
| `fetchViaProxy(url, signal)` | Main fetch function: tries each proxy in order, caches successful responses, applies rate limiting (800 ms/domain), retries with exponential backoff (MAX_RETRIES=2) |
| `parseHTML(html)` | DOMParser + cleanup: removes `<script>`, `<style>`, `<nav>`, `<footer>`, `<iframe>`, `<form>`, cookie banner elements |

**Proxy health tracking**: `proxyFails` Map tracks consecutive failures per proxy. After `PROXY_MAX_FAILS` failures in a session, a proxy is skipped. State is persisted to IDB `knowledge` store under key `'pfails'`.

**Rate limiting**: `_lastReq` Map tracks last request time per domain. Requests to the same hostname are throttled to 800 ms minimum spacing.

### 3. Translation (lines ~380–450)

| Function | Purpose |
|---|---|
| `translateChunk(text, signal)` | Translate one chunk (≤450 chars) via MyMemory → Lingva fallback chain |
| `translate(text, signal)` | Split long text into 450-char chunks, translate each, rejoin |

Language detection is script-heuristic (CJK, Arabic, Cyrillic patterns). Translation is only attempted when the user enables the "Auto-translate" toggle.

### 4. Image extraction (lines ~450–600)

| Function | Purpose |
|---|---|
| `extractImages(doc, baseURL)` | Extract images from a parsed DOM: og:image, twitter:image, JSON-LD, `<img>` srcset, `<noscript>` fallbacks, `<picture>` sources |
| `fetchBingImages(query, signal)` | Scrape Bing image search results |
| `fetchDDGImages(query, signal)` | DuckDuckGo image API (requires extracting `vqd` token first) |
| `fetchWikipediaImages(query, signal)` | Wikipedia REST API — thumbnail + infobox images |

Stock photo domains (Getty, Shutterstock, Unsplash, iStock, Adobe Stock) are filtered out. Broken and duplicate images are removed. Maximum 12 images returned per search.

### 5. Claude AI integration (lines ~598–825)

Claude is **optional** — all AI calls are gated on the user having entered an API key. The app degrades gracefully to regex-only extraction if no key is present.

| Constant/Function | Purpose |
|---|---|
| `CLAUDE_API` | `https://api.anthropic.com/v1/messages` |
| `CLAUDE_VER` | API version header value |
| `getClaudeKey()` / `getClaudeModel()` | Read from IDB `knowledge` store, key `'claude-settings'` |
| `callClaude(system, user, maxTokens, signal)` | Direct browser call with `anthropic-dangerous-direct-browser-access` header, 30s timeout |
| `claudeExtract(pageTexts, query, searchType, signal)` | Extract structured JSON fields from scraped text; validates every returned value through `validateFieldValue` |
| `claudePolishDescription(merged, query, searchType, signal)` | Polish description to investigative-journalism style; returns null on failure |
| `claudeFieldSchema(searchType)` | Returns the field schema object for the given type (farm / mill / vessel) |

`claudeExtract` runs **concurrently** with the scraping loop — it does not add latency because it starts at the same time as the first source requests.

### 6. Field extraction (lines ~1326–1600)

`extractFields(doc, text)` is the core regex+DOM extraction function. It returns a flat `{}` object with any fields it found.

Extraction sources within a page, in priority order:
1. `<meta name="description">` and `<meta property="og:description">`
2. `<h1>` and `<title>` → `_heading`
3. `<table>` cells (2-column and 4-column label|value patterns)
4. `<dl>/<dt>/<dd>` definition lists
5. `<script type="application/ld+json">` (JSON-LD structured data: name, geo, address, founder)
6. `[data-label]`, `[data-key]`, `[data-field]` attributes
7. `.label`, `.field-label`, `.prop-label`, `.detail-label` sibling patterns
8. `.vessel-detail`, `.ship-detail`, `.detail-row`, `.info-row` row patterns
9. **Coordinate extraction** from: Google Maps iframes, Google Maps links, `data-lat`/`data-lng` attributes, Schema.org microdata, Leaflet/OpenLayers JS init, JSON-format lat/lon in page scripts
10. **Regex fallback on plain text** — ~50 named patterns covering all field types

`assignField(f, rawLabel, rawValue)` maps scraped label strings to canonical field keys (e.g. `"gross tonnage"` → `gross_tonnage`, `"flag state"` → `flag`).

### 7. IMO validation (lines ~845–870)

```js
function validIMO(imo) {
  // Check digit: (d[0]*7 + d[1]*6 + d[2]*5 + d[3]*4 + d[4]*3 + d[5]*2) % 10 === d[6]
}
```

IMO numbers are the primary identifier for vessels. Always validate with `validIMO()` before storing. `extractIMOs(text)` scans free text for valid 7-digit IMO numbers.

### 8. Source search strategies (lines ~2200–2900)

The main search pipeline (`runBot()` → `doSearch()`) queries sources in tiers:

**Tier 1 — Type-specific direct sources** (scraped via proxy):
- Vessel: MarineTraffic, VesselFinder, FleetMon, Equasis, FAO Global Record
- Farm: FAO Fisheries, ASC, BAP, SeafoodSource
- Mill: IFFO, FIS, EUMOFA, Marine Ingredients Org

**Tier 2 — Structured APIs** (direct fetch, no proxy):
- OpenStreetMap Overpass API (aquaculture facilities with coordinates)
- Wikipedia REST API

**Tier 3 — Search engines** (via proxy):
- Bing (site-targeted domain queries)
- DuckDuckGo (structured JSON)
- Google Search

**Tier 4 — Fallbacks**:
- Broad English queries
- Multilingual queries (Spanish, Norwegian, Portuguese, French, Chinese, German, Arabic, Russian)

**Early exit**: The scraping loop stops early once `FIELD_THRESHOLD = 6` unique non-internal fields have been found across all sources so far. The `AbortController` pattern (`exitAC`) handles cooperative cancellation.

### 9. Result merging (lines ~2900–3050)

`mergeResults(scrapeResults, searchType)` takes the array of per-source result objects and produces a single merged record:

1. Sort sources by trust rank
2. For each field, take the first non-empty value from the highest-ranked source
3. Where fields are missing, apply fallbacks (e.g. `flag` → `country`)
4. Run `normalizeFields()` — deduplicate species, standardize units, enforce canonical values

### 10. Rendering (lines ~1800–2100)

`renderCard(info, sources, imgs)` builds the result card HTML. It is type-aware — `FARM_FIELDS`, `VESSEL_FIELDS`, and `MILL_FIELDS` arrays define which fields and labels to show for each type.

Cards include: reference links to MarineTraffic / VesselFinder / FAO / ASC / Wikipedia / OSM / Google Maps, image gallery (lightbox), source attribution badges, AI verification status badge, notes and verification controls.

### 11. File handling (lines ~3100–3450)

`handleFile(event)` lazy-loads the appropriate parser:
- PDF → `pdf.js` (Mozilla CDN)
- Word (.docx) → `mammoth.js`
- Excel (.xlsx/.xls) → `xlsx.js` (SheetJS)
- CSV/TXT/JSON/XML → native `FileReader`

After parsing, text is passed through `extractFields()` and optionally translated.

### 12. Bulk lookup (lines ~3820–3890)

`doBulk()` reads a textarea of newline-separated names, runs `doSearch()` on each in sequence, and accumulates results in `bulkRes`. Progress bar updates per item. Results are rendered as a table and can be exported as CSV or JSON.

## Adding a new field

1. Add the regex pattern to the `pairs` array in `extractFields()`
2. Add the field key to the appropriate `*_ONLY` set in `filterFieldsByType()` if it is type-specific
3. Add a validation case in `validateFieldValue()` if the field needs precision validation
4. Add to `claudeFieldSchema()` for Claude extraction
5. Add to `FARM_FIELDS`, `VESSEL_FIELDS`, or `MILL_FIELDS` in `renderCard()` for display

## Adding a new source

1. Add a scrape step to `doSearch()` (or `scrapeURL()` for URL mode)
2. Assign it a rank in the source trust hierarchy used by `mergeResults()`
3. Add the domain to `domainStats` tracking if you want per-session success rate learning

## Patterns to follow

- Always pass scraped text through `relevanceScore()` before extracting — skip pages scoring 0
- Always pass pages through `topicMatch()` to avoid cross-category contamination
- Always run `extractFields()` output through `filterFieldsByType()` before merging
- Use `log(message, level)` for the live search log — levels: `'ok'`, `'err'`, `'warn'`, `'info'`
- Use `toast(message)` for one-off user notifications
