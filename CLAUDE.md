# Fish Farm & Ship Intelligence — Project CLAUDE.md

## What this project is

A browser-based research intelligence tool for aquaculture facilities and maritime vessels. Users search by name, scrape URLs, upload documents, or paste text to build structured data profiles on fish farms, fish mills, and fishing/shipping vessels. All data is stored locally in the browser — there is no backend.

Deployed as a static site on Netlify. No build step. No framework.

## Directory structure

```
fish-intel/
├── index.html          — Main app shell (HTML + modals + tab panels)
├── ship_scraper.html   — Legacy standalone version; not part of current architecture
├── sw.js               — Service worker (offline support, asset caching)
├── netlify.toml        — Deployment config, security headers, SPA fallback
├── planning/           — Architecture planning docs (not deployed)
│   ├── nextjs-conversion.md   — Proposed Next.js migration plan + folder structure
│   ├── database-schema.md     — Proposed Directus collections and field schemas
│   └── agentic-flow.md        — Ideas for a reasoning-capable agentic search loop
├── css/
│   └── style.css       — All styling (~4500 lines, CSS variables, responsive)
└── js/
    ├── app.js          — Entire application logic (~4400 lines)
    └── modules/
        ├── idb.js      — IndexedDB adapter (window.AppIDB)
        ├── router.js   — Hash-based URL router (window.AppRouter)
        └── cache.js    — TTL-aware search cache (window.AppCache)
```

## Tech stack

- **Vanilla JavaScript** — no framework, no bundler, no build step
- **IndexedDB** via `AppIDB` — primary persistent storage
- **Service Worker** — offline-capable PWA, cache-first for assets
- **Anthropic Claude API** — optional, called directly from the browser using `anthropic-dangerous-direct-browser-access`
- **CORS proxies** — rotating chain of 10 public proxies for web scraping
- **DOMPurify** (CDN) — sanitizes all scraped HTML before insertion
- **PDF.js / XLSX / Mammoth** — lazy-loaded only when a file is uploaded

## Five input modes

| Mode | What it does |
|---|---|
| Search by Name | Queries type-specific registries + search engines for a named entity or IMO number |
| Scrape URL | User provides 1–3 URLs; pages are scraped and cross-referenced |
| Upload File | Parses PDF, Word, Excel, CSV, TXT, JSON, XML and extracts structured fields |
| Paste Text | Extracts fields from raw pasted text (inspection reports, harvest logs, etc.) |
| Bulk Lookup | Runs the Search pipeline on a list of names sequentially; results exportable as CSV/JSON |

## Three entity types

Each type has its own field schema, source list, and display card. The type selector controls which fields are extracted, which sources are queried, and which fields appear in results.

- **farm** — fish farm / aquaculture facility
- **mill** — fish meal/oil processing plant
- **vessel** — fishing or shipping vessel (IMO number is the primary identifier)

## Data flow

1. User submits query → check `AppCache` (30-min TTL)
2. Cache miss → scrape sources via `fetchViaProxy()` with proxy fallback chain
3. Parse HTML with `parseHTML()` (removes nav/footer/scripts/cookie banners)
4. Extract fields: `extractFields()` (regex + DOM parsing) + optional `claudeExtract()` (Claude API in parallel)
5. Validate every field: `validateFieldValue()` — coordinates, IMO checksum, units, etc.
6. Rank sources by trust level; merge fields (`mergeResults()`)
7. Normalize: `normalizeFields()` — deduplicate species lists, standardize country names, units
8. Render result card; save to `AppIDB` records store on user action

## Source trust hierarchy (lowest → highest)

1. Broad / international search fallbacks
2. Web search result pages (Bing, DuckDuckGo, Google)
3. Wikipedia, AIS registry
4. Trade databases (SeafoodSource, EUMOFA, etc.)
5. Sector registries (FAO, ASC, BAP, IFFO)
6. Structured geo data (OpenStreetMap)
7. Authoritative vessel registries (Equasis, MarineTraffic, VesselFinder, FleetMon)

## Key global constants (app.js)

| Name | Purpose |
|---|---|
| `PROXIES` | Array of 10 CORS proxy URLs, tried in order with health tracking |
| `UA_POOL` | 6 rotating user-agent strings |
| `REFERERS` | 10 Google referrer URLs rotated per request |
| `_SEA_KW` | Regex of 40+ maritime/aquaculture keywords — global domain gate |
| `MAX_FILE_BYTES` | 25 MB upload limit |
| `PROXY_MAX_FAILS` | Max consecutive failures before a proxy is skipped this session |

## Key global state (app.js)

| Name | Purpose |
|---|---|
| `stats` | `{ searches, ships, images }` — live session counters shown in header |
| `saved` | Array of persisted records (synced with IDB) |
| `learned` | Entity knowledge base: `normalizedName → { fields, sources, hitCount }` |
| `domainStats` | Per-hostname success rates for intelligent source skipping |
| `proxyFails` | Map of proxy URL → consecutive fail count |
| `reqCache` | Session-scoped in-memory URL → HTML cache (Map, max 100) |
| `isRunning` | Boolean lock preventing double-submit |

## Directus schema rules — always follow these

Outlaw Ocean runs a shared Directus instance used by multiple products. Careless schema changes can break other projects.

- **All collections created for this project must be prefixed `fi_`** — e.g. `fi_vessels`, `fi_farms`, `fi_mills`, `fi_searches`. Never create an unprefixed collection.
- **Never modify, rename, or delete a collection that does not start with `fi_`.** Those belong to other OO projects.
- **Never add fields to a non-`fi_` collection** without explicit confirmation that it is safe to do so.
- **Before writing any Directus migration, query the existing schema first** (`/collections` endpoint or the MCP Directus tool) to confirm the collection does not already exist under a different name and that your new field names do not collide with system fields (Directus reserves fields like `id`, `status`, `sort`, `date_created`, `date_updated`, `user_created`, `user_updated`).
- The canonical schema for `fi_` collections lives in [planning/database-schema.md](planning/database-schema.md). Treat that file as the source of truth and keep it in sync with any real migrations.

## Security rules — always follow these

- **All user-controlled or scraped content must pass through `esc()` before DOM insertion.** Never use innerHTML directly with untrusted data.
- **All scraped HTML must pass through `sanitize()` (DOMPurify) before parsing.**
- **All field values must pass through `validateFieldValue(key, val)`** — this catches bad coordinates, invalid IMOs, navigation boilerplate, and URL-shaped strings leaking into description fields.
- **All URLs must pass through `isValidURL()`** before fetching — rejects localhost, private IPs, non-HTTPS.
- The CSP in `index.html` is intentional — do not loosen it without understanding the implications.

## Coding conventions

- Camelcase functions: `runBot()`, `fetchViaProxy()`, `normalizeFields()`
- ALL_CAPS for module-level constants: `PROXIES`, `UA_POOL`, `MAX_FILE_BYTES`
- `_underscore` prefix for private module internals: `_db`, `_mem`, `_memGet()`
- Status log entries use string literals `'ok'`, `'err'`, `'warn'`, `'info'` as the second arg to `log()`
- HTML class naming: `.btn-blue`, `.btn-ghost`, `.s-ok`, `.s-err`, `.vessel-card`, `.saved-*`
- Do not use `var`. Use `const`/`let` throughout.

## Deployment

- **Platform**: Netlify, static site, no build step (`publish = "."`)
- **Asset versioning**: JS and CSS served with `max-age=31536000, immutable`; bust cache by incrementing `?v=N` query param in `index.html` script/link tags
- **Service worker versioning**: Increment `CACHE_VER` in `sw.js` when shell assets change
- **SPA fallback**: All routes redirect to `index.html` (status 200) via `netlify.toml`
- **sw.js** is served with `Cache-Control: no-cache` so browsers always check for a new version

## What ship_scraper.html is

A legacy standalone single-file version of the app (HTML + CSS + JS all in one file). It predates the current modular architecture. It is not linked from the main app and is not deployed as an active feature. Do not modify it — treat it as a historical artifact.
