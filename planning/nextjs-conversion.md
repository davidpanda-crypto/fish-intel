# Next.js Conversion Plan

Status: **Proposed — not started**

---

## Goal

Port Fish Intel from a vanilla JS static site to a Next.js application consistent with the rest of the Outlaw Ocean product family. The conversion should eliminate the CORS proxy chain, move the Anthropic API key server-side, and set up the foundation for shared auth and Directus storage.

---

## Proposed folder structure

```
fish-intel-next/
│
├── app/                              # Next.js App Router
│   ├── layout.tsx                    # Root layout — fonts, metadata, global providers
│   ├── page.tsx                      # Main page shell (replaces index.html)
│   ├── globals.css                   # Global styles (port from css/style.css)
│   │
│   └── api/                          # Server-side Route Handlers
│       ├── scrape/
│       │   └── route.ts              # Fetch any URL server-side — replaces CORS proxy chain
│       ├── claude/
│       │   └── route.ts              # Claude API calls — key stays on server
│       ├── search/
│       │   └── route.ts              # Orchestrate multi-source search, stream progress events
│       └── images/
│           └── route.ts              # Bing / DDG / Wikipedia image fetch
│
├── components/
│   ├── ToolPanel/
│   │   ├── index.tsx                 # Tab container — five input modes
│   │   ├── SearchMode.tsx            # Search by name + facility type selector
│   │   ├── ScrapeMode.tsx            # URL inputs (up to 3) + options toggles
│   │   ├── UploadMode.tsx            # File dropzone + keyword search
│   │   ├── PasteMode.tsx             # Textarea + auto-translate toggle
│   │   └── BulkMode.tsx              # Bulk textarea + progress bar + export
│   │
│   ├── ResultCard/
│   │   ├── index.tsx                 # Type-aware result card (farm / mill / vessel)
│   │   ├── FieldGrid.tsx             # Label/value field grid
│   │   ├── ImageGallery.tsx          # Thumbnail strip
│   │   ├── SourceBadges.tsx          # Source attribution chips
│   │   └── ReferenceLinks.tsx        # MarineTraffic / FAO / OSM / Maps links
│   │
│   ├── SavedRecords/
│   │   ├── index.tsx                 # Records list with filter/sort/view toggle
│   │   ├── RecordCard.tsx            # Card view of a saved record
│   │   ├── RecordTable.tsx           # Table view of saved records
│   │   └── ExportMenu.tsx            # CSV / JSON / Excel export
│   │
│   ├── BotLog.tsx                    # Live streaming search progress log
│   ├── Lightbox.tsx                  # Full-screen image viewer
│   ├── Toast.tsx                     # Bottom-center notification
│   └── Header.tsx                    # Sticky header + session stats
│
├── lib/
│   ├── extract/
│   │   ├── fields.ts                 # extractFields() — DOM + regex extraction
│   │   ├── validate.ts               # validateFieldValue() — per-field precision validators
│   │   ├── normalize.ts              # normalizeFields() — dedup species, standardize units
│   │   ├── images.ts                 # extractImages() from parsed DOM
│   │   └── imo.ts                    # validIMO(), extractIMOs()
│   │
│   ├── merge/
│   │   ├── rank.ts                   # Source trust hierarchy
│   │   └── merge.ts                  # mergeResults() — ranked field merging
│   │
│   ├── schema/
│   │   ├── fields.ts                 # claudeFieldSchema() per type
│   │   └── types.ts                  # TypeScript types: FarmRecord, VesselRecord, MillRecord
│   │
│   ├── sources/                      # One file per source tier
│   │   ├── registries.ts             # MarineTraffic, VesselFinder, FAO, ASC, BAP, etc.
│   │   ├── structured.ts             # OpenStreetMap Overpass, Wikipedia API
│   │   ├── search-engines.ts         # Bing, DuckDuckGo, Google
│   │   └── fallbacks.ts              # Broad + multilingual fallback queries
│   │
│   ├── translate.ts                  # translateChunk(), translate() — MyMemory/Lingva chain
│   └── parse.ts                      # parseHTML() — DOM cleanup after fetch
│
├── hooks/
│   ├── useSearch.ts                  # Search state machine: idle → running → done → error
│   ├── useRecords.ts                 # CRUD for saved records (IndexedDB or Directus)
│   ├── useCache.ts                   # TTL cache wrapper (IndexedDB-backed)
│   └── useRouter.ts                  # Hash-based routing (shareable search URLs)
│
├── store/                            # (if global state is needed — Zustand recommended)
│   └── searchStore.ts                # Search state, session stats, running lock
│
├── public/
│   └── sw.js                         # Service worker (same logic, updated shell URLs)
│
├── next.config.ts                    # Next.js config
├── tailwind.config.ts                # (if adopting Tailwind — TBD)
├── tsconfig.json
└── package.json
```

---

## Phase plan

### Phase 1 — Extract pure logic into `/lib`

Port `extractFields`, `validateFieldValue`, `normalizeFields`, `mergeResults`, IMO validation, and `claudeFieldSchema` from `app.js` into typed TypeScript modules under `/lib`. These have no browser dependencies and can be unit-tested in isolation.

This is the safest first step — no UI changes, just moving and typing logic.

### Phase 2 — API route handlers

Replace the CORS proxy chain with `/api/scrape/route.ts` — a server-side fetch that can hit any URL without CORS restrictions. Replace direct browser Anthropic calls with `/api/claude/route.ts` using a server-side `ANTHROPIC_API_KEY` env var.

This eliminates the two most fragile parts of the current architecture.

### Phase 3 — Streaming search

`/api/search/route.ts` orchestrates the multi-source search and streams progress events back to the client via `ReadableStream` (Server-Sent Events). This preserves the live log UX that the current app has. The `BotLog` component subscribes to the stream.

### Phase 4 — React components

Port the five input panels, result card, saved records section, header, lightbox, and toast into React components. Existing CSS can move to CSS Modules with minimal changes.

### Phase 5 — Hooks and state

`useSearch` replaces `runBot()` / `isRunning` / `stats`. `useRecords` replaces the `saved` array + direct IDB calls. `useCache` wraps the cache logic. If Directus storage is added, `useRecords` is the single place that swaps the storage backend.

### Phase 6 — PWA / service worker

Update `sw.js` shell URLs for the new asset paths. Evaluate `next-pwa` if the manual service worker becomes difficult to maintain.

---

## Open decisions

- **CSS approach**: port existing CSS to CSS Modules (minimal change) or adopt Tailwind (more churn, faster future development)
- **State management**: React `useState`/`useReducer` may be sufficient; Zustand if the search state grows complex
- **Storage backend**: `useRecords` should be designed to swap between IndexedDB and Directus without the rest of the app caring — see `database-schema.md`
- **Deployment**: Netlify supports Next.js; Vercel is the natural fit if the team wants to standardise
