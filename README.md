# Fish Intel

A research intelligence tool for aquaculture facilities and maritime vessels. Search by name, scrape URLs, upload documents, or paste inspection reports — the bot aggregates structured profiles from dozens of registries, databases, and open data sources.

Built for the Outlaw Ocean Project.

---

## What it does

Fish Intel consolidates scattered information about **fish farms**, **fish mills**, and **fishing/shipping vessels** into a single structured record. Data is pulled from FAO, ASC, BAP, MarineTraffic, VesselFinder, Equasis, OpenStreetMap, Wikipedia, and more. An optional Claude AI integration polishes extraction and generates investigative-grade descriptions.

**Five ways to feed it data:**

| Mode | Use when |
|---|---|
| Search by Name | You have a name or 7-digit IMO number |
| Scrape URL | You already know which pages to pull from |
| Upload File | You have a PDF, Word doc, Excel sheet, or CSV |
| Paste Text | You have inspection reports, certifications, or raw text |
| Bulk Lookup | You have a list of names to run in one batch |

**Three entity types:**
- **Fish Farm / Aquaculture** — species, capacity, certifications, water type, production method, coordinates
- **Fish Mill / Processing Plant** — input species, fishmeal/oil percentages, processing capacity
- **Vessel** — IMO, flag state, gross tonnage, call sign, port of registry, owner/operator

---

## Running locally

No build step. Serve the directory with any static file server:

```bash
npx serve .
# or
python -m http.server 8080
```

Then open `http://localhost:3000` (or whichever port).

---

## Structure

```
fish-intel/
├── index.html          — App shell
├── sw.js               — Service worker (offline / PWA)
├── netlify.toml        — Deployment and security headers
├── css/style.css       — All styles
├── js/
│   ├── app.js          — All application logic
│   └── modules/
│       ├── idb.js      — IndexedDB storage
│       ├── router.js   — Hash-based URL routing
│       └── cache.js    — TTL search cache
├── planning/           — Architecture planning (Next.js, Directus, agentic flow)
└── tests/              — Test suite (Vitest, placeholder stubs)
```

See [CLAUDE.md](CLAUDE.md) for full architecture documentation.

---

## AI integration

Structured field extraction and description generation use the [Anthropic Claude API](https://www.anthropic.com). Add your API key via the settings button in the app header. The key is stored locally in IndexedDB and never leaves your browser. The app works without it — AI is an optional enhancement on top of regex extraction.

---

## Architecture notes

The app is currently a **vanilla JS static site** with no framework or build step. All data lives in the browser (IndexedDB). See [planning/](planning/) for proposals on:

- Converting to Next.js (consistent with other Outlaw Ocean products)
- Adding Directus backend storage (`fi_` prefixed collections)
- An agentic reasoning loop for smarter multi-step search

---

## Deployment

Deployed on Netlify. Push to `main` deploys automatically. Assets are versioned with `?v=N` query params — increment in `index.html` when JS or CSS changes. Increment `CACHE_VER` in `sw.js` when the app shell changes.
