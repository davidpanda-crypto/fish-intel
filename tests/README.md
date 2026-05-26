# Tests

Status: **Placeholder — not yet implemented**

This folder will hold the test suite for Fish Intel. The goal is regression coverage on the extraction and validation logic, which is the most complex and most breakable part of the application.

---

## Planned test structure

```
tests/
├── unit/
│   ├── validate.test.js        — validateFieldValue() for every field type
│   ├── extract.test.js         — extractFields() against fixture HTML pages
│   ├── imo.test.js             — validIMO() check-digit algorithm
│   ├── normalize.test.js       — normalizeFields() deduplication and unit standardization
│   ├── merge.test.js           — mergeResults() source ranking and field priority
│   ├── relevance.test.js       — relevanceScore() and topicMatch() filtering
│   └── schema.test.js          — claudeFieldSchema() returns correct fields per type
│
├── integration/
│   ├── search-farm.test.js     — Full search pipeline for a known fish farm
│   ├── search-vessel.test.js   — Full search pipeline for a known vessel (by IMO)
│   ├── search-mill.test.js     — Full search pipeline for a known fish mill
│   └── bulk.test.js            — Bulk lookup across multiple entities
│
├── fixtures/
│   ├── html/
│   │   ├── marinetraffic-vessel.html   — Saved MarineTraffic page for a known vessel
│   │   ├── asc-farm.html               — Saved ASC producer page for a known farm
│   │   ├── wikipedia-vessel.html       — Saved Wikipedia vessel article
│   │   └── fao-farm.html               — Saved FAO fisheries page
│   └── records/
│       ├── vessel-expected.json        — Expected output record for the vessel fixture
│       ├── farm-expected.json          — Expected output record for the farm fixture
│       └── mill-expected.json          — Expected output record for the mill fixture
│
└── helpers/
    └── mock-fetch.js           — Intercepts fetchViaProxy() calls and returns fixtures
```

---

## Priority test cases

These are the behaviours most likely to break silently during development:

### Field validation regressions
- `latitude`/`longitude`: rejects 0.0, enforces ±90/±180 range, rounds to 5 decimal places
- `imo`: rejects 6- and 8-digit numbers; rejects 7-digit numbers that fail the check-digit
- `certification`: normalizes "asc certified", "ASC", "asc-approved" all to "ASC Certified"
- `country`: maps ISO-2/ISO-3 codes to full names ("NO" → "Norway", "NOR" → "Norway")
- `description`: rejects strings under 30 chars; rejects platform boilerplate ("Search our database of...")
- `production_method`: normalizes "net pen", "sea cage", "open net" all to "Sea cage / Net pen"

### Extraction regressions
- IMO number extracted from free text ("IMO: 9876543", "IMO#9876543", "IMO 9876543")
- Coordinates from Google Maps iframes, data-lat/data-lng attributes, and DMS format
- Fields from `<table>` two-column and four-column layouts
- Fields from JSON-LD `<script type="application/ld+json">` blocks
- Noise rejection: "N/A", "Unknown", "Login", "Read more" are never saved as field values

### Topic filtering regressions
- A vessel page is rejected when searching for a farm (`topicMatch` cross-category exclusion)
- A hotel or restaurant page is rejected for all types (`isSeaRelated` domain gate)
- A farm page is accepted when searching for a farm even if it mentions shipping

### Merge / ranking regressions
- Higher-ranked source (Equasis) wins over lower-ranked (Wikipedia) for `flag` field
- When two sources agree on a value, that value is kept (no accidental deduplication)
- Fallback: when `flag` is missing, `country` is used in its place

---

## Suggested test runner

**Vitest** — fast, no config needed for vanilla JS, works well in a Next.js project too if the conversion happens. Alternatively **Jest** with jsdom for DOM-dependent tests.

To add:
```
npm install -D vitest jsdom
```

Then add to `package.json`:
```json
"scripts": {
  "test": "vitest run",
  "test:watch": "vitest"
}
```
