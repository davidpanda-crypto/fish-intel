# Agentic Flow — Reasoning Ideas

Status: **Exploratory — ideas only, not implemented**

The current app is a linear scraper: fetch → extract → merge → display. These are notes on what a more reasoning-capable agentic version might look like — where the model actively decides what to search for next, rather than following a fixed source list.

---

## The core problem with the current approach

The current pipeline is deterministic: hit sources in order, stop when 6 fields are found. It doesn't know what it doesn't know. If a vessel's IMO number would unlock a much richer result from Equasis, but the first pass didn't find the IMO, the system never goes back.

An agentic loop changes this: the model reviews what's been found, identifies the highest-value gap, and decides what to do next.

---

## Proposed reasoning steps

### Step 1 — Entity disambiguation

Before scraping anything, the model should establish: *what exactly is being searched for?*

- Is "Atlantic Dawn" a vessel or a company?
- Is "Mowi ASA" the parent company or a specific farm?
- Is the 7-digit number a valid IMO? (Check-digit validation first.)
- If ambiguous, generate 2–3 candidate interpretations and rank them by plausibility

**Tool calls at this step**: none — pure reasoning on the query string and type hint.

**Output**: a structured entity hypothesis: `{ name, type, likely_country, disambiguation_notes }`

---

### Step 2 — Source selection

Given the entity hypothesis, the model selects which sources to try first, rather than always following the same fixed order.

- For a vessel with a known IMO → go straight to Equasis and MarineTraffic
- For a Norwegian salmon farm → FAO + ASC + Wikipedia in Norwegian
- For a Peruvian fishmeal mill → TASA / IFFO / Spanish-language queries first
- For an unknown entity → broad search first to establish type before hitting registries

**Tool calls at this step**: none — reasoning about source selection.

**Output**: ordered list of sources with rationale for each choice.

---

### Step 3 — Fetch and extract (iterative)

The existing scrape-and-extract loop, but now supervised by the reasoning layer.

After each source:
- What fields were found?
- What's the confidence in each field? (Was it in a structured table, or regex-matched from free text?)
- What contradictions exist between sources so far?
- What is the single most valuable missing field, and which source is most likely to have it?

**Tool calls**: `fetch_url(url)`, `extract_fields(html, entity_type)`, `translate(text)`

**Output**: running field state with confidence scores and provenance per field.

---

### Step 4 — Gap analysis and follow-up queries

This is where the agentic loop differs most from the current approach. Instead of stopping at 6 fields, the model asks: *what would make this record materially more useful?*

Examples of gap-filling reasoning:

- "I have the vessel name and flag but no IMO. The FAO Global Record has an IMO search — try that."
- "I have coordinates but no country name. Reverse-geocode via OpenStreetMap Nominatim."
- "The description mentions a parent company I haven't searched for — run a secondary search on that company to get ownership context."
- "Two sources give different capacities (12,000 t/yr vs. 8,000 t/yr). The higher figure came from a press release; the lower from the ASC registry. Trust the registry."
- "This farm is ASC-certified but I don't have the certificate number. The ASC producer list has it — fetch that page."

**Tool calls**: `search(query, source)`, `fetch_url(url)`, `reverse_geocode(lat, lon)`

**Max iterations**: cap at ~5 follow-up steps to prevent runaway loops.

---

### Step 5 — Conflict resolution

When multiple sources give different values for the same field, the model should reason about which to trust rather than blindly applying the source trust hierarchy.

Reasoning prompts:
- Which source is more authoritative for this specific field type?
- Is one value a subset of the other (e.g. one source says "salmon" and another says "Atlantic salmon, rainbow trout")?
- Is one value older (and therefore possibly stale)?
- Do the values contradict or just differ in granularity?

**Tool calls**: none — reasoning on already-fetched data.

**Output**: resolved field values with a short rationale string per resolved conflict.

---

### Step 6 — Description synthesis

Generate the investigative summary paragraph only after the field state is stable, not on every scrape iteration as it currently works.

The model should be instructed to:
- Flag anything that looks anomalous (flag change, ownership gap, certification lapse)
- Note what's unknown and why it might matter (e.g. "No port-state control history found — may indicate limited port calls or registry opacity")
- Avoid padding — if data is sparse, say so rather than inflating the paragraph

---

### Step 7 — Confidence scoring and completeness assessment

Before presenting results, produce a structured self-assessment:

```json
{
  "completeness": 0.72,
  "high_confidence_fields": ["vessel_name", "imo", "flag", "gross_tonnage"],
  "low_confidence_fields": ["owner", "port_of_registry"],
  "not_found": ["mmsi", "year_built"],
  "contradictions_resolved": [
    { "field": "operator", "chosen": "Nordic Seas Ltd", "rejected": "Nordic Seas AS", "reason": "Ltd is the registered name on Equasis" }
  ],
  "suggested_follow_up": "Ownership structure unclear — secondary search on Nordic Seas Ltd recommended"
}
```

This gives researchers a clear signal on how much to trust the result and where to dig further.

---

## Model routing idea

Not all steps need the same model. A possible split:

| Step | Task | Suggested model |
|---|---|---|
| 1 — Disambiguation | Structured reasoning on query | Qwen32B (DGT Spark) |
| 2 — Source selection | Structured reasoning on source list | Qwen32B |
| 3 — Extraction | JSON field extraction from scraped text | Qwen32B |
| 4 — Gap analysis | Deciding what to search next | Qwen32B |
| 5 — Conflict resolution | Reasoning about source credibility | Qwen32B |
| 6 — Description | Investigative journalism prose | Claude (stronger writing) |
| 7 — Self-assessment | Confidence scoring | Qwen32B |

The expensive Claude call is reserved for the one task where writing quality matters — description synthesis. All reasoning steps use the cheaper/faster on-prem model.

---

## Implementation approach (if we build this)

The agentic loop would live in `/app/api/search/route.ts` as a streaming route. Each reasoning step emits a progress event to the client (the live log). The loop is bounded by a max-iterations cap and a timeout.

Tool calls within the agent are implemented as Next.js API route calls from within the agent itself — `fetch_url` calls `/api/scrape`, `extract_fields` calls `/lib/extract/fields.ts` directly (server-side), `search` calls `/api/search` recursively with a depth counter to prevent infinite loops.

The `useSearch` hook on the client subscribes to the SSE stream and updates the BotLog and result card as events arrive.
