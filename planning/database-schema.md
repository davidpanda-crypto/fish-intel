# Database Schema — Directus

Status: **Proposed — not implemented**

Target: existing Outlaw Ocean Directus instance (or a dedicated instance TBD — see open questions in GitHub issue).

---

## Collections

### `fi_vessels`

Maritime vessels — fishing boats, cargo ships, reefers, factory ships.

| Field | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key (auto) |
| `date_created` | timestamp | Auto |
| `date_updated` | timestamp | Auto |
| `created_by` | user FK | Auto |
| `vessel_name` | string | Required |
| `imo` | string | 7-digit, validated with check-digit |
| `mmsi` | string | 9-digit |
| `flag` | string | Full country name |
| `call_sign` | string | |
| `vessel_type` | string | e.g. Trawler, Longliner, Purse Seiner, Reefer |
| `gross_tonnage` | string | Stored as string to preserve original units/formatting |
| `dwt` | string | Deadweight tonnage |
| `length_m` | float | LOA in metres |
| `beam_m` | float | |
| `year_built` | integer | |
| `engine` | string | |
| `speed_knots` | float | |
| `port_of_registry` | string | |
| `owner` | string | |
| `operator` | string | |
| `manager` | string | |
| `nav_status` | string | |
| `class_society` | string | |
| `country` | string | |
| `description` | text | Investigative summary paragraph |
| `sources` | json | Array of source URLs/names that contributed data |
| `images` | json | Array of image URLs |
| `verified` | boolean | Manual verification flag |
| `notes` | text | Researcher notes |
| `search_query` | string | The original query that found this record |

---

### `fi_farms`

Fish farms and aquaculture facilities.

| Field | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key (auto) |
| `date_created` | timestamp | Auto |
| `date_updated` | timestamp | Auto |
| `created_by` | user FK | Auto |
| `farm_name` | string | Required |
| `operator` | string | |
| `owner` | string | |
| `country` | string | |
| `region` | string | |
| `latitude` | float | Max 5 decimal places |
| `longitude` | float | Max 5 decimal places |
| `species` | string | Comma-separated, title-cased |
| `water_type` | string | Freshwater / Saltwater / Brackish water |
| `production_method` | string | Sea cage / RAS / Pond culture / etc. |
| `annual_capacity` | string | With units, e.g. "12,000 t/yr" |
| `certification` | string | ASC / MSC / BAP / GlobalG.A.P. / etc. |
| `license_number` | string | |
| `stocking_density` | string | With units |
| `harvest_cycles` | string | |
| `feed_type` | string | |
| `fcr` | float | Feed Conversion Ratio |
| `water_temp` | string | With units |
| `salinity` | string | With units |
| `dissolved_oxygen` | string | With units |
| `ph` | string | |
| `total_area_ha` | float | Hectares |
| `employees` | integer | |
| `established_year` | integer | |
| `description` | text | |
| `sources` | json | |
| `images` | json | |
| `verified` | boolean | |
| `notes` | text | |
| `search_query` | string | |

---

### `fi_mills`

Fish meal and fish oil processing plants.

| Field | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key (auto) |
| `date_created` | timestamp | Auto |
| `date_updated` | timestamp | Auto |
| `created_by` | user FK | Auto |
| `mill_name` | string | Required |
| `operator` | string | |
| `owner` | string | |
| `country` | string | |
| `region` | string | |
| `latitude` | float | |
| `longitude` | float | |
| `processing_capacity` | string | With units, e.g. "50,000 t/yr" |
| `input_species` | string | Raw fish species used, comma-separated |
| `output_products` | string | e.g. fishmeal, fish oil |
| `fishmeal_pct` | float | |
| `fishoil_pct` | float | |
| `feed_type` | string | |
| `certification` | string | |
| `employees` | integer | |
| `description` | text | |
| `sources` | json | |
| `images` | json | |
| `verified` | boolean | |
| `notes` | text | |
| `search_query` | string | |

---

### `fi_searches` *(optional — analytics/audit)*

Log of searches run, for analytics and deduplication.

| Field | Type | Notes |
|---|---|---|
| `id` | UUID | |
| `date_created` | timestamp | |
| `created_by` | user FK | |
| `query` | string | Original search string |
| `facility_type` | string | farm / mill / vessel |
| `sources_hit` | integer | How many sources were scraped |
| `fields_found` | integer | Unique fields extracted |
| `result_id` | string | FK to fi_farms / fi_mills / fi_vessels (polymorphic) |
| `duration_ms` | integer | Search duration |

---

## Open questions

- **Primary store vs. sync target**: Should Directus replace IndexedDB entirely, or should the app work offline-first and sync to Directus when online? Offline-first is more resilient but significantly more complex to implement (conflict resolution, etc.)
- **Which instance**: Existing OO Directus, or a dedicated instance for Fish Intel?
- **Access control**: Read-only for all OO staff? Write access for defined researchers only?
- **Migration**: What happens to records already in users' browsers? A one-time export/import tool would be needed.
- **`sources` and `images` as JSON**: Keeps the schema simple but makes querying harder. Alternative: dedicated `fi_sources` and `fi_images` junction collections.
