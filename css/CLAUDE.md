# css/style.css — CLAUDE.md

## Overview

Single CSS file (~4500 lines) covering the entire UI. No preprocessor, no framework. Uses CSS custom properties (variables) for the design system.

## Design tokens (CSS variables on `:root`)

### Colors

| Variable | Value | Usage |
|---|---|---|
| `--bg` | light warm beige | Page background |
| `--surf` | near-white | Card and panel surfaces |
| `--ink` | dark brown | Primary text |
| `--accent` | `#1a4a7a` dark navy | Primary buttons, active states, links |
| `--accent2` | slightly lighter navy | Hover states on accented elements |
| `--grn` | green | Success status, verified badges |
| `--red` | red | Error status, destructive actions |
| `--gold` | amber | Highlight / warning-positive |
| `--warn` | orange | Warning status |
| `--mut` | medium gray | Muted text, borders |
| `--mut2` | lighter gray | Subtle borders |
| `--mut3` | lightest gray | Placeholder text |

### Geometry

| Variable | Usage |
|---|---|
| `--rad` | `6px` — standard border-radius |
| `--radlg` | `10px` — card/panel border-radius |
| `--radpill` | `100px` — pill badges and toggle buttons |

### Shadows

| Variable | Usage |
|---|---|
| `--sh-sm` | Subtle lift for small interactive elements |
| `--sh` | Standard card elevation |
| `--sh-lg` | Modal and lightbox elevation |

## Major sections

### Masthead / header

- `.masthead` — sticky top bar with title and session stats
- `.s-stat` — individual stat counter chips (searches, records, images)

### Tool panel (input modes)

- `.tool-panel` — the main input area container
- `.mode-strip` — tab bar for the five input modes
- `.mode-btn` — individual tab button; `.active` state for selected tab
- `.mode-body` — panel content area, shown/hidden via `hidden` attribute
- `.search-bar` — input + search button row
- `.search-config` — facility type selector + filter toggle row
- `.filter-row` — collapsible filter controls (year, category)
- `.ctrl-group` — label + select/input pair
- `.tgl` / `.tgl-row` — toggle switch + label (used for fetch images, auto-translate, etc.)
- `.dropzone` (`#dz`) — file upload area with drag-and-drop styling
- `.upload-hint` — descriptive text above file/URL/bulk inputs

### Result card

- `.vessel-card` — the main result card (used for all entity types despite the name)
- `.vc-fields` — grid of extracted field label/value pairs
- `.vc-field` — individual field row
- `.vc-badge` — pill badges for type, species, certifications, AI status
- `.vc-gallery` — image thumbnail strip
- `.vc-links` — reference links row (MarineTraffic, FAO, Google Maps, etc.)
- `.vc-sources` — source attribution chips
- `.bot-log` — the live scraping progress log (monospace, scrollable)

### Saved records section

- `.saved-section` — container for all saved records
- `.saved-card` — individual saved record card view
- `.sv-table` — tabular view of saved records
- `.saved-controls` — filter, sort, view-toggle, export buttons

### Modals

- `.sp-modal` — save preview modal (review/edit a record before saving)
- `.lightbox` — full-screen image viewer overlay

### Buttons

| Class | Usage |
|---|---|
| `.btn` | Base button styles |
| `.btn-blue` | Primary action (blue, filled) |
| `.btn-ghost` | Secondary action (outlined) |
| `.btn-red` | Destructive action |
| `.btn-sm` | Compact size modifier |

### Status / log entries

| Class | Usage |
|---|---|
| `.s-ok` | Green — success message |
| `.s-err` | Red — error message |
| `.s-warn` | Orange — warning message |
| `.s-info` | Gray — informational message |

### Toast notifications

- `.toast` — bottom-center pill notification, CSS-animated in/out

## Responsive breakpoint

Single breakpoint at `max-width: 640px`:
- Header stats chips are hidden
- Search config row stacks vertically
- Card field grid collapses to single column
- Saved records table switches to card layout

## Conventions

- No `!important` unless overriding a third-party style
- All interactive elements have `:hover` and `:focus-visible` states
- Color usage follows the token system — do not hardcode hex values; use variables
- New components should follow the `.component-name` → `.component-name-child` BEM-adjacent naming pattern already in use
