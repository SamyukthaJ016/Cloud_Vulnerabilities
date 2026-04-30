# scans/

Scan history list, detail page, and the redirect-to-scanner-dashboard handoff.
The "trigger a new scan" UX lives in `features/scanners` (`ScanModal`).

## Flow diagram coverage

- CB / CP — submit + receive jobId (via `useRunScan` from `features/scanners`)
- (listing) — `/scans` history
- R1–R6 — "View report" → `GET /scans/:id/report` → `window.location.assign`

## Routes owned

- `/scans` → `ScansListPage`
- `/scans/:id` → `ScanDetailPage`

## Backend endpoints consumed

- `POST /api/scans/run` (called from `features/scanners/ScanModal`)
- `GET /api/scans`
- `GET /api/scans/:id`
- `GET /api/scans/:id/report` — returns `{ redirectUrl }`; we `window.location.assign` to it

## Public exports

- `useScansQuery(filters)`
- `useScanQuery(id)`
- `useRunScan()`
- `fetchScanReportUrl(jobId)`

## Out of scope

- Findings rendering — scanner owns its own dashboard in v1; CP redirects there.
- Scheduling, diffs, cancellation — v2.
