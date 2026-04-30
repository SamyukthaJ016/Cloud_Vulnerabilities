# scanners/

Scanner catalog tiles + per-scan credential modal.

## Flow diagram coverage

- V — load scanner catalog
- X4 / SA1–SAN — scanner tiles on dashboard
- CA → CA3 — tile click → modal → submit credentials

## Responsibility

- `/scanners` lists every scanner from the catalog as a tile.
- Click → `ScanModal` opens, renders the scanner's manifest `credentialSchema`
  via `@rjsf/core` (JSON Schema form), submits to `POST /scans/run`.
- Admin "Refresh manifests" button calls `POST /admin/scanners/refresh`.

**Does not store credentials** — they are sent once per scan.

## Routes owned

- `/scanners` → `ScannersPage`

## Backend endpoints consumed

- `GET /api/scanners`
- `POST /api/admin/scanners/refresh` (admin)
- `POST /api/scans/run` (via `features/scans`)

## Public exports

- `ScannersPage`
- `ScanModal`
- `useScannersQuery()`, `useRefreshScanners()`

## Out of scope

- Per-org scanner config — v2.
- Adding scanner types from the UI — done via env var on the backend.
- Health pings — backend marks `availability` from manifest fetch results.
