# dashboard/

Main landing page after login. Shows everything at a glance via a single aggregate query.

## Flow diagram coverage

- R — `GET /dashboard/bootstrap` on mount
- S, T, U, V, W — backend loads org, role, subscription, scanners, secrets, recent activity
- X, X1–X5 — tiles rendered from the aggregate response

## Responsibility

Compose, don't compute. Single query powers 5 tiles. Data is cached 30s; WS events (`scan.completed`, `billing.updated`, `secret.changed`) invalidate it.

## Routes owned

- `/` → `DashboardPage`

## Backend endpoints consumed

- `GET /api/dashboard/bootstrap`

## Public hooks

- `useDashboardBootstrap()`

## WebSocket events consumed

- `scan.completed` → invalidate `['dashboard', 'bootstrap']`
- `billing.updated` → invalidate
- `secret.changed` → invalidate

## Implementation checklist

- [ ] Tile components: `OrgCard`, `BillingCard`, `SecretsCard`, `ScannerTileGrid`, `RecentActivityCard`
- [ ] `ScannerTileGrid` renders one tile per scanner; clicking navigates to `/scanners` (the run modal lives there)
- [ ] Loading skeletons per tile (not a full-page spinner)
- [ ] WS event handlers invalidate the bootstrap query
- [ ] Empty states: no scans yet, no secrets yet, trial banner if subscription is TRIAL

## Out of scope

- Scanner-specific dashboards — those are separate views in `features/scans` + `features/findings`
- Configurable tile layout — v2
