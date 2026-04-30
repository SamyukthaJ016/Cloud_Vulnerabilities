# findings/

List + triage + detail for scan findings.

## Flow diagram coverage

- R1, S1 — dashboard shows findings summary (read via dashboard bootstrap; this feature owns the standalone list)
- T1 — user opens scan details → links to `/findings` filtered by `scanJobId`
- U1 — backend enforces org-scope
- V1 — finding detail page with evidence + recommendations

## Responsibility

Global findings list (cross-scan) + detail view. Triage actions change `FindingStatus`.

## Routes owned

- `/findings` → `FindingsListPage` (supports query params for filters)
- `/findings/:id` → `FindingDetailPage`

## Backend endpoints consumed

- `GET /api/findings`
- `GET /api/findings/:id`
- `PATCH /api/findings/:id/status`

## Public hooks

- `useFindingsQuery(filters)`
- `useFindingQuery(id)`
- `useUpdateFindingStatus()`

## WebSocket events consumed

- `finding.created` → invalidate list queries for that org (may be batched by backend)

## Implementation checklist

- [ ] `SeverityBadge` (INFO/LOW/MEDIUM/HIGH/CRITICAL with color from `--severity-*` tokens)
- [ ] `FindingStatusBadge`
- [ ] Filter chips: severity, status, scanner
- [ ] Detail page: render `evidence` JSON with a switch on `scannerKey` (raw JSON fallback)
- [ ] Triage action bar: OPEN → TRIAGED → ACCEPTED/RESOLVED/FALSE_POSITIVE
- [ ] Permission-gated triage (requires `finding.triage`)
- [ ] Pagination (backend returns `PaginatedResult`)

## Out of scope

- Bulk triage — v2
- Comment threads on findings — v2
- CSV export — v2
