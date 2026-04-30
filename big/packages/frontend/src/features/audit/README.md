# audit/

Audit log viewer.

## Flow diagram coverage

- X5 — "Audit / Recent Activity" tile on dashboard (summary read via dashboard bootstrap)
- TS6 — every backend action writes an AuditLog; this feature is the read UI

## Responsibility

Paginated, filterable read-only view of audit events for the current org.

## Routes owned

- `/audit` → `AuditLogPage`

## Backend endpoints consumed

- `GET /api/audit?action=&resource=&actorUserId=&from=&to=`

## Public hooks

- `useAuditLogsQuery(filters)`

## Implementation checklist

- [ ] Filter bar: action select (populated from known action taxonomy — see backend `audit/README.md`), resource, actor, date range
- [ ] Table with createdAt (relative + absolute tooltip), actor, action badge, resource, resourceId
- [ ] Row click → side drawer with pretty-printed `details` JSON
- [ ] Pagination
- [ ] Permission gate: requires `audit.read`

## Out of scope

- CSV / JSON export — v2
- Timeline view (instead of table) — v2
