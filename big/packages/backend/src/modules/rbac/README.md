# rbac/

Roles, permissions, and plan entitlements.

## Flow diagram coverage

- O — resolve role + entitlements on login
- AB — secret authorization check
- CF — scan run authorization check
- CG / CH — scanner included in plan + quota/concurrency check

## Responsibility

Two orthogonal concerns in one module:

1. **RBAC** (who can do what) — `RbacService` + `Role`/`Permission`/`RolePermission` tables.
2. **Entitlements** (what does the plan allow) — `EntitlementsService` + `PlanEntitlement` table.

Both are hot-path checks; both should cache aggressively (in-memory with TTL is fine for v1).

## Public API

| Method | Path | Description |
|---|---|---|
| GET | `/rbac/roles` | List all system roles (for admin UI dropdowns) |

## Internal services (exposed — `@Global`)

- `RbacService.resolveForMember(orgMemberId)` — used by `auth` at login.
- `RbacService.can(userId, orgId, permissionKey)` — hot-path check for any gated action.
- `EntitlementsService.isScannerEnabled(orgId, scannerKey)` — used by `scans` module (flow CH).
- `EntitlementsService.remainingScanQuota(orgId)` — used by `scans` module (flow CG).
- `EntitlementsService.hasConcurrencyHeadroom(orgId)` — used by `scans` module (flow CG).

## Static catalog

`permissions.catalog.ts` is the source of truth for permission keys and role→permission mapping. `prisma/seed.ts` reads this file to populate the DB. **Any new permission starts here.**

## Dependencies

- `PrismaService`

## Depended on by

- `auth` (role resolution)
- `scans` (authz + entitlement)
- `secrets` (authz)
- `billing`, `findings`, etc. (authz)

## DB tables owned

- `Role`
- `Permission`
- `RolePermission`

Reads (but does not own): `PlanEntitlement`, `Subscription` (via `subscriptions` module).

## Implementation checklist

### RBAC
- [ ] `RbacService.resolveForMember` — load role + permissions
- [ ] `RbacService.can(userId, orgId, permissionKey)` with caching
- [ ] `RbacService.listRoles`
- [ ] Seed script uses `permissions.catalog.ts`

### Entitlements
- [ ] `EntitlementsService.get(orgId, key)` — resolves via subscription → plan → entitlement
- [ ] `EntitlementsService.isScannerEnabled`
- [ ] `EntitlementsService.remainingScanQuota` (counts `ScanJob` rows for billing period)
- [ ] `EntitlementsService.hasConcurrencyHeadroom`
- [ ] Cache entitlements with short TTL (60s) to avoid DB hit per scan

### Quality
- [ ] Unit tests for each service
- [ ] Integration test: role change propagates to `can()` after cache expiry

## Out of scope

- Custom roles per org — v1 is system roles only
- Resource-level ACL (e.g. per-finding permissions) — v2
- Multi-tenant role delegation — v2
