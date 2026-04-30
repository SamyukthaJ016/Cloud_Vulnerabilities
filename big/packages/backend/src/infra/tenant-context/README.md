# infra/tenant-context/

Enforces the tenant-isolation rules from the flow diagram's
`Tenant_Security_and_Data_Isolation` subgraph (flow nodes TS1-TS5).

## Files

- `tenant-context.middleware.ts` — runs after auth; puts `orgId` into AsyncLocalStorage for the request.
- `prisma-tenant.extension.ts` — auto-injects `orgId` into every query on tenant-scoped models.
- `tenant-context.module.ts` — global module, exports the middleware.

## The contract

| Flow node | Enforced by |
|---|---|
| TS1 — every request carries identity | `JwtAuthGuard` + `JwtStrategy` in `auth` module |
| TS2 — backend maps identity to org_id | `TenantContextMiddleware` (this folder) |
| TS3 — every DB query filtered by org_id | `prisma-tenant.extension.ts` (this folder) |
| TS4 — secrets fetched only from org-owned vault path | `VaultService.buildPath()` uses `orgId` |
| TS5 — results tagged and retrieved by org_id | schema: `Finding.orgId` + index |
| TS6 — audit logs | `AuditInterceptor` + `AuditService` |

## Why a Prisma extension and not a middleware?

Prisma 6 middlewares are deprecated — use `$extends({ query: ... })` instead. The extension lets us declaratively add a `where` clause to every model with an `orgId` column.

## Bypass hatch

Cross-org operations (admin tooling, cron jobs, billing-webhook processors) need to bypass the filter. Pattern: a dedicated `prisma.$untenanted` accessor that skips the extension. Only used from:
- `scripts/` and `prisma/seed.ts`
- `billing-webhooks` (razorpay webhook has no user identity)
- `audit` queries by platform admins

Document every bypass in-line with a comment explaining why.
