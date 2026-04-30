# Prisma

This is the single source of truth for the database schema. All backend modules read/write through `PrismaService` from `src/infra/prisma/`.

## Files

| File | Purpose |
|---|---|
| `schema.prisma` | All models, enums, relations. Grouped by domain with comments pointing to flow-diagram nodes. |
| `seed.ts` | Seeds system catalog: roles, permissions, plans, scanner catalog. Idempotent. |
| `migrations/` | Generated migration history. Never edit by hand. |

## Workflow

**Dev loop (schema change → migration):**
```bash
# after editing schema.prisma
npm run prisma:migrate -- --name <short_migration_name>
npm run prisma:generate
```

**Fresh environment:**
```bash
docker compose up -d postgres   # start postgres
npm run prisma:deploy           # run all pending migrations
npm run prisma:seed             # populate system catalog
```

**Reset (destroys data):**
```bash
npm run db:reset
```

## Schema conventions

- **Every tenant-scoped table has `orgId` + an index on it.** This enforces flow rule TS3 ("Every DB query filtered by org_id"). The `PrismaTenantExtension` in `src/infra/tenant-context/` applies this filter automatically.
- **Secrets hold metadata only** — the actual secret value lives in Vault (flow AE). The `Secret` model stores `vaultPath`, not `value`.
- **Findings use a normalized schema** — all scanners emit the same `Finding` shape regardless of source (flow K1). Scanner-specific raw output goes to `ScanArtifact`.
- **`WebhookEvent.eventId` is unique** — enforces replay protection for inbound Razorpay webhooks (flow BH).
- **UUIDs are Postgres `uuid` type** — using `@db.Uuid` for storage efficiency and index performance.
- **Timestamps are always `DateTime`** — never store as string.

## Module → table ownership

| Module | Tables it writes to |
|---|---|
| `auth` | `User` (login updates), `AuditLog` |
| `users` | `User` |
| `organizations` | `Organization`, `OrgMember` |
| `rbac` | `Role`, `Permission`, `RolePermission` |
| `plans` | `Plan`, `PlanEntitlement` |
| `subscriptions` | `Subscription` |
| `billing` | `PaymentOrder` |
| `billing-webhooks` | `WebhookEvent`, `PaymentOrder` (update), `Subscription` (update) |
| `secrets` | `Secret` |
| `scanners` | `Scanner` (populated from manifests at boot) |
| `scans` | `ScanJob` (full lifecycle: create + dispatch) |
| `scanner-callbacks` | `ScanJob` (status / summary / viewSecretHash transitions from external callback) |
| `findings` | `Finding`, `ScanArtifact` (defined for v2; not written by v1 scanner flow) |
| `audit` | `AuditLog` |
| `webhooks-outbound` | `WebhookSubscription`, `WebhookDelivery` |

Modules should only write to the tables they own. Cross-module reads go through the owning module's service, not raw Prisma.
