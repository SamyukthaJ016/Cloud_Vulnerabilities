# infra/prisma/

Global Prisma client. Injected everywhere via `PrismaService`.

## Files

- `prisma.service.ts` — extends `PrismaClient`, manages connection lifecycle.
- `prisma.module.ts` — global module, exports `PrismaService`.

## Usage

```ts
constructor(private readonly prisma: PrismaService) {}

async findUsers(orgId: string) {
  return this.prisma.user.findMany({ where: { memberships: { some: { orgId } } } });
}
```

## Rules for the team

- **Only the owning module touches its tables** (see ownership table in `prisma/README.md`). Other modules call the owning module's service.
- **Every tenant-scoped query filters by `orgId`** — backstopped by the Prisma client extension in `src/infra/tenant-context/prisma-tenant.extension.ts`.
- **Transactions:** use `prisma.$transaction([...])` for multi-step writes that must be atomic (e.g. creating a ScanJob + writing an AuditLog).
- **No raw SQL in feature modules** — if you need `$queryRaw`, put it in a service in `infra/` or the owning module, and document why.
