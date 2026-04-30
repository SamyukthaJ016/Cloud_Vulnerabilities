/**
 * Prisma client extension that enforces flow node TS3:
 * "Every DB query filtered by org_id".
 *
 * Strategy:
 *   - List every model that has an `orgId` field.
 *   - On every `findMany/findFirst/findUnique/update/delete` call on those models,
 *     auto-inject `where: { orgId: <current-request-orgId> }`.
 *   - orgId is read from AsyncLocalStorage populated by TenantContextMiddleware.
 *   - Bypass hatch (`$untenanted`) for admin/cron jobs that must operate cross-org.
 *
 * TODO (platform lead): implement using prisma.$extends({ query: { ... } })
 *   See https://www.prisma.io/docs/orm/prisma-client/client-extensions/query
 *
 * Until this is implemented, module authors MUST include `orgId` in their own
 * where-clauses. Do not forget.
 */
export const tenantExtension = {
  name: 'tenant-isolation',
  // placeholder — real implementation lives in platform team branch
};
