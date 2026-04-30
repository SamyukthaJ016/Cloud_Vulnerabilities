# audit/

Cross-cutting audit logging. Every significant action writes a row here.

## Flow diagram coverage

- TS6 — central rule: "Audit logs record actor, org, action, timestamp"
- AF — secret create/update/revoke
- BK — billing changes (webhook-driven)
- P1 — scan execution completed
- CF1 — unauthorized scan attempt
- AB1 — unauthorized secret action
- BH1 — rejected webhook
- X5 — "Audit / Recent Activity" dashboard tile reads from here

## Responsibility

Own the `AuditLog` table. Expose `AuditService.record(...)` for other modules to call (directly or via `@AuditAction` decorator). Expose a query API for the X5 tile.

**This module is `@Global()`** — `AuditService` is injectable everywhere without re-importing.

## Public API

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/audit` | `org_admin` \| `org_member` | Query audit trail for current org with filters |

Query params: `action`, `resource`, `actorUserId`, `from`, `to`, `page`, `pageSize`.

## Internal services (exposed — `@Global`)

- `AuditService.record({ orgId, actorUserId, action, resource, resourceId, ipAddress, userAgent, details })` — **never throws**. Failed writes are logged but don't interrupt the request.
- `AuditService.listForOrg(orgId, params)` — strict `orgId` filter.

## Two ways to write an audit log

**1. Declarative (preferred for clear side-effect endpoints):**
```ts
@AuditAction({ action: 'secret.create', resource: 'secret' })
@Post()
create(...) { ... }
```
`AuditInterceptor` runs after success, pulls actor/request context, writes the row.

**2. Imperative (for nuanced cases):**
```ts
constructor(private readonly audit: AuditService) {}

async doThing() {
  await this.audit.record({ action: '...', resource: '...', details: { ... } });
}
```

## Action taxonomy

Keep action names as `<resource>.<verb>` — dotted, lowercase, singular resource. Current vocabulary:

```
user.login
user.login.failed
secret.create
secret.read          (service-to-service only — never from HTTP)
secret.revoke
billing.checkout.start
billing.payment.captured
billing.payment.failed
billing.subscription.updated
billing.subscription.canceled
scan.run.requested
scan.run.unauthorized
scan.run.blocked.plan
scan.run.blocked.quota
scan.run.blocked.concurrency
scan.run.blocked.missing_secrets
scan.dispatched
scan.completed
scan.partial
scan.failed
finding.triage
org.member.invited
org.member.removed
org.member.role_changed
webhook.rejected
```

**Don't invent new actions without adding them to this list.** Keeps the audit UI filterable.

## DB tables owned

- `AuditLog`

## Implementation checklist

- [ ] `AuditService.record` — never throws; catch-log-swallow
- [ ] `AuditService.listForOrg` — pagination + filter indexes (already in schema)
- [ ] `AuditInterceptor` wires up (currently a stub — inject `AuditService`, extract actor, write on success)
- [ ] Audit log CSV export — v2
- [ ] Integration test: every write path in the codebase produces the expected audit row

## Out of scope

- Log shipping to SIEM — v2 (the table is the canonical store for now)
- Immutable/append-only enforcement at DB level — v2
